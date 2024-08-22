//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include <iostream>
#include <iomanip>
#include <fstream>
#include <regex>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

using namespace nil::crypto3;

//*******************************************************************************
//* Fill data structures with random data
//*******************************************************************************
template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
generate_random_data(std::size_t leaf_number, boost::random::mt11213b &rnd) {
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf;
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return rnd() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

std::vector<std::vector<std::uint8_t>>
generate_random_data_for_merkle_tree(size_t leafs_number, size_t leaf_bytes, boost::random::mt11213b &rnd) {
    std::vector<std::vector<std::uint8_t>> rdata(leafs_number, std::vector<std::uint8_t>(leaf_bytes));

    for (std::size_t i = 0; i < leafs_number; ++i) {
        std::vector<uint8_t> leaf(leaf_bytes);
        for (size_t i = 0; i < leaf_bytes; i++) {
            leaf[i] = rnd() % (std::numeric_limits<std::uint8_t>::max() + 1);
        }
        rdata.emplace_back(leaf);
    }
    return rdata;
}

template<typename FRI>
typename FRI::merkle_proof_type generate_random_merkle_proof(std::size_t tree_depth, boost::random::mt11213b &rnd) {
    std::size_t leafs_number = 1 << tree_depth;
    std::size_t leaf_size = 32;

    auto rdata1 = generate_random_data_for_merkle_tree(leafs_number, leaf_size, rnd);
    auto tree1 = containers::make_merkle_tree<typename FRI::merkle_tree_hash_type, FRI::m>(rdata1.begin(),
                                                                                           rdata1.end());
    std::size_t idx1 = rnd() % leafs_number;
    typename FRI::merkle_proof_type mp1(tree1, idx1);
    return mp1;
}

inline std::vector<std::size_t>
generate_random_step_list(const std::size_t r, const std::size_t max_step, boost::random::mt11213b &rnd) {
    using dist_type = std::uniform_int_distribution<int>;

    std::vector<std::size_t> step_list;
    std::size_t steps_sum = 0;
    while (steps_sum != r) {
        if (r - steps_sum <= max_step) {
            while (r - steps_sum != 1) {
                step_list.emplace_back(r - steps_sum - 1);
                steps_sum += step_list.back();
            }
            step_list.emplace_back(1);
            steps_sum += step_list.back();
        } else {
            step_list.emplace_back(dist_type(1, max_step)(rnd));
            steps_sum += step_list.back();
        }
    }

    return step_list;
}

template<typename FRI>
typename FRI::polynomial_values_type generate_random_polynomial_values(
        size_t step,
        nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd
) {
    typename FRI::polynomial_values_type values;

    std::size_t coset_size = 1 << (step - 1);
    values.resize(coset_size);
    for (size_t i = 0; i < coset_size; i++) {
        for (size_t j = 0; j < FRI::m; j++) {
            values[i][j] = alg_rnd();
            values[i][j] = alg_rnd();
        }
    }
    return values;
}

template<typename FieldType>
math::polynomial<typename FieldType::value_type> generate_random_polynomial(
        size_t degree,
        nil::crypto3::random::algebraic_engine<FieldType> &d
) {
    math::polynomial<typename FieldType::value_type> poly;
    poly.resize(degree);

    for (std::size_t i = 0; i < degree; ++i) {
        poly[i] = d();
    }
    return poly;
}

template<typename FRI>
typename FRI::round_proof_type generate_random_fri_round_proof(
        std::size_t r_i,
        nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
        boost::random::mt11213b &rnd
) {
    typename FRI::round_proof_type res;
    res.p = generate_random_merkle_proof<FRI>(3, rnd);
    res.y = generate_random_polynomial_values<FRI>(r_i, alg_rnd);

    return res;
}

template<typename FRI>
typename FRI::initial_proof_type generate_random_fri_initial_proof(
        std::size_t polynomial_number,
        std::size_t r0,
        nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
        boost::random::mt11213b &rnd
) {
    typename FRI::initial_proof_type res;

    std::size_t coset_size = 1 << r0;
    res.p = generate_random_merkle_proof<FRI>(3, rnd);
    res.values.resize(polynomial_number);
    for (std::size_t i = 0; i < polynomial_number; i++) {
        res.values[i].resize(coset_size / FRI::m);
        for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
            res.values[i][j][0] = alg_rnd();
            res.values[i][j][1] = alg_rnd();
        }
    }

    return res;
}

template<typename FRI>
typename FRI::query_proof_type generate_random_fri_query_proof(
        std::size_t max_batch_size,
        std::vector<std::size_t> step_list,
        nil::crypto3::marshalling::types::batch_info_type batch_info,
        nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
        boost::random::mt11213b &rnd
) {
    typename FRI::query_proof_type res;

    for (const auto &it : batch_info) {
        res.initial_proof[it.first] = generate_random_fri_initial_proof<FRI>(it.second, step_list[0], alg_rnd, rnd);
    }
    res.round_proofs.resize(step_list.size());
    for (std::size_t i = 1; i < step_list.size(); i++) {
        res.round_proofs[i-1] = generate_random_fri_round_proof<FRI>(
            step_list[i], alg_rnd,  rnd
        );
    }
    res.round_proofs[step_list.size()-1] = generate_random_fri_round_proof<FRI>(
        1, alg_rnd,  rnd
    );
    return res;
}

template<typename FRI>
typename FRI::proof_type generate_random_fri_proof(
    std::size_t d,              //final polynomial degree
    std::size_t max_batch_size,
    std::vector<std::size_t> step_list,
    std::size_t lambda,
    bool use_grinding,
    nil::crypto3::marshalling::types::batch_info_type batch_info,
    nil::crypto3::random::algebraic_engine<typename FRI::field_type> &alg_rnd,
    boost::random::mt11213b &rnd
) {
    typename FRI::proof_type res;
    res.query_proofs.resize(lambda);
    for (std::size_t k = 0; k < lambda; k++) {
        res.query_proofs[k] = generate_random_fri_query_proof<FRI>(max_batch_size, step_list, batch_info, alg_rnd, rnd);
    }
    res.fri_roots.resize(step_list.size());
    for (std::size_t k = 0; k < step_list.size(); k++) {
        res.fri_roots[k] = nil::crypto3::hash<typename FRI::merkle_tree_hash_type>(
                generate_random_data<std::uint8_t, 32>(1, rnd).at(0)
        );
    }
    if (use_grinding){
        res.proof_of_work = rnd();
    }
    res.final_polynomial = generate_random_polynomial<typename FRI::field_type>(d, alg_rnd);
    return res;
}


template<typename LPC>
typename LPC::proof_type generate_random_lpc_proof(
    std::size_t d,              //final polynomial degree
    std::size_t max_batch_size,
    std::vector<std::size_t> step_list,
    std::size_t lambda,
    std::size_t use_grinding,
    nil::crypto3::random::algebraic_engine<typename LPC::basic_fri::field_type> &alg_rnd,
    boost::random::mt11213b &rnd
) {
    typename LPC::proof_type res;

    nil::crypto3::marshalling::types::batch_info_type batch_info;
    for( std::size_t i = 0; i < 6; i++ ){
        batch_info[rnd()%6] = rnd()%9 + 1;
    }
    for( const auto&it: batch_info){
        res.z.set_batch_size(it.first, it.second);
        for( std::size_t i = 0; i < it.second; i++){
            res.z.set_poly_points_number(it.first, i, rnd()%3 + 1);
            for( std::size_t j = 0; j < res.z.get_poly_points_number(it.first, i); j++){
                res.z.set(it.first, i, j, alg_rnd());
            }
        }
    }
    res.fri_proof = generate_random_fri_proof<typename LPC::basic_fri>(d, max_batch_size, step_list, lambda, use_grinding, batch_info, alg_rnd, rnd);
    return res;
}


template<typename FieldType>
math::polynomial_dfs<typename FieldType::value_type>
generate_random_polynomial_dfs(std::size_t degree, nil::crypto3::random::algebraic_engine<FieldType> &rnd) {
    math::polynomial<typename FieldType::value_type> data = generate_random_polynomial<FieldType>(degree, rnd);
    math::polynomial_dfs<typename FieldType::value_type> result;
    result.from_coefficients(data);
    return result;
}

template<typename FieldType>
std::vector<math::polynomial<typename FieldType::value_type>> generate_random_polynomial_batch(
        std::size_t batch_size,
        std::size_t degree,
        nil::crypto3::random::algebraic_engine<FieldType> &rnd
) {
    std::vector<math::polynomial<typename FieldType::value_type>> result;

    for (std::size_t i = 0; i < batch_size; i++) {
        result.push_back(generate_random_polynomial<FieldType>(degree, rnd));
    }
    return result;
}

template<typename FieldType>
std::vector<math::polynomial_dfs<typename FieldType::value_type>>
generate_random_polynomial_dfs_batch(std::size_t batch_size,
                                     std::size_t degree,
                                     nil::crypto3::random::algebraic_engine<FieldType> &rnd) {
    auto data = generate_random_polynomial_batch(batch_size, degree, rnd);
    std::vector<math::polynomial_dfs<typename FieldType::value_type>> result;

    for (std::size_t i = 0; i < data.size(); i++) {
        math::polynomial_dfs<typename FieldType::value_type> dfs;
        dfs.from_coefficients(data[i]);
        result.push_back(dfs);
    }
    return result;
}
