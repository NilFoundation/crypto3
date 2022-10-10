//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_lpc_commitment_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <random>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/fri.hpp>

using namespace nil::crypto3;

/*
template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::hex << int(*it) << std::endl;
    }
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp2<FieldParams> &e) {
    os << "[" << e.data[0].data << "," << e.data[1].data << "]" << std::endl;
}*
*/

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
    generate_random_data(std::size_t leaf_number) {
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf;
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return std::rand() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

std::vector<std::vector<std::uint8_t>>
generate_random_data_for_merkle_tree(size_t leafs_number, size_t leaf_bytes){
    std::vector<std::vector<std::uint8_t>> rdata(leafs_number, std::vector<std::uint8_t>(leaf_bytes));
    std::random_device rd;
    for (std::size_t i = 0; i < leafs_number; ++i) {
        std::vector<uint8_t> leaf(leaf_bytes);
        for( size_t i = 0; i < leaf_bytes; i++){
            leaf[i] = rd() % (std::numeric_limits<std::uint8_t>::max() + 1);
        }
        rdata.emplace_back(leaf);
    }    
    return rdata;
}

template<typename FRIScheme>
typename FRIScheme::round_proof_type generate_random_fri_round_proof(std::size_t tree_depth) {
    std::random_device rd;
    std::size_t leafs_number = 1 << tree_depth;
    std::size_t leaf_size = 32;
    typename FRIScheme::round_proof_type proof;

    auto rdata1 = generate_random_data_for_merkle_tree(leafs_number, leaf_size);
    auto tree1 = containers::make_merkle_tree<typename FRIScheme::merkle_tree_hash_type, FRIScheme::m>(rdata1.begin(), rdata1.end());
    std::size_t idx1 = rd() % leafs_number;
    typename FRIScheme::merkle_proof_type mp1(tree1, idx1);
    proof.colinear_path = mp1;

    auto rdata2 = generate_random_data_for_merkle_tree(leafs_number, leaf_size);
    auto tree2 = containers::make_merkle_tree<typename FRIScheme::merkle_tree_hash_type, FRIScheme::m>(rdata2.begin(), rdata2.end());
    std::size_t idx2 = rd() % leafs_number;
    typename FRIScheme::merkle_proof_type mp2(tree2, idx2);
    proof.colinear_path = mp2;

    proof.T_root =
        nil::crypto3::hash<typename FRIScheme::transcript_hash_type>(generate_random_data<std::uint8_t, 32>(1).at(0));

    return proof;
}

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
    using dist_type = std::uniform_int_distribution<int>;
    static std::random_device random_engine;

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
            step_list.emplace_back(dist_type(1, max_step)(random_engine));
            steps_sum += step_list.back();
        }
    }
    return step_list;
}

template<typename FRIScheme> 
typename FRIScheme::rounds_polynomials_values_type generate_random_fri_values(size_t polynomials, typename FRIScheme::params_type fri_params){
    nil::crypto3::random::algebraic_random_device<typename FRIScheme::field_type> d;
    typename FRIScheme::rounds_polynomials_values_type values;
    values.resize(fri_params.step_list.size());
    for( size_t i = 0; i < fri_params.step_list.size(); i++){
        std::size_t coset_size = 1 << fri_params.step_list[i];
        if constexpr(!FRIScheme::is_const_size){
            values[i].resize(polynomials);
        }
        for( size_t pol = 0; pol < polynomials; pol++ ){
            values[i][pol].resize(coset_size/FRIScheme::m);
            for( size_t j = 0; j < coset_size/FRIScheme::m; j++){
                values[i][pol][j][0] = d();
                values[i][pol][j][1] = d();
            }
        }
    }
    return values;
}

template<typename FieldType>
math::polynomial<typename FieldType::value_type> generate_random_polynomial(size_t degree){
    math::polynomial<typename FieldType::value_type> poly;
    poly.resize(degree);

    nil::crypto3::random::algebraic_random_device<FieldType> d;
    for (std::size_t i = 0; i < degree; ++i) {
        poly[i] = d();
    }
    return poly;
}

template<typename FRIScheme>
typename FRIScheme::proof_type generate_random_fri_proof(size_t polynomials, size_t degree, typename FRIScheme::params_type &fri_params){
    typename FRIScheme::proof_type proof;

    proof.round_proofs.resize(fri_params.step_list.size()-1);
    for( size_t i = 0; i < fri_params.step_list.size() - 1; i++){
        proof.round_proofs[i] = generate_random_fri_round_proof<FRIScheme>(3);
    }

    if constexpr(!FRIScheme::is_const_size){
        proof.final_polynomials.resize(polynomials);
    }
    for( size_t i = 0; i < polynomials; i++){
        proof.final_polynomials[i] = generate_random_polynomial<typename FRIScheme::field_type>(degree/(1 << (fri_params.r-1)));
    }

    proof.values = generate_random_fri_values<FRIScheme>(polynomials, fri_params);

    return proof;
}

template <typename Endianness, typename FRIScheme>
void test_fri_round_proof(typename FRIScheme::round_proof_type &proof){
    auto filled_proof = nil::crypto3::marshalling::types::fill_fri_round_proof<Endianness, FRIScheme>(proof);
    auto _proof =  nil::crypto3::marshalling::types::make_fri_round_proof<Endianness, FRIScheme>(filled_proof);
    BOOST_CHECK(proof == _proof);

    using TTypeBase = nil::marshalling::field_type<Endianness>;

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_proof.write(write_iter, cv.size());

    nil::crypto3::marshalling::types::fri_round_proof<TTypeBase, FRIScheme> test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    typename FRIScheme::round_proof_type constructed_val_read = nil::crypto3::marshalling::types::make_fri_round_proof<Endianness, FRIScheme>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

template<typename Endianness, typename FRIScheme>
void test_fri_proof_one_round_values(typename FRIScheme::proof_type &proof){
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    auto filled_v0 = nil::crypto3::marshalling::types::fill_fri_polynomials_values<nil::marshalling::option::big_endian, FRIScheme>(proof.values[0]);
    auto _v0 = nil::crypto3::marshalling::types::make_fri_polynomials_values<nil::marshalling::option::big_endian, FRIScheme>(filled_v0);
    BOOST_CHECK(proof.values[0] == _v0);
    std::vector<std::uint8_t> cv0;
    cv0.resize(filled_v0.length(), 0x00);
    auto write_iter0 = cv0.begin();
    nil::marshalling::status_type status0 = filled_v0.write(write_iter0, cv0.size());

    nil::crypto3::marshalling::types::fri_polynomials_values<TTypeBase, FRIScheme> test_val_read0;
    auto read_iter0 = cv0.begin();
    status0 = test_val_read0.read(read_iter0, cv0.size());
    auto constructed_val_read0 =
        nil::crypto3::marshalling::types::make_fri_polynomials_values<Endianness, FRIScheme>(test_val_read0);
    BOOST_CHECK(proof.values[0] == constructed_val_read0);
}

template<typename Endianness, typename FRIScheme>
void test_fri_proof_values(typename FRIScheme::proof_type &proof){
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    auto filled_v = nil::crypto3::marshalling::types::fill_fri_rounds_polynomials_values<Endianness, FRIScheme>(proof.values);
    auto _v = nil::crypto3::marshalling::types::make_fri_rounds_polynomials_values<Endianness, FRIScheme>(filled_v);
    BOOST_CHECK(proof.values == _v);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_v.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_v.write(write_iter, cv.size());

    nil::crypto3::marshalling::types::fri_rounds_polynomials_values<TTypeBase, FRIScheme> test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read =
        nil::crypto3::marshalling::types::make_fri_rounds_polynomials_values<Endianness, FRIScheme>(test_val_read);
    BOOST_CHECK(proof.values == constructed_val_read);
}

template<typename Endianness, typename FRIScheme>
void test_fri_proof(typename FRIScheme::proof_type &proof){
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    
    auto filled_proof = nil::crypto3::marshalling::types::fill_fri_proof<nil::marshalling::option::big_endian, FRIScheme>(proof);
    auto _proof = nil::crypto3::marshalling::types::make_fri_proof<nil::marshalling::option::big_endian, FRIScheme>(filled_proof);

    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_proof.write(write_iter, cv.size());

    nil::crypto3::marshalling::types::fri_proof<TTypeBase, FRIScheme> test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    typename FRIScheme::proof_type constructed_val_read =
        nil::crypto3::marshalling::types::make_fri_proof<Endianness, FRIScheme>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

/*********************************************************************************************
 * This function is useful when you want to check if random generated proof structures are 
 * the same size as a real proof.
 *********************************************************************************************/
template<typename FRIScheme>
void test_fri_proofs_equal_size(typename FRIScheme::proof_type proof, typename FRIScheme::proof_type  proof2){
    BOOST_CHECK( proof.round_proofs.size() == proof2.round_proofs.size() );
    BOOST_CHECK( proof.values.size() == proof2.values.size() );
    for( size_t i = 0; i < proof.values.size(); i++){
        BOOST_CHECK(proof.values[i].size() == proof2.values[i].size());
        for(size_t j = 0; j < proof.values[i].size(); j++){
            BOOST_CHECK(proof.values[i][j].size() == proof2.values[i][j].size());
            for(size_t k = 0; k < proof.values[i][j].size(); k++){
                BOOST_CHECK(proof.values[i][j][k].size() == proof.values[i][j][k].size() );
            }
        }
    }
    BOOST_CHECK( proof.final_polynomials.size() == proof2.final_polynomials.size() );
    for( size_t i = 0; i < proof.final_polynomials.size(); i++){
        BOOST_CHECK( proof.final_polynomials[i].size() == proof2.final_polynomials[i].size() );
    }
}

BOOST_AUTO_TEST_SUITE(marshalling_fri_proof_elements)
BOOST_AUTO_TEST_CASE(marshalling_fri_some_polynomial_marshalling_test) {
    std::srand(std::time(0));
    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using FRIScheme = typename nil::crypto3::zk::commitments::fri<field_type, hash_type, hash_type, 2, 0>::basic_fri;

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    math::polynomial<typename field_type::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};
    auto filled_polynomial = nil::crypto3::marshalling::types::fill_fri_math_polynomial<Endianness, FRIScheme>(f);

    auto _f = nil::crypto3::marshalling::types::make_fri_math_polynomial<Endianness, FRIScheme>(filled_polynomial);
    BOOST_CHECK(f == _f);
}

BOOST_AUTO_TEST_CASE(marshalling_fri_random_round_proof) {
    std::srand(std::time(0));
    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using FRIScheme = typename nil::crypto3::zk::commitments::fri<field_type, hash_type, hash_type, 2, 0>::basic_fri;
    using proof_marshalling_type = typename nil::crypto3::marshalling::types::fri_round_proof<
        nil::marshalling::field_type<Endianness>, FRIScheme
    >;

    typename FRIScheme::round_proof_type proof = generate_random_fri_round_proof<FRIScheme>(5);
    test_fri_round_proof<Endianness, FRIScheme>(proof);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(marshalling_fri_proofs)
BOOST_AUTO_TEST_CASE(marshalling_fri_basic_test){
    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};
    //merkle_tree_type commit_merkle = zk::algorithms::precommit<FRIScheme>(f, D[0]);

    proof_type proof = generate_random_fri_proof<FRIScheme>(1, f.size(), params);
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_fri_basic_skipping_layers_test){
    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 1024;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    math::polynomial<typename FieldType::value_type> f(d);
    std::generate(std::begin(f), std::end(f), [&rnd]() { return rnd(); });
    f.back() = FieldType::value_type::one();

    auto proof = generate_random_fri_proof<FRIScheme>(1, f.size(), params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_fri_steps_count_test){
    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> FRIScheme;
    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;
    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);

    auto proof = generate_random_fri_proof<FRIScheme>(1, f.size(), params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_fri_basic_compile_time_size_test){

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 2;
    constexpr static const bool is_const_size = true;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, is_const_size> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}}};

    auto proof = generate_random_fri_proof<FRIScheme>(2, f[0].size(), params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_fri_basic_compile_time_size_skipping_layers_test){
    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 2048;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 10;
    constexpr static const bool is_const_size = true;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, is_const_size> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f;
    f.fill(math::polynomial<typename FieldType::value_type>(d));
    for (auto &f_i : f) {
        std::generate(std::begin(f_i), std::end(f_i), [&rnd]() { return rnd(); });
        f_i.back() = FieldType::value_type::one();
    }

    auto proof = generate_random_fri_proof<FRIScheme>(f.size(), f[0].size(), params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_fri_basic_runtime_size_test){
    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    std::vector<math::polynomial<typename FieldType::value_type>> f = {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1},
                                                                       {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 6, 1, 2, 1, 1}};

    size_t f_size = 0;
    for( size_t i = 0; i < f.size(); i++){
        if(f[i].size() > f_size ) f_size = f[i].size();
    }
    auto proof = generate_random_fri_proof<FRIScheme>(f.size(), f_size, params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_fri_basic_runtime_size_skipping_layers_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 4096;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    const std::size_t leaf_size = 10;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    std::vector<math::polynomial<typename FieldType::value_type>> f(
        leaf_size, math::polynomial<typename FieldType::value_type>(d));
    for (auto &f_i : f) {
        std::generate(std::begin(f_i), std::end(f_i), [&rnd]() { return rnd(); });
        f_i.back() = FieldType::value_type::one();
    }

    size_t f_size = 0;
    for( size_t i = 0; i < f.size(); i++){
        if(f[i].size() > f_size ) f_size = f[i].size();
    }
    auto proof = generate_random_fri_proof<FRIScheme>(f.size(), f_size, params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(fri_dfs_basic_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 1);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    math::polynomial<typename FieldType::value_type> f_data = {1, 3, 4, 1, 5, 6, 7, 2, 8, 5, 6, 1, 2, 1, 1};
    math::polynomial_dfs<typename FieldType::value_type> f;
    f.from_coefficients(f_data);

    auto proof = generate_random_fri_proof<FRIScheme>(1, f.size(), params);
    
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_fri_dfs_basic_skipping_layers_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 1024;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    math::polynomial<typename FieldType::value_type> f_data(d);
    std::generate(std::begin(f_data), std::end(f_data), [&rnd]() { return rnd(); });
    f_data.back() = FieldType::value_type::one();
    math::polynomial_dfs<typename FieldType::value_type> f;
    f.from_coefficients(f_data);

    auto proof = generate_random_fri_proof<FRIScheme>(1, f.size(), params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_fri_dfs_test_2) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 1, true> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = {2, 1, 1};

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    math::polynomial<typename FieldType::value_type> f_data = {1, 3, 4, 1, 5, 6, 7, 2, 8, 5, 6, 7, 1, 2, 1, 1};
    math::polynomial_dfs<typename FieldType::value_type> f;
    f.from_coefficients(f_data);

    auto proof = generate_random_fri_proof<FRIScheme>(1, f.size(), params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_fri_dfs_basic_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = {2, 1, 1};

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f_data = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 7, 7, 7, 1, 1}}};

    std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size> f;
    for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
        f[polynom_index].from_coefficients(f_data[polynom_index]);
    }

    using ContainerType = std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size>;
    static_assert(
        !std::is_same<typename ContainerType::value_type, math::polynomial<typename FieldType::value_type>>::value);
    static_assert(
        std::is_same<typename ContainerType::value_type, math::polynomial_dfs<typename FieldType::value_type>>::value);

    size_t f_size = 0;
    for( size_t i = 0; i < f.size(); i++){
        if(f[i].size() > f_size ) f_size = f[i].size();
    }
    auto proof = generate_random_fri_proof<FRIScheme>(f.size(), f_size, params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_fri_dfs_basic_skipping_layers_test) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 2048;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 10;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = generate_random_step_list(r, 4);

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f_data;
    f_data.fill(math::polynomial<typename FieldType::value_type>(d));
    for (auto &f_i : f_data) {
        std::generate(std::begin(f_i), std::end(f_i), [&rnd]() { return rnd(); });
        f_i.back() = FieldType::value_type::one();
    }

    std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size> f;
    for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
        f[polynom_index].from_coefficients(f_data[polynom_index]);
    }

    using ContainerType = std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size>;
    static_assert(
        !std::is_same<typename ContainerType::value_type, math::polynomial<typename FieldType::value_type>>::value);
    static_assert(
        std::is_same<typename ContainerType::value_type, math::polynomial_dfs<typename FieldType::value_type>>::value);

    size_t f_size = 0;
    for( size_t i = 0; i < f.size(); i++){
        if(f[i].size() > f_size ) f_size = f[i].size();
    }
    auto proof = generate_random_fri_proof<FRIScheme>(f.size(), f_size, params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_fri_dfs_test_2) {

    // setup
    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t leaf_size = 7;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename FRIScheme::proof_type proof_type;
    typedef typename FRIScheme::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r;
    params.D = D;
    params.max_degree = d - 1;
    params.step_list = {2, 1, 1};

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f_data = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1},
         {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 8, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 4, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1},
         {1, 3, 4, 1, 5, 7, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1}}};

    std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size> f;
    for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
        f[polynom_index].from_coefficients(f_data[polynom_index]);
    }

    using ContainerType = std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size>;
    static_assert(
        !std::is_same<typename ContainerType::value_type, math::polynomial<typename FieldType::value_type>>::value);
    static_assert(
        std::is_same<typename ContainerType::value_type, math::polynomial_dfs<typename FieldType::value_type>>::value);

    size_t f_size = 0;
    for( size_t i = 0; i < f.size(); i++){
        if(f[i].size() > f_size ) f_size = f[i].size();
    }
    auto proof = generate_random_fri_proof<FRIScheme>(f.size(), f_size, params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    test_fri_proof_one_round_values<Endianness, FRIScheme>(proof);
    test_fri_proof_values<Endianness, FRIScheme>(proof);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[0]);
    test_fri_round_proof<Endianness, FRIScheme>(proof.round_proofs[1]);
    test_fri_proof<Endianness, FRIScheme>(proof);
}

BOOST_AUTO_TEST_SUITE_END()
