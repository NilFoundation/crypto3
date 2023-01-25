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
#include <fstream>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
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

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>

using namespace nil::crypto3;

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

template <typename LPCScheme, typename FRIScheme>
typename LPCScheme::proof_type generate_random_lpc_proof( 
    size_t k,                           // number of evaluation points
    size_t polynomials,                 // number of polynomials
    size_t deg,                           // maximum degree of polynomials
    typename FRIScheme::params_type f_params
){
    typename LPCScheme::proof_type proof;

    for( size_t i = 0; i < LPCScheme::lambda; i++ ){
        proof.fri_proof[i] = generate_random_fri_proof<FRIScheme>(polynomials, deg, f_params);
    }

    proof.T_root =
        nil::crypto3::hash<typename FRIScheme::transcript_hash_type>(generate_random_data<std::uint8_t, 32>(1).at(0));

    if constexpr(!LPCScheme::is_const_size){
        proof.z[0].resize(polynomials);
        proof.z[1].resize(polynomials);
        proof.z[2].resize(polynomials);
        proof.z[3].resize(polynomials);
    }

    nil::crypto3::random::algebraic_random_device<typename LPCScheme::field_type> d;
    for(size_t j = 0; j < 4; j++){
        for( size_t poly = 0; poly < polynomials; poly++){
            proof.z[j][poly].resize(k);
            for( size_t i = 0; i < k; i++ )
                proof.z[j][poly][i] = d();
        }
    }

    return proof;
}

/*********************************************************************************************
 * This function is useful when you want to check if random generated proof structures are 
 * the same size as a real proof.
 *********************************************************************************************/
template <typename LPCScheme>
void test_lpc_proofs_equal_size(typename LPCScheme::proof_type proof, typename LPCScheme::proof_type proof2){
    BOOST_CHECK(proof.fri_proof.size() == proof2.fri_proof.size());
    BOOST_CHECK(proof.z.size() == proof2.z.size());
    for( size_t i = 0; i < proof.z.size(); i++ ){
        BOOST_CHECK(proof.z[i].size() == proof2.z[i].size());
    }
}

template <typename Endianness, typename LPCScheme>
void test_lpc_proof(typename LPCScheme::proof_type &proof){
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    
    auto filled_proof = nil::crypto3::marshalling::types::fill_lpc_proof<Endianness, LPCScheme>(proof);
    auto _proof = nil::crypto3::marshalling::types::make_lpc_proof<Endianness, LPCScheme>(filled_proof);

    BOOST_CHECK(proof.T_root == _proof.T_root);
    BOOST_CHECK(proof.fri_proof == _proof.fri_proof);
    BOOST_CHECK(proof.z == _proof.z);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_proof.write(write_iter, cv.size());

    nil::crypto3::marshalling::types::lpc_proof<TTypeBase, LPCScheme> test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    typename LPCScheme::proof_type constructed_val_read =
        nil::crypto3::marshalling::types::make_lpc_proof<Endianness, LPCScheme>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(lpc_marshalling_test_suite)

BOOST_AUTO_TEST_CASE(marshalling_lpc_basic_test) {
    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<
        merkle_hash_type, 
        transcript_hash_type, 
        lambda, r, m, 0,
        false
    > lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(zk::is_commitment<LPCScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};

    // TODO: take a point outside of the basic domain
    std::vector<typename FieldType::value_type> evaluation_points = {
        algebra::fields::arithmetic_params<FieldType>::multiplicative_generator};

    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points.size(), 1, f.size(), fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_lpc_basic_skipping_layers_test) {
    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 2048;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0,
                                                               false>
        lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(zk::is_commitment<LPCScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 5);

    // commit
    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    math::polynomial<typename FieldType::value_type> f(d);
    std::generate(std::begin(f), std::end(f), [&rnd]() { return rnd(); });
    f.back() = FieldType::value_type::one();

    merkle_tree_type tree = zk::algorithms::precommit<LPCScheme>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::vector<typename FieldType::value_type> evaluation_points = {
        algebra::fields::arithmetic_params<FieldType>::multiplicative_generator};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points.size(), 1, f.size(), fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_lpc_dfs_basic_test) {
    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0,
                                                               false>
        lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    static_assert(zk::is_commitment<FRIScheme>::value);
    static_assert(zk::is_commitment<LPCScheme>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    math::polynomial<typename FieldType::value_type> f_data = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};
    math::polynomial_dfs<typename FieldType::value_type> f;
    f.from_coefficients(f_data);

    // TODO: take a point outside of the basic domain
    std::vector<typename FieldType::value_type> evaluation_points = {
        algebra::fields::arithmetic_params<FieldType>::multiplicative_generator};

    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points.size(), 1, f.size(), fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_lpc_basic_test) {

    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t leaf_size = 1;
    constexpr static const bool is_const_size = true;
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, is_const_size> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m,
                                                               leaf_size, is_const_size>
        lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}}};

    // TODO: take a point outside of the basic domain
    std::array<std::vector<typename FieldType::value_type>, leaf_size> evaluation_points = {
        {{algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}}};

    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points[0].size(), f.size(), f[0].size(), fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_lpc_basic_skipping_layers_test) {
    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t leaf_size = 2;
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 1024;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, true> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m,
                                                               leaf_size, true>
        lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 4);

    // commit

    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f;
    f.fill(math::polynomial<typename FieldType::value_type>(d));
    for (auto &f_i : f) {
        std::generate(std::begin(f_i), std::end(f_i), [&rnd]() { return rnd(); });
        f_i.back() = FieldType::value_type::one();
    }

    // TODO: take a point outside of the basic domain
    std::array<std::vector<typename FieldType::value_type>, leaf_size> evaluation_points = {
            {{algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
             {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}}};

    size_t max_d = 0;
    for( size_t i = 0; i < f.size(); i++){
        if( max_d < f[i].size() ){
            max_d = f[i].size();
        }
    }
    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points[0].size(), 2, max_d, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_lpc_basic_test_2) {

    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t leaf_size = 2;
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, true> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m,
                                                               leaf_size, true>
        lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 2, 5, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}}};

    // TODO: take a point outside of the basic domain
    std::array<std::vector<typename FieldType::value_type>, leaf_size> evaluation_points = {
        {{algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
         {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}}};

    size_t max_d = 0;
    for( size_t i = 0; i < f.size(); i++){
        if( max_d < f[i].size() ){
            max_d = f[i].size();
        }
    }
    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points[0].size(), 2, max_d, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_lpc_dfs_basic_test_2) {

    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t leaf_size = 2;
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, true> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m,
                                                               leaf_size, true>
        lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f_data = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 7, 7, 7, 2, 1, 1}}};

    std::array<math::polynomial_dfs<typename FieldType::value_type>, leaf_size> f;
    for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
        f[polynom_index].from_coefficients(f_data[polynom_index]);
    }

    // TODO: take a point outside of the basic domain
    std::array<std::vector<typename FieldType::value_type>, leaf_size> evaluation_points = {
        {{algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
         {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}}};

    size_t max_d = 0;
    for( size_t i = 0; i < f.size(); i++){
        if( max_d < f[i].size() ){
            max_d = f[i].size();
        }
    }
    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points[0].size(), 2, max_d, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_lpc_basic_test_runtime_size) {

    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t leaf_size = 2;
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0,
                                                               false>
        lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    std::vector<math::polynomial<typename FieldType::value_type>> f = {
        {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 2, 5, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}};

    // TODO: take a point outside of the basic domain
    std::vector<std::vector<typename FieldType::value_type>> evaluation_points = {
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}};

    size_t max_d = 0;
    for( size_t i = 0; i < f.size(); i++){
        if( max_d < f[i].size() ){
            max_d = f[i].size();
        }
    }
    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points[0].size(), 2, max_d, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_lpc_basic_test_runtime_size_skipping_layers) {
    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t leaf_size = 5;
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 2048;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0,
                                                               false>
        lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 4);

    // commit

    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    std::vector<math::polynomial<typename FieldType::value_type>> f(
        leaf_size, math::polynomial<typename FieldType::value_type>(d));
    for (auto &f_i : f) {
        std::generate(std::begin(f_i), std::end(f_i), [&rnd]() { return rnd(); });
        f_i.back() = FieldType::value_type::one();
    }

    // TODO: take a point outside of the basic domain
    std::vector<std::vector<typename FieldType::value_type>> evaluation_points = {
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    size_t max_d = 0;
    for( size_t i = 0; i < f.size(); i++){
        if( max_d < f[i].size() ){
            max_d = f[i].size();
        }
    }
    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points[0].size(), 5, max_d, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_lpc_dfs_basic_test_runtime_size) {
    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t leaf_size = 2;
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0,
                                                               false>
        lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    std::vector<math::polynomial<typename FieldType::value_type>> f_data = {
        {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 2, 5, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}};

    std::vector<math::polynomial_dfs<typename FieldType::value_type>> f(leaf_size);
    for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
        f[polynom_index].from_coefficients(f_data[polynom_index]);
    }

    // TODO: take a point outside of the basic domain
    std::vector<std::vector<typename FieldType::value_type>> evaluation_points = {
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}};

    size_t max_d = 0;
    for( size_t i = 0; i < f.size(); i++){
        if( max_d < f[i].size() ){
            max_d = f[i].size();
        }
    }
    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points[0].size(), 2, max_d, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_CASE(marshalling_batched_lpc_dfs_basic_test_runtime_size_skipping_layers) {
    // setup
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t leaf_size = 10;
    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 1024;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> FRIScheme;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0,
                                                               false>
        lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> LPCScheme;

    typedef typename LPCScheme::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename FRIScheme::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 4);

    // commit

    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    std::vector<math::polynomial<typename FieldType::value_type>> f_data(
        leaf_size, math::polynomial<typename FieldType::value_type>(d));
    for (auto &f_i : f_data) {
        std::generate(std::begin(f_i), std::end(f_i), [&rnd]() { return rnd(); });
        f_i.back() = FieldType::value_type::one();
    }

    std::vector<math::polynomial_dfs<typename FieldType::value_type>> f(leaf_size);
    for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
        f[polynom_index].from_coefficients(f_data[polynom_index]);
    }

    // TODO: take a point outside of the basic domain
    std::vector<std::vector<typename FieldType::value_type>> evaluation_points = {
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}};

    size_t max_d = 0;
    for( size_t i = 0; i < f.size(); i++){
        if( max_d < f[i].size() ){
            max_d = f[i].size();
        }
    }
    auto proof = generate_random_lpc_proof<LPCScheme, FRIScheme>(evaluation_points[0].size(), 10, max_d, fri_params);

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    test_lpc_proof<Endianness, LPCScheme>(proof);
}

BOOST_AUTO_TEST_SUITE_END()