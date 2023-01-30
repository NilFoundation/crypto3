//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#define BOOST_TEST_MODULE lpc_test

#include <string>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

using namespace nil::crypto3;

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

BOOST_AUTO_TEST_SUITE(lpc_test_suite)

BOOST_AUTO_TEST_CASE(lpc_basic_test) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0, false>
            lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(zk::is_commitment<lpc_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    std::array<std::vector<math::polynomial<typename FieldType::value_type>>,4> f;
    f[0].push_back({1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
    f[1].push_back({0, 1});
    f[2].push_back({0});
    f[3].push_back({0});

    std::array<merkle_tree_type,4> tree;
    tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
    tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
    tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
    tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::vector<typename FieldType::value_type> evaluation_point;
    evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
    std::array<std::vector<std::vector<typename FieldType::value_type>>, 4> evaluation_points;
    evaluation_points[0].push_back(evaluation_point);
    evaluation_points[1].push_back(evaluation_point);
    evaluation_points[2].push_back(evaluation_point);
    evaluation_points[3].push_back(evaluation_point);

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
    
    std::array<typename lpc_type::commitment_type, 4> commitment;

    commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
    commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
    commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
    commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, commitment, fri_params, transcript_verifier
    ));
}
/*
BOOST_AUTO_TEST_CASE(lpc_basic_skipping_layers_test) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0, false>
            lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(zk::is_commitment<lpc_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 5);

    // commit

    nil::crypto3::random::algebraic_random_device<FieldType> rnd;
    math::polynomial<typename FieldType::value_type> f(d);
    std::generate(std::begin(f), std::end(f), [&rnd]() { return rnd(); });
    f.back() = FieldType::value_type::one();

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::vector<typename FieldType::value_type> evaluation_points = {
        algebra::fields::arithmetic_params<FieldType>::multiplicative_generator};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(lpc_dfs_basic_test) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0, false>
            lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(zk::is_commitment<lpc_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    math::polynomial<typename FieldType::value_type> f_data = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};
    math::polynomial_dfs<typename FieldType::value_type> f;
    f.from_coefficients(f_data);

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::vector<typename FieldType::value_type> evaluation_points = {
        algebra::fields::arithmetic_params<FieldType>::multiplicative_generator};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(batched_lpc_test_suite)

BOOST_AUTO_TEST_CASE(batched_lpc_basic_test) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, is_const_size>
        fri_type;

    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type,
                                                               transcript_hash_type,
                                                               lambda,
                                                               r,
                                                               m,
                                                               leaf_size,
                                                               is_const_size>
        lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}}};

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::array<std::vector<typename FieldType::value_type>, leaf_size> evaluation_points = {
        {{algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}}};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(batched_lpc_basic_skipping_layers_test) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, true> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, leaf_size, true>
            lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

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

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::array<std::vector<typename FieldType::value_type>, leaf_size> evaluation_points = {
        {{algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
         {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}}};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(batched_lpc_basic_test_2) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, true> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, leaf_size, true>
            lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    std::array<math::polynomial<typename FieldType::value_type>, leaf_size> f = {
        {{1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 2, 5, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}}};

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::array<std::vector<typename FieldType::value_type>, leaf_size> evaluation_points = {
        {{algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
         {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}}};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(batched_lpc_dfs_basic_test_2) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, leaf_size, true> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, leaf_size, true>
            lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

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

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::array<std::vector<typename FieldType::value_type>, leaf_size> evaluation_points = {
        {{algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
         {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}}};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(batched_lpc_basic_test_runtime_size) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0, false>
            lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1);

    // commit

    std::vector<math::polynomial<typename FieldType::value_type>> f = {
        {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}, {1, 2, 5, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1}};

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::vector<std::vector<typename FieldType::value_type>> evaluation_points = {
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(batched_lpc_basic_test_runtime_size_skipping_layers) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0, false>
            lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

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

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::vector<std::vector<typename FieldType::value_type>> evaluation_points = {
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(batched_lpc_dfs_basic_test_runtime_size) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0, false>
            lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

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

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::vector<std::vector<typename FieldType::value_type>> evaluation_points = {
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}

BOOST_AUTO_TEST_CASE(batched_lpc_dfs_basic_test_runtime_size_skipping_layers) {

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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m, 0, false> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 0, false>
            lpc_params_type;
    typedef zk::commitments::batched_list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    typedef typename lpc_type::proof_type proof_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params;

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

    merkle_tree_type tree = zk::algorithms::precommit<lpc_type>(f, D[0], fri_params.step_list.front());

    // TODO: take a point outside of the basic domain
    std::vector<std::vector<typename FieldType::value_type>> evaluation_points = {
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator},
        {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator}};

    std::array<std::uint8_t, 96> x_data {};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, zk::algorithms::commit<lpc_type>(tree), fri_params, transcript_verifier));
}
*/
BOOST_AUTO_TEST_SUITE_END()
