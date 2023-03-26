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
#include <regex>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3;

using dist_type = std::uniform_int_distribution<int>;

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step, boost::random::mt11213b &rnd) {
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

template <typename FieldType>
inline math::polynomial<typename FieldType::value_type> generate_random_polynomial(
    std::size_t degree,
    nil::crypto3::random::algebraic_engine<FieldType> &rnd
){
    math::polynomial<typename FieldType::value_type> result(degree);
    std::generate(std::begin(result), std::end(result), [&rnd]() { return rnd(); });
    return result;
}

template <typename FieldType>
inline math::polynomial_dfs<typename FieldType::value_type> generate_random_polynomial_dfs(
    std::size_t degree,
    nil::crypto3::random::algebraic_engine<FieldType> &rnd
){
    math::polynomial<typename FieldType::value_type> data = generate_random_polynomial(degree, rnd);
    math::polynomial_dfs<typename FieldType::value_type> result;
    result.from_coefficients(data);
    return result;
}

template <typename FieldType>
inline std::vector<math::polynomial<typename FieldType::value_type>> generate_random_polynomial_batch(
    std::size_t batch_size,
    std::size_t degree,
    nil::crypto3::random::algebraic_engine<FieldType> &rnd
){
    std::vector<math::polynomial<typename FieldType::value_type>> result;

    for( uint i = 0; i < batch_size; i++ ){
        result.push_back(generate_random_polynomial(degree, rnd));
    }
    return result;
}

template <typename FieldType>
inline std::vector<math::polynomial_dfs<typename FieldType::value_type>> generate_random_polynomial_dfs_batch(
    std::size_t batch_size,
    std::size_t degree,
    nil::crypto3::random::algebraic_engine<FieldType> &rnd
){
    auto data = generate_random_polynomial_batch(batch_size, degree, rnd);
    std::vector<math::polynomial_dfs<typename FieldType::value_type>> result;

    for( uint i = 0; i < data.size(); i++ ){
        math::polynomial_dfs<typename FieldType::value_type> dfs;
        dfs.from_coefficients(data[i]);
        result.push_back(dfs);
    }
    return result;
}

std::size_t test_global_seed = 0;
boost::random::mt11213b test_global_rnd_engine;
template <typename FieldType>
nil::crypto3::random::algebraic_engine<FieldType> test_global_alg_rnd_engine;

struct test_fixture {
    // Enumerate all fields used in tests;
    using field1_type = algebra::curves::bls12<381>::scalar_field_type;

    test_fixture(){
        test_global_seed = 0;

        for( std::size_t i = 0; i < boost::unit_test::framework::master_test_suite().argc - 1; i++){
            if(std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--seed"){
                if(std::string(boost::unit_test::framework::master_test_suite().argv[i+1]) == "random"){
                    std::random_device rd;
                    test_global_seed = rd();
                    std::cout << "Random seed=" << test_global_seed << std::endl;
                    break;
                }
                if(std::regex_match( boost::unit_test::framework::master_test_suite().argv[i+1], std::regex( ( "((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?" ) ) ) ){
                    test_global_seed = atoi(boost::unit_test::framework::master_test_suite().argv[i+1]);
                    break;
                }
            }
        }

        BOOST_TEST_MESSAGE("test_global_seed = " << test_global_seed);
        test_global_rnd_engine  = boost::random::mt11213b(test_global_seed);
        test_global_alg_rnd_engine<field1_type> = nil::crypto3::random::algebraic_engine<field1_type>(test_global_seed);
    }
    ~test_fixture(){}
};

BOOST_AUTO_TEST_SUITE(lpc_math_polynomial_suite);

BOOST_FIXTURE_TEST_CASE(lpc_basic_test, test_fixture) {
    // Setup types.
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;
    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;
    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 10;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;
    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, 4> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 4>
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

    // Setup params
    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1, test_global_rnd_engine);

    // Generate polynomials
    std::array<std::vector<math::polynomial<typename FieldType::value_type>>,4> f;
    f[0].push_back({1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
    f[1].push_back({0, 1});
    f[1].push_back({0, 1, 2});
    f[1].push_back({0, 1, 3});
    f[2].push_back({0});
    f[3].push_back(generate_random_polynomial(4, test_global_alg_rnd_engine<FieldType>));
    f[3].push_back(generate_random_polynomial(9, test_global_alg_rnd_engine<FieldType>));

    // Commit
    std::array<merkle_tree_type,4> tree;
    tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
    tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
    tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
    tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

    // Generate evaluation points. Generate points outside of the basic domain
    std::vector<typename FieldType::value_type> evaluation_point;
    evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
    std::array<std::vector<std::vector<typename FieldType::value_type>>, 4> evaluation_points;
    evaluation_points[0].push_back(evaluation_point);
    evaluation_points[1].push_back(evaluation_point);
    evaluation_points[2].push_back(evaluation_point);
    evaluation_points[3].push_back(evaluation_point);

    std::array<std::uint8_t, 96> x_data {};

    // Prove
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    std::array<typename lpc_type::commitment_type, 4> commitment;
    commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
    commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
    commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
    commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);
    
    // Verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, commitment, fri_params, transcript_verifier
    ));

    // Check transcript state
    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_FIXTURE_TEST_CASE(lpc_basic_skipping_layers_test, test_fixture) {
    // Setup types
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 10;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 2048;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, 4> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 4>
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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, 4> fri_type;
    typename fri_type::params_type fri_params;

    // Setup params
    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 5, test_global_rnd_engine);

    // Generate polynomials
    std::array<std::vector<math::polynomial<typename FieldType::value_type>>,4> f;
    f[0] = generate_random_polynomial_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>);
    f[1] = generate_random_polynomial_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>);
    f[2] = generate_random_polynomial_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>);
    f[3] = generate_random_polynomial_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>);

    // Commit
    std::array<merkle_tree_type,4> tree;
    tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
    tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
    tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
    tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

    std::array<typename lpc_type::commitment_type, 4> commitment;
    commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
    commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
    commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
    commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);

    // Generate evaluation points. Choose poin1ts outside the domain
    std::vector<typename FieldType::value_type> evaluation_point;
    evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
    std::array<std::vector<std::vector<typename FieldType::value_type>>, 4> evaluation_points;
    evaluation_points[0].push_back(evaluation_point);
    evaluation_points[1].push_back(evaluation_point);
    evaluation_points[2].push_back(evaluation_point);
    evaluation_points[3].push_back(evaluation_point);

    std::array<std::uint8_t, 96> x_data {};

    // Prove
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // Verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, commitment, fri_params, transcript_verifier
    ));

    // Check transcript state
    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_FIXTURE_TEST_CASE(lpc_dfs_basic_test, test_fixture) {

    // Setup types
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 10;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, 4> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 4>
            lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(zk::is_commitment<lpc_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);
    static_assert(!zk::is_commitment<merkle_tree_type>::value);
    static_assert(!zk::is_commitment<std::size_t>::value);

    typedef typename lpc_type::proof_type proof_type;

    // Setup params
    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r+1);

    typename fri_type::params_type fri_params;

    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1, test_global_rnd_engine);

    // Generate polynomials
    std::array<std::vector<math::polynomial_dfs<typename FieldType::value_type>>,4> f;
    f[0] = generate_random_polynomial_dfs_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>);
    f[1] = generate_random_polynomial_dfs_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>);
    f[2] = generate_random_polynomial_dfs_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>);
    f[3] = generate_random_polynomial_dfs_batch<FieldType>(dist_type(1, 10)(test_global_rnd_engine), d, test_global_alg_rnd_engine<FieldType>);

    // Commit
    std::array<merkle_tree_type,4> tree;
    tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
    tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
    tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
    tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

    std::array<typename lpc_type::commitment_type, 4> commitment;
    commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
    commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
    commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
    commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);

    // Generate evaluation points. Choose poin1ts outside the domain
    std::vector<typename FieldType::value_type> evaluation_point;
    evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
    std::array<std::vector<std::vector<typename FieldType::value_type>>, 4> evaluation_points;
    evaluation_points[0].push_back(evaluation_point);
    evaluation_points[1].push_back(evaluation_point);
    evaluation_points[2].push_back(evaluation_point);
    evaluation_points[3].push_back(evaluation_point);

    std::array<std::uint8_t, 96> x_data {};

    // Prove
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    // Verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, commitment, fri_params, transcript_verifier
    ));

    // Check transcript state
    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}
BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(lpc_params_test_suite)
BOOST_FIXTURE_TEST_CASE(lpc_batches_num_3_test, test_fixture){
    // Setup types.
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

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, 3> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 3>
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

    // Setup params
    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1, test_global_rnd_engine);

    // Generate polynomials
    std::array<std::vector<math::polynomial<typename FieldType::value_type>>,3> f;
    f[0].push_back({1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
    f[1].push_back({0, 1});
    f[1].push_back({0, 1, 2});
    f[1].push_back({0, 1, 3});
    f[2].push_back({0});

    // Commit
    std::array<merkle_tree_type,3> tree;
    tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
    tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
    tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());

    // Generate evaluation points. Generate points outside of the basic domain
    std::vector<typename FieldType::value_type> evaluation_point;
    evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);

    std::array<std::vector<std::vector<typename FieldType::value_type>>, 3> evaluation_points;
    evaluation_points[0].push_back(evaluation_point);
    evaluation_points[1].push_back(evaluation_point);
    evaluation_points[2].push_back(evaluation_point);

    std::array<std::uint8_t, 96> x_data {};

    // Prove
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    std::array<typename lpc_type::commitment_type, 3> commitment;
    commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
    commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
    commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
    
    // Verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, commitment, fri_params, transcript_verifier
    ));

    // Check transcript state
    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_FIXTURE_TEST_CASE(lpc_different_hash_types_test, test_fixture) {
    // Setup types.
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;
    typedef hashes::keccak_1600<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;
    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 10;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 16;
    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, 4> fri_type;

    typedef zk::commitments::
        list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 4>
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

    // Setup params
    fri_params.r = r;
    fri_params.D = D;
    fri_params.max_degree = d - 1;
    fri_params.step_list = generate_random_step_list(r, 1, test_global_rnd_engine);

    // Generate polynomials
    std::array<std::vector<math::polynomial<typename FieldType::value_type>>,4> f;
    f[0].push_back({1, 13, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1});
    f[1].push_back({0, 1});
    f[1].push_back({0, 1, 2});
    f[1].push_back({0, 1, 3});
    f[2].push_back({0});
    f[3].push_back(generate_random_polynomial(4, test_global_alg_rnd_engine<FieldType>));
    f[3].push_back(generate_random_polynomial(9, test_global_alg_rnd_engine<FieldType>));

    // Commit
    std::array<merkle_tree_type,4> tree;
    tree[0] = zk::algorithms::precommit<lpc_type>(f[0], D[0], fri_params.step_list.front());
    tree[1] = zk::algorithms::precommit<lpc_type>(f[1], D[0], fri_params.step_list.front());
    tree[2] = zk::algorithms::precommit<lpc_type>(f[2], D[0], fri_params.step_list.front());
    tree[3] = zk::algorithms::precommit<lpc_type>(f[3], D[0], fri_params.step_list.front());

    // Generate evaluation points. Generate points outside of the basic domain
    std::vector<typename FieldType::value_type> evaluation_point;
    evaluation_point.push_back(algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
    std::array<std::vector<std::vector<typename FieldType::value_type>>, 4> evaluation_points;
    evaluation_points[0].push_back(evaluation_point);
    evaluation_points[1].push_back(evaluation_point);
    evaluation_points[2].push_back(evaluation_point);
    evaluation_points[3].push_back(evaluation_point);

    std::array<std::uint8_t, 96> x_data {};

    // Prove
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
    auto proof = zk::algorithms::proof_eval<lpc_type>(evaluation_points, tree, f, fri_params, transcript);

    std::array<typename lpc_type::commitment_type, 4> commitment;
    commitment[0] = zk::algorithms::commit<lpc_type>(tree[0]);
    commitment[1] = zk::algorithms::commit<lpc_type>(tree[1]);
    commitment[2] = zk::algorithms::commit<lpc_type>(tree[2]);
    commitment[3] = zk::algorithms::commit<lpc_type>(tree[3]);
    
    // Verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
    BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
        evaluation_points, proof, commitment, fri_params, transcript_verifier
    ));

    // Check transcript state
    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_SUITE_END()