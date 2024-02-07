//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

// Do it manually for all performance tests
#define ZK_PLACEHOLDER_PROFILING_ENABLED

#include <string>

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
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_scoped_profiler.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<>
            struct print_log_value<nil::crypto3::math::polynomial<
                algebra::fields::detail::element_fp<algebra::fields::params<algebra::fields::bls12_base_field<381>>>>> {
                void operator()(std::ostream &,
                                const nil::crypto3::math::polynomial<algebra::fields::detail::element_fp<
                                    algebra::fields::params<algebra::fields::bls12_base_field<381>>>> &) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

template<typename FieldType, typename NumberType>
std::vector<math::polynomial<typename FieldType::value_type>> generate(NumberType degree) {
    typedef boost::random::independent_bits_engine<boost::random::mt19937,
                                                   FieldType::modulus_bits,
                                                   typename FieldType::value_type::integral_type>
        random_polynomial_generator_type;

    std::vector<math::polynomial<typename FieldType::value_type>> res;

    boost::random::random_device rd;     // Will be used to obtain a seed for the random number engine
    boost::random::mt19937 gen(rd());    // Standard mersenne_twister_engine seeded with rd()
    boost::random::uniform_int_distribution<> distrib(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());

    random_polynomial_generator_type polynomial_element_gen;
    std::size_t height = 1;
    res.reserve(height);

    for (int i = 0; i < height; i++) {
        math::polynomial<typename FieldType::value_type> poly;
        for (int j = 0; j < degree; j++) {
            poly.push_back(typename FieldType::value_type(polynomial_element_gen()));
        }
        res.push_back(poly);
    }

    return res;
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

BOOST_AUTO_TEST_SUITE(lpc_performance_test_suite)

BOOST_AUTO_TEST_CASE(step_list_1) {
    PROFILE_PLACEHOLDER_SCOPE("LPC step list 1 test");
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::keccak_1600<256> merkle_hash_type;
    typedef hashes::keccak_1600<256> transcript_hash_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    // It's important parameter
    constexpr static const std::size_t d = 1 << 24;
    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;

    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m > fri_type;
    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, m>  lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params(
        d - 1,
        D,
        generate_random_step_list(r, 1),
        r
    );

    using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type, math::polynomial<typename FieldType::value_type>>;
    lpc_scheme_type lpc_scheme_prover(fri_params);
    lpc_scheme_type lpc_scheme_verifier(fri_params);

    typedef boost::random::independent_bits_engine<
        boost::random::mt19937,  FieldType::modulus_bits,
        typename FieldType::value_type::integral_type
    > random_polynomial_generator_type;

    std::vector<math::polynomial<typename FieldType::value_type>> res;

    // Generate polys
    boost::random::random_device rd;     // Will be used to obtain a seed for the random number engine
    boost::random::mt19937 gen(rd());    // Standard mersenne_twister_engine seeded with rd()
    boost::random::uniform_int_distribution<> distrib(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());

    random_polynomial_generator_type polynomial_element_gen;
    std::size_t height = 1;
    res.reserve(height);

    for (int i = 0; i < height; i++) {
        math::polynomial<typename FieldType::value_type> poly(fri_params.max_degree + 1);
        for (int j = 0; j < fri_params.max_degree + 1; j++) {
            poly[i] = typename FieldType::value_type(polynomial_element_gen());
        }

        std::map<std::size_t, typename lpc_scheme_type::commitment_type> commitments;
        {
            PROFILE_PLACEHOLDER_SCOPE("polynomial commitment");
            lpc_scheme_prover.append_to_batch(0,poly);
            commitments[0] = lpc_scheme_prover.commit(0);
        }


        typename lpc_scheme_type::proof_type proof;
        std::array<std::uint8_t, 96> x_data {};
        {
            PROFILE_PLACEHOLDER_SCOPE("proof generation");
            lpc_scheme_prover.append_eval_point(0, algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
            zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
            proof = lpc_scheme_prover.proof_eval(transcript);
        }

        {
            PROFILE_PLACEHOLDER_SCOPE("verification");
            zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
            lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));

            lpc_scheme_verifier.append_eval_point(0,  algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
            BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));
        }
    }
}

BOOST_AUTO_TEST_CASE(step_list_3) {
    PROFILE_PLACEHOLDER_SCOPE("LPC step list 3 test");
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::keccak_1600<256> merkle_hash_type;
    typedef hashes::keccak_1600<256> transcript_hash_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    // It's important parameter
    constexpr static const std::size_t d = 1 << 24;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m > fri_type;
    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, m>  lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params(
        d - 1,
        D,
        generate_random_step_list(r, 3),
        r
    );

    using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type, math::polynomial<typename FieldType::value_type>>;
    lpc_scheme_type lpc_scheme_prover(fri_params);
    lpc_scheme_type lpc_scheme_verifier(fri_params);

    typedef boost::random::independent_bits_engine<
        boost::random::mt19937,  FieldType::modulus_bits,
        typename FieldType::value_type::integral_type
    > random_polynomial_generator_type;

    std::vector<math::polynomial<typename FieldType::value_type>> res;

    // Generate polys
    boost::random::random_device rd;     // Will be used to obtain a seed for the random number engine
    boost::random::mt19937 gen(rd());    // Standard mersenne_twister_engine seeded with rd()
    boost::random::uniform_int_distribution<> distrib(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());

    random_polynomial_generator_type polynomial_element_gen;
    std::size_t height = 1;
    res.reserve(height);

    for (int i = 0; i < height; i++) {
        math::polynomial<typename FieldType::value_type> poly(fri_params.max_degree + 1);
        for (int j = 0; j < fri_params.max_degree + 1; j++) {
            poly[i] = typename FieldType::value_type(polynomial_element_gen());
        }

        std::map<std::size_t, typename lpc_scheme_type::commitment_type> commitments;
        {
            PROFILE_PLACEHOLDER_SCOPE("polynomial commitment");
            lpc_scheme_prover.append_to_batch(0,poly);
            commitments[0] = lpc_scheme_prover.commit(0);
        }


        typename lpc_scheme_type::proof_type proof;
        std::array<std::uint8_t, 96> x_data {};
        {
            PROFILE_PLACEHOLDER_SCOPE("proof generation");
            lpc_scheme_prover.append_eval_point(0, algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
            zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
            proof = lpc_scheme_prover.proof_eval(transcript);
        }

        {
            PROFILE_PLACEHOLDER_SCOPE("verification");
            zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
            lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));

            lpc_scheme_verifier.append_eval_point(0,  algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
            BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));
        }
    }
}

BOOST_AUTO_TEST_CASE(step_list_5) {
    PROFILE_PLACEHOLDER_SCOPE("LPC step list 5 test");
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::keccak_1600<256> merkle_hash_type;
    typedef hashes::keccak_1600<256> transcript_hash_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    // It's important parameter
    constexpr static const std::size_t d = 1 << 24;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m > fri_type;
    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, m>  lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    typename fri_type::params_type fri_params(
        d - 1,
        D,
        generate_random_step_list(r, 5),
        r
    );

    using lpc_scheme_type = nil::crypto3::zk::commitments::lpc_commitment_scheme<lpc_type, math::polynomial<typename FieldType::value_type>>;
    lpc_scheme_type lpc_scheme_prover(fri_params);
    lpc_scheme_type lpc_scheme_verifier(fri_params);

    typedef boost::random::independent_bits_engine<
        boost::random::mt19937,  FieldType::modulus_bits,
        typename FieldType::value_type::integral_type
    > random_polynomial_generator_type;

    std::vector<math::polynomial<typename FieldType::value_type>> res;

    // Generate polys
    boost::random::random_device rd;     // Will be used to obtain a seed for the random number engine
    boost::random::mt19937 gen(rd());    // Standard mersenne_twister_engine seeded with rd()
    boost::random::uniform_int_distribution<> distrib(std::numeric_limits<int>::min(), std::numeric_limits<int>::max());

    random_polynomial_generator_type polynomial_element_gen;
    std::size_t height = 1;
    res.reserve(height);

    for (int i = 0; i < height; i++) {
        math::polynomial<typename FieldType::value_type> poly(fri_params.max_degree + 1);
        for (int j = 0; j < fri_params.max_degree + 1; j++) {
            poly[i] = typename FieldType::value_type(polynomial_element_gen());
        }

        std::map<std::size_t, typename lpc_scheme_type::commitment_type> commitments;
        {
            PROFILE_PLACEHOLDER_SCOPE("polynomial commitment");
            lpc_scheme_prover.append_to_batch(0,poly);
            commitments[0] = lpc_scheme_prover.commit(0);
        }


        typename lpc_scheme_type::proof_type proof;
        std::array<std::uint8_t, 96> x_data {};
        {
            PROFILE_PLACEHOLDER_SCOPE("proof generation");
            lpc_scheme_prover.append_eval_point(0, algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
            zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);
            proof = lpc_scheme_prover.proof_eval(transcript);
        }

        {
            PROFILE_PLACEHOLDER_SCOPE("verification");
            zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);
            lpc_scheme_verifier.set_batch_size(0, proof.z.get_batch_size(0));

            lpc_scheme_verifier.append_eval_point(0,  algebra::fields::arithmetic_params<FieldType>::multiplicative_generator);
            BOOST_CHECK(lpc_scheme_verifier.verify_eval(proof, commitments, transcript_verifier));
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()