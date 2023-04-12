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

BOOST_AUTO_TEST_CASE(lpc_performance_test) {
    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::scalar_field_type FieldType;

    typedef hashes::keccak_1600<256> merkle_hash_type;
    typedef hashes::keccak_1600<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;

    constexpr static const std::size_t d = 1 << 24;

    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, lambda, m, 1 > fri_type;
    typedef zk::commitments::list_polynomial_commitment_params<merkle_hash_type, transcript_hash_type, lambda, r, m, 1>
        lpc_params_type;
    typedef zk::commitments::list_polynomial_commitment<FieldType, lpc_params_type> lpc_type;
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
        math::polynomial<typename FieldType::value_type> poly(fri_params.max_degree + 1);
        for (int j = 0; j < fri_params.max_degree + 1; j++) {
            poly[i] = typename FieldType::value_type(polynomial_element_gen());
        }
        merkle_tree_type tree =
            zk::algorithms::precommit<lpc_type>(poly, D[0], fri_params.step_list.front());    // phase_1: Commit

        // TODO: take a point outside of the basic domain
        std::vector<typename FieldType::value_type> point = {algebra::fields::arithmetic_params<FieldType>::multiplicative_generator};
        std::vector<std::vector<typename FieldType::value_type>> evaluation_points = {
            point
        };

        std::array<std::uint8_t, 96> x_data {};
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(x_data);

        std::array<std::vector<std::vector<typename FieldType::value_type>>,1> evaluation_points_batch = {
            evaluation_points
        };
        std::array<merkle_tree_type, 1> tree_batch = {tree};

        std::vector<math::polynomial<typename FieldType::value_type>> poly_vector = {poly};
        std::array<std::vector<math::polynomial<typename FieldType::value_type>>, 1> poly_batch = {poly_vector};

        auto proof = zk::algorithms::proof_eval<lpc_type>(
            evaluation_points_batch, tree_batch, poly_batch, fri_params, transcript);    // phase_2: Prove

        // verify
        zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(x_data);

        std::array<typename fri_type::commitment_type, 1> commitment_batch = {tree.root()};
        BOOST_CHECK(zk::algorithms::verify_eval<lpc_type>(
            evaluation_points_batch, proof, commitment_batch, fri_params, transcript_verifier)
        );    // phase_3: Verify
    }
}

BOOST_AUTO_TEST_SUITE_END()