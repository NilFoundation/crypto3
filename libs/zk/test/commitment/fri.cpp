//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#define BOOST_TEST_MODULE fri_test

#include <string>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

using namespace nil::crypto3;

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const std::size_t max_step) {
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

BOOST_AUTO_TEST_SUITE(fri_test_suite)

template<typename FieldType, typename PolynomialType>
void fri_basic_test()
{
    // setup
    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;
    constexpr static const std::size_t lambda = 40;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;


    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(extended_log, r);

    std::size_t degree_log = std::ceil(std::log2(d - 1));
    params_type params(
            1, /*max_step*/
            degree_log,
            lambda,
            2, //expand_factor
            true, // use_grinding
            16 // grinding_parameter
            );

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());

    // commit

    std::vector<typename FieldType::value_type> coefficients =
        {1u, 3u, 4u, 1u, 5u, 6u, 7u, 2u, 8u, 7u, 5u, 6u, 1u, 2u, 1u, 1u};

    PolynomialType f;
    if constexpr (std::is_same<math::polynomial_dfs<typename FieldType::value_type>,
            PolynomialType>::value) {
        f.from_coefficients(coefficients);
        if (f.size() != params.D[0]->size()) {
            f.resize(params.D[0]->size(), nullptr, params.D[0]);
        }
    } else {
        f = PolynomialType(coefficients);
    }

    typename fri_type::merkle_tree_type tree = zk::algorithms::precommit<fri_type>(f, params.D[0],
            params.step_list[0]);
    auto root = zk::algorithms::commit<fri_type>(tree);

    // eval
    std::vector<std::uint8_t> init_blob{0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = zk::algorithms::proof_eval<fri_type>(f, tree, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(zk::algorithms::verify_eval<fri_type>(proof, root, params, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

}

BOOST_AUTO_TEST_CASE(fri_basic_test_polynomial) {

    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using PolynomialType = math::polynomial<FieldType::value_type>;

    fri_basic_test<FieldType, PolynomialType>();
}

BOOST_AUTO_TEST_CASE(fri_basic_test_polynomial_dfs) {

    using curve_type = algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;
    using PolynomialType = math::polynomial_dfs<FieldType::value_type>;

    fri_basic_test<FieldType, PolynomialType>();
}


BOOST_AUTO_TEST_SUITE_END()
