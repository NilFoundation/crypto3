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

#define BOOST_TEST_MODULE fri_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(fri_test_suite)

BOOST_AUTO_TEST_CASE(fri_basic_test) {

    // setup
    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;

    static_assert(zk::is_commitment<fri_type>::value);
    static_assert(!zk::is_commitment<merkle_hash_type>::value);

    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        zk::commitments::detail::calculate_domain_set<FieldType>(extended_log, r);

    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};
    params.r = r;
    params.D = D;
    params.q = q;
    params.max_degree = d - 1;

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());
    BOOST_CHECK(params.q.evaluate(D[0]->get_domain_element(1)) == D[0]->get_domain_element(1).squared());

    // commit
    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};

    merkle_tree_type commit_merkle = fri_type::precommit(f, D[0]);
    std::array<typename FieldType::value_type, 1> evaluation_points = {D[0]->get_domain_element(1).pow(5)};

    // eval
    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = fri_type::proof_eval(f, commit_merkle, params, transcript);

    // verify
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);

    BOOST_CHECK(fri_type::verify_eval(proof, params, transcript_verifier));

    typename FieldType::value_type verifier_next_challenge = transcript_verifier.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
}

BOOST_AUTO_TEST_CASE(fri_fold_test) {

    // fri params
    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 4;
    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;
    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    std::size_t d_log = boost::static_log2<d>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D = 
        zk::commitments::detail::calculate_domain_set<FieldType>(d_log, 1);

    params.r = r;
    params.D = D;
    params.q = q;

    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 3};

    typename FieldType::value_type omega = D[0]->get_domain_element(1);

    typename FieldType::value_type x_next = params.q.evaluate(omega);
    typename FieldType::value_type alpha = algebra::random_element<FieldType>();

    math::polynomial<typename FieldType::value_type> f_next = zk::commitments::detail::fold_polynomial<FieldType>(f, alpha);

    BOOST_CHECK_EQUAL(f_next.degree(), f.degree() / 2);
    std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> interpolation_points {
        std::make_pair(omega, f.evaluate(omega)),
        std::make_pair(-omega, f.evaluate(-omega)),
    };

    math::polynomial<typename FieldType::value_type> interpolant = math::lagrange_interpolation(interpolation_points);
    typename FieldType::value_type x1 = interpolant.evaluate(alpha);
    typename FieldType::value_type x2 = f_next.evaluate(x_next);
    BOOST_CHECK(x1 == x2);
}

BOOST_AUTO_TEST_CASE(fri_steps_count_test) {

    // fri params
    using curve_type = algebra::curves::mnt4<298>;
    using FieldType = typename curve_type::base_field_type;

    typedef hashes::sha2<256> merkle_hash_type;
    typedef hashes::sha2<256> transcript_hash_type;

    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

    constexpr static const std::size_t d = 16;

    constexpr static const std::size_t r = boost::static_log2<d>::value;
    constexpr static const std::size_t m = 2;

    typedef zk::commitments::fri<FieldType, merkle_hash_type, transcript_hash_type, m> fri_type;
    typedef typename fri_type::proof_type proof_type;
    typedef typename fri_type::params_type params_type;

    params_type params;
    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};

    constexpr static const std::size_t d_extended = d;
    std::size_t extended_log = boost::static_log2<d_extended>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        zk::commitments::detail::calculate_domain_set<FieldType>(extended_log, r);

    params.r = r - 1;
    params.D = D;
    params.q = f;
    params.max_degree = d - 1;

    BOOST_CHECK(D[1]->m == D[0]->m / 2);
    merkle_tree_type commit_merkle = fri_type::precommit(f, D[0]);
    std::array<typename FieldType::value_type, 1> evaluation_points = {D[0]->get_domain_element(1).pow(5)};

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    zk::transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);

    proof_type proof = fri_type::proof_eval(f, commit_merkle, params, transcript);

    math::polynomial<typename FieldType::value_type> final_polynomial = proof.final_polynomial;
    BOOST_CHECK_EQUAL(proof.final_polynomial.degree(), 1);
}

BOOST_AUTO_TEST_SUITE_END()