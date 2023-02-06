//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE kzg_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/algorithms/pair.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/edwards.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/edwards.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::math;

BOOST_AUTO_TEST_SUITE(kzg_test_suite)

BOOST_AUTO_TEST_CASE(kzg_basic_test) {

    typedef algebra::curves::mnt4<298> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;
    typedef zk::commitments::kzg_commitment<curve_type> kzg_type;

    scalar_value_type alpha = 10;
    scalar_value_type i = 2;
    std::size_t n = 16;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3};

    auto srs = kzg_type::setup({n, alpha});
    BOOST_CHECK(curve_type::template g1_type<>::value_type::one() == srs.commitment_key[0]);
    BOOST_CHECK(10 * curve_type::template g1_type<>::value_type::one() == srs.commitment_key[1]);
    BOOST_CHECK(100 * curve_type::template g1_type<>::value_type::one() == srs.commitment_key[2]);
    BOOST_CHECK(1000 * curve_type::template g1_type<>::value_type::one() == srs.commitment_key[3]);
    BOOST_CHECK(alpha * curve_type::template g2_type<>::value_type::one() == srs.verification_key);

    auto commit = kzg_type::commit(srs, f);
    BOOST_CHECK(3209 * curve_type::template g1_type<>::value_type::one() == commit);

    auto eval = f.evaluate(i);
    auto proof = kzg_type::proof_eval(srs, f, i, eval);
    BOOST_CHECK(33 * scalar_value_type::one() == eval);
    BOOST_CHECK(397 * curve_type::template g1_type<>::value_type::one() == proof);

    BOOST_CHECK(kzg_type::verify_eval(srs, proof, commit, i, eval));
}

BOOST_AUTO_TEST_CASE(kzg_random_test) {

    typedef algebra::curves::mnt4<298> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;
    typedef zk::commitments::kzg_commitment<curve_type> kzg_type;

    scalar_value_type alpha = algebra::random_element<scalar_field_type>();
    scalar_value_type i = algebra::random_element<scalar_field_type>();
    std::size_t n = 298;
    const polynomial<scalar_value_type> f = {-1, 1, 2, 3, 5, -15};

    auto srs = kzg_type::setup({n, alpha});
    auto commit = kzg_type::commit(srs, f);
    auto eval = f.evaluate(i);
    auto proof = kzg_type::proof_eval(srs, f, i, eval);

    BOOST_CHECK(kzg_type::verify_eval(srs, proof, commit, i, eval));
}

BOOST_AUTO_TEST_CASE(kzg_batched_accumulate_test) {

    typedef algebra::curves::mnt4<298> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;
    typedef zk::commitments::kzg_batched_commitment<curve_type> kzg_type;

    {
        const std::vector<polynomial<scalar_value_type>> polynomials = {{
            {1, 2, 3, 4}, // 1 + 2x + 2x^2 + 3x^3
        }};
        const scalar_value_type beta = 29;

        const polynomial<scalar_value_type> expect_result = {1, 2, 3, 4};

        BOOST_CHECK(expect_result == kzg_type::accumulate(polynomials, beta));
    }

    {
        const std::vector<polynomial<scalar_value_type>> polynomials = {{
            {1, 2, 3, 4}, // 1 + 2x + 2x^2 + 3x^3
            {5, 6, 7},
            {8, 9, 10, 11, 12},
        }};
        const scalar_value_type beta = 29;

        const polynomial<scalar_value_type> expect_result = {
            1 + beta * 5 + beta * beta * 8,
            2 + beta * 6 + beta * beta * 9,
            3 + beta * 7 + beta * beta * 10,
            4 + beta * 0 + beta * beta * 11,
            0 + beta * 0 + beta * beta * 12
        };

        BOOST_CHECK(expect_result == kzg_type::accumulate(polynomials, beta));
    }

    {
        const std::vector<polynomial<scalar_value_type>> f_set{
            {1, 2, 3, 4, 5, 6, 7, 8},
            {11, 12, 0, 14, 15, 16, 17},
        };
        const scalar_value_type beta = 29;

        const polynomial<scalar_value_type> expect{
            1 + beta * 11,
            2 + beta * 12,
            3 + beta * 0,
            4 + beta * 14,
            5 + beta * 15,
            6 + beta * 16,
            7 + beta * 17,
            8 + beta * 0};

        const polynomial<scalar_value_type> actual =
            kzg_type::accumulate(f_set, beta);

        BOOST_CHECK(expect == actual);
    }
}

BOOST_AUTO_TEST_CASE(kzg_batched_basic_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;
    typedef zk::commitments::kzg_batched_commitment<curve_type> kzg_type;

    scalar_value_type alpha = 7;
    std::size_t n = 8;
    const std::vector<polynomial<scalar_value_type>> fs{{
        {{1, 2, 3, 4, 5, 6, 7, 8}},
        {{11, 12, 13, 14, 15, 16, 17, 18}},
        {{21, 22, 23, 24, 25, 26, 27, 28}},
        {{31, 32, 33, 34, 35, 36, 37, 38}},
    }};
    const std::vector<polynomial<scalar_value_type>> gs{{
        {{71, 72, 73, 74, 75, 76, 77, 78}},
        {{81, 82, 83, 84, 85, 86, 87, 88}},
        {{91, 92, 93, 94, 95, 96, 97, 98}},
    }};
    typename kzg_type::batch_of_batches_of_polynomials_type polys = {fs, gs};
    
    std::vector<scalar_value_type> zs = {123, 456};
    auto evals = kzg_type::evaluate_polynomials(polys, zs);

    auto srs = kzg_type::setup({n, alpha});
    
    std::vector<scalar_value_type> gammas = {54321, 98760};

    auto proof = kzg_type::proof_eval(srs, polys, evals, zs, gammas);

    for (size_t j = 0; j < proof.size(); ++j) {
        scalar_value_type h0_x = scalar_value_type::zero();
        for (size_t i = 0; i < polys[j].size(); ++i) {
            const polynomial<scalar_value_type> &f_i = polys[j][i];
            const scalar_value_type f_x_minus_f_z0 = f_i.evaluate(alpha) - f_i.evaluate(zs[j]);
            const scalar_value_type gamma_power = gammas[j].pow(i);
            h0_x += gamma_power * f_x_minus_f_z0 * ((alpha - zs[j]).inversed());
        }
        BOOST_CHECK(h0_x * curve_type::template g1_type<>::value_type::one() == proof[j]);
    }

    scalar_value_type r = 23546;
    auto c0 = kzg_type::commit(srs, fs);
    auto c1 = kzg_type::commit(srs, gs);
    BOOST_CHECK(kzg_type::verify_eval(srs, proof, evals, {c0, c1}, zs, gammas, r));
}

BOOST_AUTO_TEST_CASE(kzg_batched_random_test) {

    typedef algebra::curves::bls12<381> curve_type;
    typedef typename curve_type::base_field_type::value_type base_value_type;
    typedef typename curve_type::base_field_type base_field_type;
    typedef typename curve_type::scalar_field_type scalar_field_type;
    typedef typename curve_type::scalar_field_type::value_type scalar_value_type;
    typedef zk::commitments::kzg_batched_commitment<curve_type> kzg_type;

    scalar_value_type alpha = algebra::random_element<scalar_field_type>();
    std::size_t n = 298;
    const std::vector<polynomial<scalar_value_type>> f0{{
        {{1, 2, 3, 4, 5, 6, 7, 8}},
        {{11, 12, 13, 14, 15, 16, 17}},
        {{21, 22, 23, 24, 25, 26, 27, 28}},
        {{31, 32, 33, 34, 35, 36, 37, 38, 39}},
    }};
    const std::vector<polynomial<scalar_value_type>> f1{{
        {{71, 72}},
        {{81, 82, 83, 85, 86, 87, 88}},
        {{91, 92, 93, 94, 95, 96, 97, 98, 99, 100}},
    }};
    const std::vector<polynomial<scalar_value_type>> f2{{
        {{73, 74, 25}},
        {{87}},
        {{91, 92, 93, 94, 95, 96, 97, 100, 1, 2, 3}},
    }};
    const kzg_type::batch_of_batches_of_polynomials_type polys = {f0, f1, f2};
    std::size_t num_polys = polys.size();

    std::vector<scalar_value_type> zs;
    for (std::size_t i = 0; i < num_polys; ++i) {
        zs.push_back(algebra::random_element<scalar_field_type>());
    }
    auto evals = kzg_type::evaluate_polynomials(polys, zs);

    auto srs = kzg_type::setup({n, alpha});
    
    std::vector<scalar_value_type> gammas;
    for (std::size_t i = 0; i < num_polys; ++i) {
        gammas.push_back(algebra::random_element<scalar_field_type>());
    }

    auto proof = kzg_type::proof_eval(srs, polys, evals, zs, gammas);

    for (std::size_t j = 0; j < proof.size(); ++j) {
        scalar_value_type h0_x = scalar_value_type::zero();
        for (std::size_t i = 0; i < polys[j].size(); ++i) {
            const polynomial<scalar_value_type> &f_i = polys[j][i];
            const scalar_value_type f_x_minus_f_z0 = f_i.evaluate(alpha) - f_i.evaluate(zs[j]);
            const scalar_value_type gamma_power = gammas[j].pow(i);
            h0_x += gamma_power * f_x_minus_f_z0 * ((alpha - zs[j]).inversed());
        }
        BOOST_CHECK(h0_x * curve_type::template g1_type<>::value_type::one() == proof[j]);
    }

    scalar_value_type r = algebra::random_element<scalar_field_type>();
    std::vector<std::vector<kzg_type::commitment_type>> cs;
    for (std::size_t j = 0; j < num_polys; ++j) {
        cs.push_back(kzg_type::commit(srs, polys[j]));
    }
    BOOST_CHECK(kzg_type::verify_eval(srs, proof, evals, cs, zs, gammas, r));
}

BOOST_AUTO_TEST_SUITE_END()