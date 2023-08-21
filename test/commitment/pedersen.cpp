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

#define BOOST_TEST_MODULE pedersen_test

#include <vector>
#include <iostream>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/commitments/polynomial/pedersen.hpp>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(pedersen_test_suite)

    BOOST_AUTO_TEST_CASE(pedersen_basic_test) {

        // setup
        using curve_type = algebra::curves::bls12<381>;
        using curve_group_type = curve_type::template g1_type<>;
        using field_type = typename curve_type::scalar_field_type;

        constexpr static const int n = 50;
        constexpr static const int k = 26;
        curve_group_type::value_type g = algebra::random_element<curve_group_type>();
        curve_group_type::value_type h = algebra::random_element<curve_group_type>();
        while (g == h) {
            h = algebra::random_element<curve_group_type>();
        }

        typedef typename zk::commitments::pedersen<curve_type> pedersen_type;

        typedef typename pedersen_type::proof_type proof_type;
        typedef typename pedersen_type::params_type params_type;

        params_type params;

        params.n = n;
        params.k = k;
        params.g = g;
        params.h = h;

        BOOST_CHECK(g != h);
        BOOST_CHECK(n >= k);
        BOOST_CHECK(k > 0);

        // commit
        constexpr static const field_type::value_type w = field_type::value_type(37684);

        // eval
        proof_type proof = pedersen_type::proof_eval(params, w);

        // verify
        BOOST_CHECK(pedersen_type::verify_eval(params, proof));

        std::vector<int> idx;
        std::vector<int> idx_base;
        for (int i = 1; i <= n; ++i) {
            idx_base.push_back(i);
        }
        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(idx_base.begin(), idx_base.end(), gen);
        for (int i = 0; i < k; ++i) {
            idx.push_back(idx_base[i]);
        }

        BOOST_CHECK(idx.size() >= k);
        field_type::value_type secret = pedersen_type::message_eval(params, proof, idx);
        BOOST_CHECK(w == secret);
    }

    BOOST_AUTO_TEST_CASE(pedersen_short_test) {

        // setup
        using curve_type = algebra::curves::bls12<381>;
        using curve_group_type = curve_type::template g1_type<>;
        using field_type = typename curve_type::scalar_field_type;

        constexpr static const int n = 2;
        constexpr static const int k = 1;
        static curve_group_type::value_type g = algebra::random_element<curve_group_type>();
        static curve_group_type::value_type h = algebra::random_element<curve_group_type>();
        while (g == h) {
            h = algebra::random_element<curve_group_type>();
        }

        typedef typename zk::commitments::pedersen<curve_type> pedersen_type;

        typedef typename pedersen_type::proof_type proof_type;
        typedef typename pedersen_type::params_type params_type;

        params_type params;

        params.n = n;
        params.k = k;
        params.g = g;
        params.h = h;

        BOOST_CHECK(g != h);
        BOOST_CHECK(n >= k);
        BOOST_CHECK(k > 0);

        // commit
        constexpr static const field_type::value_type w = field_type::value_type(3);

        // eval
        proof_type proof = pedersen_type::proof_eval(params, w);

        // verify
        BOOST_CHECK(pedersen_type::verify_eval(params, proof));

        std::vector<int> idx;
        std::vector<int> idx_base;
        for (int i = 1; i <= n; ++i) {
            idx_base.push_back(i);
        }
        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(idx_base.begin(), idx_base.end(), gen);
        for (int i = 0; i < k; ++i) {
            idx.push_back(idx_base[i]);
        }

        BOOST_CHECK(idx.size() >= k);
        field_type::value_type secret = pedersen_type::message_eval(params, proof, idx);
        BOOST_CHECK(w == secret);
    }

    BOOST_AUTO_TEST_CASE(pedersen_long_test) {

        // setup
        using curve_type = algebra::curves::bls12<381>;
        using curve_group_type = curve_type::template g1_type<>;
        using field_type = typename curve_type::scalar_field_type;

        constexpr static const int n = 2000000000;
        constexpr static const int k = 1999999999;
        static curve_group_type::value_type g = algebra::random_element<curve_group_type>();
        static curve_group_type::value_type h = algebra::random_element<curve_group_type>();
        while (g == h) {
            h = algebra::random_element<curve_group_type>();
        }

        typedef typename zk::commitments::pedersen<curve_type> pedersen_type;

        typedef typename pedersen_type::proof_type proof_type;
        typedef typename pedersen_type::params_type params_type;

        params_type params;

        params.n = n;
        params.k = k;
        params.g = g;
        params.h = h;

        BOOST_CHECK(g != h);
        BOOST_CHECK(n >= k);
        BOOST_CHECK(k > 0);

        // commit
        constexpr static const field_type::value_type w = field_type::value_type(300000000);

        // eval
        proof_type proof = pedersen_type::proof_eval(params, w);

        // verify
        BOOST_CHECK(pedersen_type::verify_eval(params, proof));

        std::vector<int> idx;
        std::vector<int> idx_base;
        for (int i = 1; i <= n; ++i) {
            idx_base.push_back(i);
        }
        std::random_device rd;
        std::mt19937 gen(rd());
        std::shuffle(idx_base.begin(), idx_base.end(), gen);
        for (int i = 0; i < k; ++i) {
            idx.push_back(idx_base[i]);
        }

        BOOST_CHECK(idx.size() >= k);
        field_type::value_type secret = pedersen_type::message_eval(params, proof, idx);
        BOOST_CHECK(w == secret);
    }

BOOST_AUTO_TEST_SUITE_END()
