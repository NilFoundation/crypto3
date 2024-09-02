//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// Test all circuits on one set of parameters (pallas and poseidon)
//

#define BOOST_TEST_MODULE placeholder_circuits_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

#include "circuits.hpp"
#include "placeholder_test_runner.hpp"

BOOST_AUTO_TEST_SUITE(placeholder_circuits)

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using hash_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;
    using test_runner_type = placeholder_test_runner<field_type, hash_type, hash_type>;

    BOOST_AUTO_TEST_CASE(circuit1)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_1<field_type>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

    BOOST_AUTO_TEST_CASE(circuit2)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto pi0 = random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()();
        auto circuit = circuit_test_t<field_type>(
                pi0,
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

    BOOST_AUTO_TEST_CASE(circuit3)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_3<field_type>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

    BOOST_AUTO_TEST_CASE(circuit4)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_4<field_type>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

    BOOST_AUTO_TEST_CASE(circuit5)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_5<field_type>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

    BOOST_AUTO_TEST_CASE(circuit6)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_6<field_type>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

    BOOST_AUTO_TEST_CASE(circuit7)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_7<field_type>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

    BOOST_AUTO_TEST_CASE(circuit_fib)
    {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_fib<field_type, 100>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()
        );
        test_runner_type test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }


BOOST_AUTO_TEST_SUITE_END()
