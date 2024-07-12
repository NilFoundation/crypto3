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
// Test circuit1 on different curves field: pallas, vesta, mnt4, mnt6, bls12
//

#define BOOST_TEST_MODULE placeholder_curves_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

#include "circuits.hpp"
#include "placeholder_test_runner.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;


BOOST_AUTO_TEST_SUITE(placeholder_curves_test)

    using hash_type = hashes::keccak_1600<256>;

    using TestRunners = boost::mpl::list<
            placeholder_test_runner<algebra::curves::pallas::scalar_field_type, hash_type, hash_type>,
            placeholder_test_runner<algebra::curves::vesta::scalar_field_type, hash_type, hash_type>,
            placeholder_test_runner<algebra::curves::mnt4_298::scalar_field_type, hash_type, hash_type>,
            placeholder_test_runner<algebra::curves::mnt6_298::scalar_field_type, hash_type, hash_type>,
            placeholder_test_runner<algebra::curves::bls12_381::scalar_field_type, hash_type, hash_type>,
            placeholder_test_runner<algebra::curves::bls12_377::scalar_field_type, hash_type, hash_type>,
            placeholder_test_runner<algebra::curves::alt_bn128_254::scalar_field_type, hash_type, hash_type>
    >;

    BOOST_AUTO_TEST_CASE_TEMPLATE(curve_test, TestRunner, TestRunners) {
        using field_type = typename TestRunner::field_type;
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto circuit = circuit_test_1<field_type>(
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        TestRunner test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

BOOST_AUTO_TEST_SUITE_END()

