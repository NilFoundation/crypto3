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
// Test circuit2 with KZG commitment schemes, v1 and v2 on different curves
//

#define BOOST_TEST_MODULE placeholder_kzg_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/gates_argument.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg_v2.hpp>
#include <nil/crypto3/zk/commitments/batched_commitment.hpp>
#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

#include "circuits.hpp"
#include "placeholder_test_runner.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

using hash_type = hashes::keccak_1600<256>;

BOOST_AUTO_TEST_SUITE(placeholder_circuit2_kzg)

    using TestRunners = boost::mpl::list<
            placeholder_kzg_test_runner<algebra::curves::mnt4_298, hash_type>,
            placeholder_kzg_test_runner<algebra::curves::mnt6_298, hash_type>
    >;

    BOOST_AUTO_TEST_CASE_TEMPLATE(kzg_test, TestRunner, TestRunners) {
        using field_type = typename TestRunner::field_type;
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto pi0 = random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()();
        auto circuit = circuit_test_t<field_type>(
                pi0,
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        TestRunner test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit2_kzg_v2)

    using TestRunners = boost::mpl::list<
            placeholder_kzg_test_runner_v2<algebra::curves::mnt4_298, hash_type>,
            placeholder_kzg_test_runner_v2<algebra::curves::mnt6_298, hash_type>
    >;

    BOOST_AUTO_TEST_CASE_TEMPLATE(kzg_v2_test, TestRunner, TestRunners) {
        using field_type = typename TestRunner::field_type;
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto pi0 = random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()();
        auto circuit = circuit_test_t<field_type>(
                pi0,
                random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
                random_test_initializer.generic_random_engine
        );
        TestRunner test_runner(circuit);
        BOOST_CHECK(test_runner.run_test());
    }

BOOST_AUTO_TEST_SUITE_END()
