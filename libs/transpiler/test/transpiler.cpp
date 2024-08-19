//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#define BOOST_TEST_MODULE transpiler_test

#include <string>
#include <random>
#include <regex>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/proof_of_work.hpp>
#include <nil/crypto3/zk/commitments/batched_commitment.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/transpiler/evm_verifier_gen.hpp>
#include <nil/blueprint/transpiler/recursive_verifier_generator.hpp>

#include "./detail/circuits.hpp"

using namespace nil;
using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

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

// *******************************************************************************
// * Randomness setup
// *******************************************************************************/
using dist_type = std::uniform_int_distribution<int>;
std::size_t test_global_seed = 0;
boost::random::mt11213b test_global_rnd_engine;
template<typename FieldType>
nil::crypto3::random::algebraic_engine<FieldType> test_global_alg_rnd_engine;

struct test_initializer {
    // Enumerate all fields used in tests;
    using field1_type = algebra::curves::pallas::base_field_type;
    using field2_type = algebra::curves::bls12<381>::scalar_field_type;
    test_initializer() {
        test_global_seed = 0;

        for (std::size_t i = 0; i < boost::unit_test::framework::master_test_suite().argc - 1; i++) {
            if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--seed") {
                if (std::string(boost::unit_test::framework::master_test_suite().argv[i + 1]) == "random") {
                    std::random_device rd;
                    test_global_seed = rd();
                    std::cout << "Random seed = " << test_global_seed << std::endl;
                    break;
                }
                if (std::regex_match(boost::unit_test::framework::master_test_suite().argv[i + 1],
                                     std::regex(("((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?")))) {
                    test_global_seed = atoi(boost::unit_test::framework::master_test_suite().argv[i + 1]);
                    break;
                }
            }
        }

        BOOST_TEST_MESSAGE("test_global_seed = " << test_global_seed);
        test_global_rnd_engine = boost::random::mt11213b(test_global_seed);
        test_global_alg_rnd_engine<field1_type> = nil::crypto3::random::algebraic_engine<field1_type>(test_global_seed);
        test_global_alg_rnd_engine<field2_type> = nil::crypto3::random::algebraic_engine<field2_type>(test_global_seed);
    }

    void setup() {
    }

    void teardown() {
    }

    ~test_initializer() {
    }
};

BOOST_AUTO_TEST_SUITE(placeholder_circuit1)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    using merkle_hash_type = hashes::keccak_1600<256>;
    using transcript_hash_type = hashes::keccak_1600<256>;

    struct placeholder_test_params {
        constexpr static const std::size_t witness_columns = witness_columns_1;
        constexpr static const std::size_t public_input_columns = public_columns_1;
        constexpr static const std::size_t constant_columns = constant_columns_1;
        constexpr static const std::size_t selector_columns = selector_columns_1;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };
    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    auto circuit = circuit_test_1<field_type>(test_global_alg_rnd_engine<field_type>);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, false
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );

    auto printer = nil::blueprint::evm_verifier_printer<lpc_placeholder_params_type>(
        constraint_system,
        lpc_preprocessed_public_data.common_data,
        "circuit1",
        26, // gates library size threshold
        60, // lookups library size threshold
        13, // gates inline size threshold
        15 // lookups inline size threshold
    );
    printer.print();
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit2)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = 3;
        constexpr static const std::size_t public_input_columns = 1;
        constexpr static const std::size_t constant_columns = 0;
        constexpr static const std::size_t selector_columns = 2;

        constexpr static const std::size_t lambda = 1;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<
        field_type
    >;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_t_params>;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    auto pi0 = test_global_alg_rnd_engine<field_type>();
    auto circuit = circuit_test_t<field_type>(pi0, test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    bool verifier_res;

    // LPC commitment scheme
    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );
    auto printer = nil::blueprint::evm_verifier_printer<lpc_placeholder_params_type>(
        constraint_system,
        lpc_preprocessed_public_data.common_data,
        "circuit2",
        26, // gates library size threshold
        60, // lookups library size threshold
        13, // gates inline size threshold
        15 // lookups inline size threshold
    );
    printer.print();
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit3)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_3;
        constexpr static const std::size_t public_input_columns = public_columns_3;
        constexpr static const std::size_t constant_columns = constant_columns_3;
        constexpr static const std::size_t selector_columns = selector_columns_3;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    auto circuit = circuit_test_3<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );
    auto printer = nil::blueprint::evm_verifier_printer<lpc_placeholder_params_type>(
        constraint_system,
        preprocessed_public_data.common_data,
        "circuit3",
        26, // gates library size threshold
        60, // lookups library size threshold
        13, // gates inline size threshold
        15 // lookups inline size threshold
    );
    printer.print();
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit4)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_4;
        constexpr static const std::size_t public_input_columns = public_columns_4;
        constexpr static const std::size_t constant_columns = constant_columns_4;
        constexpr static const std::size_t selector_columns = selector_columns_4;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    auto circuit = circuit_test_4<field_type>(test_global_alg_rnd_engine<field_type>);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );
    auto printer = nil::blueprint::evm_verifier_printer<lpc_placeholder_params_type>(
        constraint_system,
        preprocessed_public_data.common_data,
        "circuit4",
        26, // gates library size threshold
        60, // lookups library size threshold
        13, // gates inline size threshold
        15 // lookups inline size threshold
    );
    printer.print();
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit5)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t usable_rows = 5;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_5;
        constexpr static const std::size_t public_input_columns = public_columns_5;
        constexpr static const std::size_t constant_columns = constant_columns_5;
        constexpr static const std::size_t selector_columns = selector_columns_5;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    auto circuit = circuit_test_5<field_type>(test_global_alg_rnd_engine<field_type>);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 10
        );
    auto printer = nil::blueprint::evm_verifier_printer<lpc_placeholder_params_type>(
        constraint_system,
        preprocessed_public_data.common_data,
        "circuit5_chunk10",
        26, // gates library size threshold
        60, // lookups library size threshold
        13, // gates inline size threshold
        15 // lookups inline size threshold
    );
    printer.print();
}

BOOST_FIXTURE_TEST_CASE(transpiler_test100, test_initializer) {
    auto circuit = circuit_test_5<field_type>(test_global_alg_rnd_engine<field_type>);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 100
        );
    auto printer = nil::blueprint::evm_verifier_printer<lpc_placeholder_params_type>(
        constraint_system,
        preprocessed_public_data.common_data,
        "circuit5_chunk100",
        26, // gates library size threshold
        60, // lookups library size threshold
        13, // gates inline size threshold
        15 // lookups inline size threshold
    );
    printer.print();
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit6)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_6;
        constexpr static const std::size_t public_input_columns = public_columns_6;
        constexpr static const std::size_t constant_columns = constant_columns_6;
        constexpr static const std::size_t selector_columns = selector_columns_6;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    auto circuit = circuit_test_6<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );

    auto printer = nil::blueprint::evm_verifier_printer<lpc_placeholder_params_type>(
        constraint_system,
        preprocessed_public_data.common_data,
        "circuit6",
        26, // gates library size threshold
        60, // lookups library size threshold
        13, // gates inline size threshold
        15 // lookups inline size threshold
    );
    printer.print();
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit7)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t witness_columns = witness_columns_7;
        constexpr static const std::size_t public_input_columns = public_columns_7;
        constexpr static const std::size_t constant_columns = constant_columns_7;
        constexpr static const std::size_t selector_columns = selector_columns_7;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    auto circuit = circuit_test_7<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    transcript_type transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );

    auto printer = nil::blueprint::evm_verifier_printer<lpc_placeholder_params_type>(
        constraint_system,
        preprocessed_public_data.common_data,
        "circuit7",
        26, // gates library size threshold
        60, // lookups library size threshold
        13, // gates inline size threshold
        15  // lookups inline size threshold
    );
    printer.print();
}

// TODO implement for EVM
/*
BOOST_FIXTURE_TEST_CASE(transpiler_test10, test_initializer) {
    auto circuit = circuit_test_7<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    transcript_type transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme,10
        );

    auto printer = nil::blueprint::evm_verifier_printer<lpc_placeholder_params_type>(
        constraint_system,
        preprocessed_public_data.common_data,
        "circuit7_chunk10",
        26, // gates library size threshold
        60, // lookups library size threshold
        13, // gates inline size threshold
        15  // lookups inline size threshold
    );
    printer.print();
}*/
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recursive_circuit1)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using policy = hashes::detail::mina_poseidon_policy<field_type>;
    using merkle_hash_type = hashes::poseidon<policy>;
    using transcript_hash_type = hashes::poseidon<policy>;

    struct placeholder_test_params {
        constexpr static const std::size_t witness_columns = witness_columns_1;
        constexpr static const std::size_t public_input_columns = public_columns_1;
        constexpr static const std::size_t constant_columns = constant_columns_1;
        constexpr static const std::size_t selector_columns = selector_columns_1;

        constexpr static const std::size_t lambda = 4;
        constexpr static const std::size_t m = 2;
    };
    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        merkle_hash_type,
        transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, lpc_placeholder_params_type>;
    using common_data_type = nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    std::cout << "Recursive_circuit 1" << std::endl;
    auto circuit = circuit_test_1<field_type>(test_global_alg_rnd_engine<field_type>);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );
    {
        std::string cpp_path = "./circuit1/placeholder_verifier.cpp";
        std::ofstream output_file;
        output_file.open(cpp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_recursive_verifier(
            constraint_system, preprocessed_public_data.common_data, {desc.usable_rows_amount + 1}
        );
        output_file.close();
    }

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme
    );

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data,
        proof,
        desc,
        constraint_system,
        lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    {
        std::string inp_path = "./circuit1/placeholder_verifier.inp";
        std::ofstream output_file;
        output_file.open(inp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_input(
            assignments.public_inputs(), proof,  {desc.usable_rows_amount + 1}
        );
        output_file.close();
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recursive_circuit2)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using policy = hashes::detail::mina_poseidon_policy<field_type>;
        using merkle_hash_type = hashes::poseidon<policy>;
        using transcript_hash_type = hashes::poseidon<policy>;

        constexpr static const std::size_t witness_columns = 3;
        constexpr static const std::size_t public_input_columns = 1;
        constexpr static const std::size_t constant_columns = 0;
        constexpr static const std::size_t selector_columns = 2;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<
        field_type
    >;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, lpc_placeholder_params_type>;
    using common_data_type = nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    std::cout << "Recursive_circuit 2" << std::endl;
    auto pi0 = test_global_alg_rnd_engine<field_type>();
    auto circuit = circuit_test_t<field_type>(pi0, test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    // LPC commitment scheme
    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );
    {
        std::string cpp_path =  "./circuit2/placeholder_verifier.cpp";
        std::ofstream output_file;
        output_file.open(cpp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_recursive_verifier(
            constraint_system, preprocessed_public_data.common_data, {3}
        );
        output_file.close();
    }

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data,
        proof,
        desc,
        constraint_system,
        lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    std::string inp_path = "./circuit2/placeholder_verifier.inp";
    std::ofstream output_file;
    output_file.open(inp_path);
    output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_input(
        assignments.public_inputs(), proof,  {3}
    );
    output_file.close();
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recursive_circuit3)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using policy = hashes::detail::mina_poseidon_policy<field_type>;
        using merkle_hash_type = hashes::poseidon<policy>;
        using transcript_hash_type = hashes::poseidon<policy>;

        constexpr static const std::size_t witness_columns = witness_columns_3;
        constexpr static const std::size_t public_input_columns = public_columns_3;
        constexpr static const std::size_t constant_columns = constant_columns_3;
        constexpr static const std::size_t selector_columns = selector_columns_3;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, lpc_placeholder_params_type>;
    using common_data_type = nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    std::cout << "Recursive_circuit 3" << std::endl;
    auto circuit = circuit_test_3<field_type>();

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );

    std::string cpp_path = "./circuit3/placeholder_verifier.cpp";
    std::ofstream output_file;
    output_file.open(cpp_path);
    output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_recursive_verifier(
        constraint_system, preprocessed_public_data.common_data, std::vector<std::size_t>()
    );
    output_file.close();

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data,
        proof,
        desc,
        constraint_system,
        lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    {
        std::string inp_path = "./circuit3/placeholder_verifier.inp";
        std::ofstream output_file;
        output_file.open(inp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_input(
            assignments.public_inputs(), proof, std::vector<std::size_t>()
        );
        output_file.close();
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recursive_circuit4)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using policy = hashes::detail::mina_poseidon_policy<field_type>;
        using merkle_hash_type = hashes::poseidon<policy>;
        using transcript_hash_type = hashes::poseidon<policy>;

        constexpr static const std::size_t witness_columns = witness_columns_4;
        constexpr static const std::size_t public_input_columns = public_columns_4;
        constexpr static const std::size_t constant_columns = constant_columns_4;
        constexpr static const std::size_t selector_columns = selector_columns_4;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, lpc_placeholder_params_type>;
    using common_data_type = nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    std::cout << "Recursive_circuit 4" << std::endl;
    auto circuit = circuit_test_4<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );
    {
        std::string cpp_path = "./circuit4/placeholder_verifier.cpp";
        std::ofstream output_file;
        output_file.open(cpp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_recursive_verifier(
            constraint_system, preprocessed_public_data.common_data, std::vector<std::size_t>()
        );
        output_file.close();
    }

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data,
        proof,
        desc,
        constraint_system,
        lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    {
        std::string inp_path = "./circuit4/placeholder_verifier.inp";
        std::ofstream output_file;
        output_file.open(inp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_input(
            assignments.public_inputs(), proof, std::vector<std::size_t>()
        );
        output_file.close();
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recursive_circuit5_chunk10)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using policy = hashes::detail::mina_poseidon_policy<field_type>;
        using merkle_hash_type = hashes::poseidon<policy>;
        using transcript_hash_type = hashes::poseidon<policy>;

        constexpr static const std::size_t witness_columns = witness_columns_5;
        constexpr static const std::size_t public_input_columns = public_columns_5;
        constexpr static const std::size_t constant_columns = constant_columns_5;
        constexpr static const std::size_t selector_columns = selector_columns_5;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, lpc_placeholder_params_type>;
    using common_data_type = nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    std::cout << "Recursive_circuit 5" << std::endl;
    auto circuit = circuit_test_5<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 10
        );
    {
        std::string cpp_path = "./circuit5_chunk10/placeholder_verifier.cpp";
        std::ofstream output_file;
        output_file.open(cpp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_recursive_verifier(
            constraint_system, preprocessed_public_data.common_data, {135}
        );
        output_file.close();
    }

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data,
        proof,
        desc,
        constraint_system,
        lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    {
        std::string inp_path = "./circuit5_chunk10/placeholder_verifier.inp";
        std::ofstream output_file;
        output_file.open(inp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_input(
            assignments.public_inputs(), proof, {135}
        );
        output_file.close();
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recursive_circuit5_chunk100)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using policy = hashes::detail::mina_poseidon_policy<field_type>;
        using merkle_hash_type = hashes::poseidon<policy>;
        using transcript_hash_type = hashes::poseidon<policy>;

        constexpr static const std::size_t witness_columns = witness_columns_5;
        constexpr static const std::size_t public_input_columns = public_columns_5;
        constexpr static const std::size_t constant_columns = constant_columns_5;
        constexpr static const std::size_t selector_columns = selector_columns_5;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, lpc_placeholder_params_type>;
    using common_data_type = nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    std::cout << "Recursive_circuit 5" << std::endl;
    auto circuit = circuit_test_5<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 100
        );
    {
        std::string cpp_path = "./circuit5_chunk100/placeholder_verifier.cpp";
        std::ofstream output_file;
        output_file.open(cpp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_recursive_verifier(
            constraint_system, preprocessed_public_data.common_data, {135}
        );
        output_file.close();
    }

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data,
        proof,
        desc,
        constraint_system,
        lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    {
        std::string inp_path = "./circuit5_chunk100/placeholder_verifier.inp";
        std::ofstream output_file;
        output_file.open(inp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_input(
            assignments.public_inputs(), proof, {135}
        );
        output_file.close();
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recursive_circuit6)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using policy = hashes::detail::mina_poseidon_policy<field_type>;
        using merkle_hash_type = hashes::poseidon<policy>;
        using transcript_hash_type = hashes::poseidon<policy>;

        constexpr static const std::size_t witness_columns = witness_columns_6;
        constexpr static const std::size_t public_input_columns = public_columns_6;
        constexpr static const std::size_t constant_columns = constant_columns_6;
        constexpr static const std::size_t selector_columns = selector_columns_6;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, lpc_placeholder_params_type>;
    using common_data_type = nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    std::cout << "Recursive_circuit 6" << std::endl;
    auto circuit = circuit_test_6<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme);
    {
        std::string cpp_path = "./circuit6/placeholder_verifier.cpp";
        std::ofstream output_file;
        output_file.open(cpp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_recursive_verifier(
            constraint_system, preprocessed_public_data.common_data, std::vector<std::size_t>()
        );
        output_file.close();
    }

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data,
        proof,
        desc,
        constraint_system,
        lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    {
        std::string inp_path = "./circuit6/placeholder_verifier.inp";
        std::ofstream output_file;
        output_file.open(inp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_input(
            assignments.public_inputs(), proof, std::vector<std::size_t>()
        );
        output_file.close();
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recursive_circuit7)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using policy = hashes::detail::mina_poseidon_policy<field_type>;
        using merkle_hash_type = hashes::poseidon<policy>;
        using transcript_hash_type = hashes::poseidon<policy>;

        constexpr static const std::size_t witness_columns = witness_columns_7;
        constexpr static const std::size_t public_input_columns = public_columns_7;
        constexpr static const std::size_t constant_columns = constant_columns_7;
        constexpr static const std::size_t selector_columns = selector_columns_7;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, lpc_placeholder_params_type>;
    using common_data_type = nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    std::cout << "Recursive_circuit 7" << std::endl;
    auto circuit = circuit_test_7<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);
    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    transcript_type transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );
    {
        std::string cpp_path = "./circuit7/placeholder_verifier.cpp";
        std::ofstream output_file;
        output_file.open(cpp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_recursive_verifier(
            constraint_system, preprocessed_public_data.common_data, std::vector<std::size_t>()
        );
        output_file.close();
    }

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data,
        proof,
        desc,
        constraint_system,
        lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    {
        std::string inp_path = "./circuit7/placeholder_verifier.inp";
        std::ofstream output_file;
        output_file.open(inp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_input(
            assignments.public_inputs(), proof, std::vector<std::size_t>()
        );
        output_file.close();
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(recursive_circuit7_chunk10)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using BlueprintFieldType = algebra::curves::pallas::base_field_type;
        using policy = hashes::detail::mina_poseidon_policy<field_type>;
        using merkle_hash_type = hashes::poseidon<policy>;
        using transcript_hash_type = hashes::poseidon<policy>;

        constexpr static const std::size_t witness_columns = witness_columns_7;
        constexpr static const std::size_t public_input_columns = public_columns_7;
        constexpr static const std::size_t constant_columns = constant_columns_7;
        constexpr static const std::size_t selector_columns = selector_columns_7;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;
    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, lpc_placeholder_params_type>;
    using common_data_type = nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type::common_data_type;

BOOST_FIXTURE_TEST_CASE(transpiler_test, test_initializer) {
    std::cout << "Recursive_circuit 7 chunk 10" << std::endl;
    std::filesystem::create_directory("./circuit7_chunk10");
    auto circuit = circuit_test_7<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);
    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    transcript_type transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 10
        );
    {
        std::string cpp_path = "./circuit7_chunk10/placeholder_verifier.cpp";
        std::ofstream output_file;
        output_file.open(cpp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_recursive_verifier(
            constraint_system, preprocessed_public_data.common_data, std::vector<std::size_t>()
        );
        output_file.close();
    }

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data.common_data,
        proof,
        desc,
        constraint_system,
        lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    {
        std::string inp_path = "./circuit7_chunk10/placeholder_verifier.inp";
        std::ofstream output_file;
        output_file.open(inp_path);
        output_file << nil::blueprint::recursive_verifier_generator<lpc_placeholder_params_type, proof_type, common_data_type>(desc).generate_input(
            assignments.public_inputs(), proof, std::vector<std::size_t>()
        );
        output_file.close();
    }
}
BOOST_AUTO_TEST_SUITE_END()