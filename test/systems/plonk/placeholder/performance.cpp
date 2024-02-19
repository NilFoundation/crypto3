//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2023 Martun Karapetyan <martun@nil.foundation>
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

#include "nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp"
#define BOOST_TEST_MODULE placeholder_performance_test

// NOTE: Most of the following code is taken from main.cpp of transpiler.

// Do it forsefully because it is a main purpose of this test.
#define ZK_PLACEHOLDER_PROFILING_ENABLED

#include <string>
#include <random>
#include <iostream>
#include <fstream>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

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

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/marshalling/zk/types/plonk/variable.hpp>
#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/flat_expression.hpp>
#include <nil/crypto3/marshalling/math/types/expression.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/copy_constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

class placeholder_performance_test_base {
    public:
    static std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
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

    template<typename fri_type, typename FieldType>
    typename fri_type::params_type create_fri_params(
        std::size_t degree_log, const int max_step = 1, std::size_t expand_factor = 7) {
    std::size_t r = degree_log - 1;

    return typename fri_type::params_type(
        (1 << degree_log) - 1, // max_degree
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r),
        generate_random_step_list(r, max_step),
        expand_factor
    );
}

};

template<std::size_t lambda>
class placeholder_performance_test : public placeholder_performance_test_base {
public:
    // using curve_type = algebra::curves::bls12<381>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    using hash_type = hashes::keccak_1600<256>;

    static constexpr std::size_t m = 2;

    // These values were taken from the transpiler code.
    static constexpr std::size_t WitnessColumns = 15;
    static constexpr std::size_t PublicInputColumns = 1;
    static constexpr std::size_t ConstantColumns = 5;
    static constexpr std::size_t SelectorColumns = 35;
    static constexpr std::size_t TotalColumns = WitnessColumns + PublicInputColumns + ConstantColumns + SelectorColumns;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        hash_type, hash_type, lambda, m, true /* use grinding */>;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using circuit_params_type = placeholder_circuit_params<field_type>;
    using lpc_placeholder_params_type = zk::snark::placeholder_params<circuit_params_type, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params_type>;

    using constraint_system_type = zk::snark::plonk_constraint_system<field_type>;
    using table_description_type = zk::snark::plonk_table_description<field_type>;

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using column_type = zk::snark::plonk_column<field_type>;

    using circuit_marshalling_type = marshalling::types::plonk_constraint_system<TTypeBase, constraint_system_type>;
    using assignment_table_type = zk::snark::plonk_table<field_type, column_type>;
    using assignment_table_marshalling_type = marshalling::types::plonk_assignment_table<TTypeBase, assignment_table_type>;

    using columns_rotations_type = std::vector<std::set<int>>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<hash_type>;

    void run_placeholder_perf_test(std::string test_name, std::string circuit_file_path,
            std::string assignment_table_file_path) {

        std::cout << std::endl << "Running '" << test_name << "' performance test" <<  std::endl;

        load_circuit(circuit_file_path);
        load_assignment_table(assignment_table_file_path);

        compute_columns_rotations();

        std::cout << "rows_amount = " << table_description.rows_amount << std::endl;

        std::size_t table_rows_log = std::ceil(std::log2(table_description.rows_amount));
        typename lpc_type::fri_type::params_type fri_params =
            create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);

        std::size_t permutation_size = table_description.witness_columns +
            table_description.public_input_columns + table_description.constant_columns;

        std::cout << "table_rows_log = " << table_rows_log << std::endl;

        lpc_scheme_type lpc_scheme(fri_params);
        transcript_type lpc_transcript;

        auto lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.public_table(), table_description, lpc_scheme,
                permutation_size
            );
        std::cout << "max_gates_degree = " << lpc_preprocessed_public_data.common_data.max_gates_degree << std::endl;

        auto lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.private_table(), table_description
            );

        auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
            lpc_preprocessed_public_data, lpc_preprocessed_private_data, table_description,
            constraint_system, lpc_scheme
        );

        bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
            lpc_preprocessed_public_data, lpc_proof, table_description, constraint_system, lpc_scheme
        );

        BOOST_CHECK(verifier_res);
        std::cout << "===========================================================" << std::endl;
    }

private:

    bool read_buffer_from_file(std::istream &ifile, std::vector<std::uint8_t> &v) {
        char c;
        char c1;
        uint8_t b;

        ifile >> c;
        if (c != '0')
            return false;

        ifile >> c;
        if (c != 'x')
            return false;
        while (ifile) {
            std::string str = "";
            ifile >> c >> c1;
            if (!isxdigit(c) || !isxdigit(c1))
                return false;

            str += c;
            str += c1;
            b = stoi(str, 0, 0x10);
            v.push_back(b);
        }
        return true;
    }

    void load_assignment_table(std::string assignment_file_path) {

        std::ifstream iassignment;
        iassignment.open(assignment_file_path);
        BOOST_CHECK(iassignment);

        std::vector<std::uint8_t> v;
        BOOST_CHECK(read_buffer_from_file(iassignment, v));

        iassignment.close();

        assignment_table_marshalling_type marshalled_data;
        auto read_iter = v.begin();
        auto status = marshalled_data.read(read_iter, v.size());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        std::tie(table_description, assignments) =
            marshalling::types::make_assignment_table<Endianness, assignment_table_type>(marshalled_data);
    }

    void load_circuit(std::string circuit_file_path) {
        std::ifstream ifile;
        ifile.open(circuit_file_path);
        BOOST_CHECK(ifile.is_open());

        std::vector<std::uint8_t> v;
        BOOST_CHECK(read_buffer_from_file(ifile, v));
        ifile.close();

        circuit_marshalling_type marshalled_data;
        auto read_iter = v.begin();
        auto status = marshalled_data.read(read_iter, v.size());
        BOOST_ASSERT(status == nil::marshalling::status_type::success);
        constraint_system = marshalling::types::make_plonk_constraint_system<
            Endianness, constraint_system_type>(marshalled_data);
    }

    void compute_columns_rotations() {
        using variable_type = typename zk::snark::plonk_variable<typename constraint_system_type::field_type::value_type>;

        for (const auto& gate: constraint_system.gates()) {
            for (const auto& constraint: gate.constraints) {
                math::expression_for_each_variable_visitor<variable_type> visitor(
                    [this](const variable_type& var) {
                        if (var.relative) {
                            std::size_t column_index = this->table_description.global_index(var);
                            this->columns_rotations[column_index].insert(var.rotation);
                        }
                    });
                visitor.visit(constraint);
            }
        }

        // TODO update for lookups
        //for (const auto& gate: constraint_system.lookup_gates()) {
        //    for (const auto& constraint: gate.constraints) {
        //        math::expression_for_each_variable_visitor<variable_type> visitor(
        //            const auto& var = lookup_input.vars[0];
        //            if (var.relative) {
        //                std::size_t column_index = table_description.global_index(var);
        //                columns_rotations[column_index].insert(var.rotation);
        //            }
        //        }
        //    }
        //}

        for (std::size_t i = 0; i < TotalColumns; i++) {
            columns_rotations[i].insert(0);
        }
    }

    constraint_system_type constraint_system;
    table_description_type table_description = table_description_type(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    assignment_table_type assignments = assignment_table_type(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    columns_rotations_type columns_rotations = columns_rotations_type(TotalColumns);
};

BOOST_AUTO_TEST_SUITE(placeholder_transpiler_suite, *boost::unit_test::disabled())

BOOST_FIXTURE_TEST_CASE(placeholder_merkle_tree_poseidon_test, placeholder_performance_test<2>) {

    run_placeholder_perf_test(
        "Merkle tree poseidon performance test",
        "../libs/zk/test/systems/plonk/placeholder/data/merkle_tree_poseidon/merkle_tree_posseidon_circuit.crct",
        "../libs/zk/test/systems/plonk/placeholder/data/merkle_tree_poseidon/merkle_tree_posseidon_assignment.tbl"
    );
}

BOOST_FIXTURE_TEST_CASE(placeholder_many_hashes_test, placeholder_performance_test<2>) {
    run_placeholder_perf_test(
        "Many hashes performance test",
        "../libs/zk/test/systems/plonk/placeholder/data/many_hashes/many_hashes_circuit.crct",
        "../libs/zk/test/systems/plonk/placeholder/data/many_hashes/many_hashes_assignment.tbl"
    );
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_prover_test_suite)

// using curve_type = algebra::curves::bls12<381>;
using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;

struct placeholder_fibonacci_params {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::sha2<256>;

    constexpr static const std::size_t witness_columns = 1;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 1;

    constexpr static const std::size_t lambda = 1;
    constexpr static const std::size_t m = 2;
};

using circuit_fib_params = placeholder_circuit_params<field_type>;

constexpr static const std::size_t table_columns =
    placeholder_fibonacci_params::witness_columns + placeholder_fibonacci_params::public_input_columns;

using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_fibonacci_params::transcript_hash_type>;

using lpc_params_type = commitments::list_polynomial_commitment_params<
    typename placeholder_fibonacci_params::merkle_hash_type,
    typename placeholder_fibonacci_params::transcript_hash_type,
    placeholder_fibonacci_params::lambda,
    placeholder_fibonacci_params::m
>;

using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_fib_params, lpc_scheme_type>;
using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

const std::size_t rows_amount = 987;

BOOST_FIXTURE_TEST_CASE(placeholder_large_fibonacci_test, placeholder_performance_test_base) {
    auto circuit = circuit_test_fib<field_type, rows_amount>();

    plonk_table_description<field_type> desc(
        placeholder_fibonacci_params::witness_columns,
        placeholder_fibonacci_params::public_input_columns,
        placeholder_fibonacci_params::constant_columns,
        placeholder_fibonacci_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename lpc_type::fri_type::params_type fri_params =
        create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1};

    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
        constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc,
        constraint_system, lpc_scheme
    );

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_proof, desc, constraint_system, lpc_scheme
    );
    BOOST_CHECK(verifier_res);
    std::cout << "==========================================================="<<std::endl;
}

BOOST_AUTO_TEST_SUITE_END()


