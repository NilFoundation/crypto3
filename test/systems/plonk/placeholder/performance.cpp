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

#define BOOST_TEST_MODULE placeholder_test

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

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
// #include <nil/crypto3/zk/snark/systems/plonk/placeholder/gates_argument.hpp>
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
#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/copy_constraint.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/gate.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

#include "circuits.hpp"

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

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log, const int max_step = 1) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    constexpr std::size_t expand_factor = 4;

    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.max_degree = (1 << degree_log) - 1;
    params.step_list = generate_random_step_list(r, max_step);

    return params;
}

BOOST_AUTO_TEST_SUITE(placeholder_prover_test_suite)

// using curve_type = algebra::curves::bls12<381>;
using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;

// lpc params
constexpr static const std::size_t m = 2;

constexpr static const std::size_t table_rows_log = 4;
constexpr static const std::size_t table_rows = 1 << table_rows_log;
constexpr static const std::size_t permutation_size = 4;
constexpr static const std::size_t usable_rows = (1 << table_rows_log) - 3;

struct placeholder_fibonacci_params {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = nil::crypto3::hashes::sha2<256>;

    constexpr static const std::size_t witness_columns = 1;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 1;

    using arithmetization_params =
        plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

    constexpr static const std::size_t lambda = 1;
    constexpr static const std::size_t r = 4;
    constexpr static const std::size_t m = 2;
};
using circuit_fib_params = placeholder_circuit_params<
    field_type, 
    typename placeholder_fibonacci_params::arithmetization_params
>;

constexpr static const std::size_t table_columns =
    placeholder_fibonacci_params::witness_columns + placeholder_fibonacci_params::public_input_columns;

using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_fibonacci_params::transcript_hash_type>;
using lpc_params_type = commitments::list_polynomial_commitment_params<        
    typename placeholder_fibonacci_params::merkle_hash_type,
    typename placeholder_fibonacci_params::transcript_hash_type, 
    placeholder_fibonacci_params::lambda, 
    placeholder_fibonacci_params::r,
    placeholder_fibonacci_params::m
>;

using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_fib_params, lpc_scheme_type>;
using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

/*
BOOST_AUTO_TEST_CASE(small_merkle_tree_test1) {
    std::cout << std::endl << "Small merkle tree test" << std::endl;

    constexpr std::size_t rows_log = 2;
    constexpr std::size_t expand_factor = 1;
    constexpr std::size_t r = rows_log - 1;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(rows_log + expand_factor, r);

    typedef commitments::lpc<
        FieldType, 
        circuit_fib_params::batched_commitment_params_type
    > lpc_type;

    std::vector<math::polynomial_dfs<typename FieldType::value_type>> batch1 = {};
    math::polynomial_dfs<typename FieldType::value_type> poly(3, {1,1,2,3, 5, 8, 13, 21});
    batch1.push_back(poly);

    std::size_t domain_size = D[0]->size();
    std::size_t leafs_number = domain_size / 2;
    std::vector<std::vector<std::uint8_t>> y_data(
            leafs_number,
            std::vector<std::uint8_t>(2 * lpc_type::field_element_type::length()
    ));
    for (std::size_t x_index = 0; x_index < leafs_number; x_index++) {
        auto write_iter = y_data[x_index].begin();
        typename lpc_type::field_element_type y_val0(poly[x_index * 2]);
        y_val0.write(write_iter, lpc_type::field_element_type::length());
        typename lpc_type::field_element_type y_val1(poly[x_index * 2 + 1]);
        y_val1.write(write_iter, lpc_type::field_element_type::length());
    }
    auto tree = containers::make_merkle_tree<typename lpc_type::merkle_tree_hash_type, lpc_type::m>(y_data.begin(), y_data.end());
    std::cout << "Simple tree root = "<< tree.root() << std::endl;

    auto proof = typename lpc_type::merkle_proof_type(tree, 0);
    BOOST_CHECK(proof.validate(y_data[0]));
}
*/

BOOST_AUTO_TEST_CASE(placeholder_large_fibonacci_test) {
    constexpr std::size_t rows_log = 10;
    std::cout << std::endl << "Fibonacci test rows_log = "<< rows_log << std::endl;

    auto circuit = circuit_test_fib<field_type, rows_log>();
    typename lpc_type::fri_type::params_type fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(rows_log);

    plonk_table_description<field_type, typename circuit_fib_params::arithmetization_params> desc;

    desc.rows_amount = 1 << rows_log;
    desc.usable_rows_amount = desc.rows_amount - 3;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1};

    lpc_scheme_type lpc_scheme(fri_params);
    transcript_type lpc_transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size(), lpc_transcript
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, assignments, lpc_scheme, lpc_transcript
    );

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_proof, constraint_system, lpc_scheme, lpc_transcript
    );
    BOOST_CHECK(verifier_res);
    std::cout << "==========================================================="<<std::endl;
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_transpiler_suite)
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 5;
    constexpr std::size_t ConstantColumns = 5;
    constexpr std::size_t SelectorColumns = 30;

    using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ConstraintSystemType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using TableDescriptionType = nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams>;

    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using value_marshalling_type = nil::crypto3::marshalling::types::plonk_constraint_system<TTypeBase, ConstraintSystemType>;
    using columns_rotations_type = std::array<std::set<int>, ArithmetizationParams::total_columns>;
    using ColumnType = nil::crypto3::zk::snark::plonk_column<BlueprintFieldType>;
    using TableAssignmentType = nil::crypto3::zk::snark::plonk_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
        
    const std::size_t Lambda = 2;
    using Hash = nil::crypto3::hashes::keccak_1600<256>;
    using circuit_params_type = placeholder_circuit_params<BlueprintFieldType, ArithmetizationParams>;

    // r -- ?
    using lpc_params_type = commitments::list_polynomial_commitment_params<        
        Hash, Hash, Lambda, 2, 2
    >;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<Hash>;

    using lpc_type = commitments::list_polynomial_commitment<BlueprintFieldType, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params_type, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<BlueprintFieldType, circuit_params_type>;


columns_rotations_type load_columns_rotations(
    const ConstraintSystemType &constraint_system,  const TableDescriptionType &table_description
) {
    using variable_type = typename nil::crypto3::zk::snark::plonk_variable<typename ConstraintSystemType::field_type::value_type>;

    columns_rotations_type result;
    for (const auto& gate: constraint_system.gates()) {
        for (const auto& constraint: gate.constraints) {
            nil::crypto3::math::expression_for_each_variable_visitor<variable_type> visitor(
                [&table_description, &result](const variable_type& var) {
                    if (var.relative) {
                        std::size_t column_index = table_description.global_index(var);
                        result[column_index].insert(var.rotation);
                    }
                });
            visitor.visit(constraint);
        }
    }
    /*
    // TODO update for lookups
    for (const auto& gate: constraint_system.lookup_gates()) {
        for (const auto& constraint: gate.constraints) {
            nil::crypto3::math::expression_for_each_variable_visitor<variable_type> visitor(
                const auto& var = lookup_input.vars[0];
                if (var.relative) {
                    std::size_t column_index = table_description.global_index(var);
                    result[column_index].insert(var.rotation);
                }
            }
        }
    }
    */
    for (std::size_t i = 0; i < ArithmetizationParams::total_columns; i++) {
        result[i].insert(0);
    }

    return result;
}

bool read_buffer_from_file(std::ifstream &ifile, std::vector<std::uint8_t> &v) {
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

std::tuple<std::size_t, std::size_t,
           nil::crypto3::zk::snark::plonk_table<BlueprintFieldType, ArithmetizationParams, ColumnType>>
    load_assignment_table(std::istream &istr) {
    using PrivateTableType =
        nil::crypto3::zk::snark::plonk_private_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
    using PublicTableType =
        nil::crypto3::zk::snark::plonk_public_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
    using TableAssignmentType =
        nil::crypto3::zk::snark::plonk_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
    std::size_t usable_rows;
    std::size_t rows_amount;

    typename PrivateTableType::witnesses_container_type witness;
    typename PublicTableType::public_input_container_type public_input;
    typename PublicTableType::constant_container_type constant;
    typename PublicTableType::selector_container_type selector;

    istr >> usable_rows;
    istr >> rows_amount;

    for (size_t i = 0; i < witness.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
        ColumnType column;
        typename BlueprintFieldType::integral_type num;
        for (size_t j = 0; j < rows_amount; j++) {
            istr >> num;
            column.push_back(typename BlueprintFieldType::value_type(num));
        }
        witness[i] = column;
    }

    for (size_t i = 0; i < public_input.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
        ColumnType column;
        typename BlueprintFieldType::integral_type num;
        for (size_t j = 0; j < rows_amount; j++) {
            istr >> num;
            column.push_back(typename BlueprintFieldType::value_type(num));
        }
        public_input[i] = column;
    }

    for (size_t i = 0; i < constant.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
        ColumnType column;
        typename BlueprintFieldType::integral_type num;
        for (size_t j = 0; j < rows_amount; j++) {
            istr >> num;
            column.push_back(typename BlueprintFieldType::value_type(num));
        }
        constant[i] = column;
    }
    for (size_t i = 0; i < selector.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
        ColumnType column;
        typename BlueprintFieldType::integral_type num;
        for (size_t j = 0; j < rows_amount; j++) {
            istr >> num;
            column.push_back(typename BlueprintFieldType::value_type(num));
        }
        selector[i] = column;
    }
    return std::make_tuple(
        usable_rows, rows_amount,
        TableAssignmentType(PrivateTableType(witness), PublicTableType(public_input, constant, selector)));
}

void load_circuit_and_table(ConstraintSystemType &circuit, TableAssignmentType &table, TableDescriptionType &table_description, std::string input_folder_path){
    std::string ifile_path;
    std::string iassignment_path;

    ifile_path = input_folder_path + "/circuit.crct";
    iassignment_path = input_folder_path + "/assignment.tbl";

    std::ifstream ifile;
    ifile.open(ifile_path);
    if (!ifile.is_open()) {
        std::cout << "Cannot find input file " << ifile_path << std::endl;
        BOOST_ASSERT(false);
    }
    std::vector<std::uint8_t> v;
    if (!read_buffer_from_file(ifile, v)) {
        std::cout << "Cannot parse input file " << ifile_path << std::endl;
        BOOST_ASSERT(false);
    }
    ifile.close();

    value_marshalling_type marshalled_data;
    auto read_iter = v.begin();
    auto status = marshalled_data.read(read_iter, v.size());
    circuit = nil::crypto3::marshalling::types::make_plonk_constraint_system<ConstraintSystemType, Endianness>(
            marshalled_data);

    std::ifstream iassignment;
    iassignment.open(iassignment_path);
    if (!iassignment) {
        std::cout << "Cannot open " << iassignment_path << std::endl;
        BOOST_ASSERT(false);
    }

    std::tie(table_description.usable_rows_amount, table_description.rows_amount, table) =
        load_assignment_table(iassignment);
    iassignment.close();
}

BOOST_AUTO_TEST_CASE(placeholder_merkle_tree_poseidon_test) {
    std::cout << std::endl << "Merkle tree poseidon performance test" <<  std::endl;

    ConstraintSystemType constraint_system;
    TableAssignmentType assignments;
    TableDescriptionType desc;

    load_circuit_and_table(constraint_system, assignments, desc, "../libs/zk/test/systems/plonk/placeholder/data/merkle_tree_poseidon");
    auto columns_rotations = load_columns_rotations(constraint_system, desc);

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));
    typename lpc_type::fri_type::params_type fri_params = create_fri_params<typename lpc_type::fri_type, BlueprintFieldType>(table_rows_log);
    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;
    std::cout << "table_rows_log = " << table_rows_log << std::endl;

    lpc_scheme_type lpc_scheme(fri_params);
    transcript_type lpc_transcript;

    typename placeholder_public_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, permutation_size, lpc_transcript
        );
    std::cout << "max_gates_degree = " << lpc_preprocessed_public_data.common_data.max_gates_degree << std::endl;

    typename placeholder_private_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<BlueprintFieldType, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, assignments, lpc_scheme, lpc_transcript
    );

    bool verifier_res = placeholder_verifier<BlueprintFieldType, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_proof, constraint_system, lpc_scheme, lpc_transcript
    );
    BOOST_CHECK(verifier_res);
    std::cout << "==========================================================="<<std::endl;
}

BOOST_AUTO_TEST_CASE(placeholder_many_hashes_test) {
    std::cout << std::endl << "Many_hashes performance test" <<  std::endl;

    ConstraintSystemType constraint_system;
    TableAssignmentType assignments;
    TableDescriptionType desc;

    load_circuit_and_table(constraint_system, assignments, desc, "../libs/zk/test/systems/plonk/placeholder/data/many_hashes");
    auto columns_rotations = load_columns_rotations(constraint_system, desc);

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));
    typename lpc_type::fri_type::params_type fri_params = create_fri_params<typename lpc_type::fri_type, BlueprintFieldType>(table_rows_log);
    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;
    std::cout << "table_rows_log = " << table_rows_log << std::endl;

    lpc_scheme_type lpc_scheme(fri_params);
    transcript_type lpc_transcript;

    typename placeholder_public_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, permutation_size, lpc_transcript
        );
    std::cout << "max_gates_degree = " << lpc_preprocessed_public_data.common_data.max_gates_degree << std::endl;

    typename placeholder_private_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<BlueprintFieldType, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<BlueprintFieldType, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, assignments, lpc_scheme, lpc_transcript
    );

    bool verifier_res = placeholder_verifier<BlueprintFieldType, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_proof, constraint_system, lpc_scheme, lpc_transcript
    );
    BOOST_CHECK(verifier_res);
    std::cout << "==========================================================="<<std::endl;
}
BOOST_AUTO_TEST_SUITE_END()
