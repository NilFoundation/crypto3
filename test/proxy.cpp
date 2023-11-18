// Copyright (c) 2023 Aleksei Kokoshnikov <alexeikokoshnikov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_proxy_test

#include <boost/test/unit_test.hpp>
#include <boost/integer/extended_euclidean.hpp>

#include <memory>
#include <map>
#include <functional>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/blueprint/blueprint/plonk/circuit_proxy.hpp>
#include <nil/blueprint/blueprint/plonk/assignment_proxy.hpp>

using namespace nil::blueprint;

BOOST_AUTO_TEST_CASE(blueprint_circuit_proxy_gates_test) {
    using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 5;
    constexpr std::size_t SelectorColumns = 35;

    using ArithmetizationParams =
    nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    auto bp_ptr = std::make_shared<circuit<ArithmetizationType>>();
    std::vector<circuit_proxy<ArithmetizationType>> circuits;
    circuits.emplace_back(bp_ptr, 0);
    circuits.emplace_back(bp_ptr, 1);

    circuits[0].add_gate({0, {var(0, 0, true, var::column_type::witness)}});
    circuits[0].add_gate({1, {var(0, 1, true, var::column_type::witness)}});
    circuits[1].add_gate({2, {var(0, 2, true, var::column_type::witness)}});

    BOOST_ASSERT(circuits[0].get_next_selector_index() == circuits[1].get_next_selector_index());
    BOOST_ASSERT(circuits[0].get_next_selector_index() == 3);

    BOOST_ASSERT(circuits[0].num_gates() == circuits[1].num_gates());
    BOOST_ASSERT(circuits[0].num_gates() == 3);

    std::set<uint32_t> used_gates_0 = {0, 1};
    BOOST_ASSERT(circuits[0].get_used_gates() == used_gates_0);
    std::set<uint32_t> used_gates_1 = {2};
    BOOST_ASSERT(circuits[1].get_used_gates() == used_gates_1);
}

BOOST_AUTO_TEST_CASE(blueprint_circuit_proxy_lookup_gates_test) {
    using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 5;
    constexpr std::size_t SelectorColumns = 35;

    using ArithmetizationParams =
    nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    auto bp_ptr = std::make_shared<circuit<ArithmetizationType>>();
    std::vector<circuit_proxy<ArithmetizationType>> circuits;
    circuits.emplace_back(bp_ptr, 0);
    circuits.emplace_back(bp_ptr, 1);

    circuits[0].add_lookup_gate({0, {var(0, 0, true, var::column_type::constant)}});
    circuits[0].add_lookup_gate({1, {var(1, 0, true, var::column_type::constant)}});
    circuits[1].add_lookup_gate({2, {var(0, 1, true, var::column_type::constant)}});

    BOOST_ASSERT(circuits[0].get_next_selector_index() == circuits[1].get_next_selector_index());
    BOOST_ASSERT(circuits[0].get_next_selector_index() == 3);

    BOOST_ASSERT(circuits[0].num_lookup_gates() == circuits[1].num_lookup_gates());
    BOOST_ASSERT(circuits[0].num_lookup_gates() == 3);

    std::set<uint32_t> used_lookup_gates_0 = {0, 1};
    BOOST_ASSERT(circuits[0].get_used_lookup_gates() == used_lookup_gates_0);
    std::set<uint32_t> used_lookup_gates_1 = {2};
    BOOST_ASSERT(circuits[1].get_used_lookup_gates() == used_lookup_gates_1);
}

BOOST_AUTO_TEST_CASE(blueprint_circuit_proxy_copy_constraints_test) {
        using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
        constexpr std::size_t WitnessColumns = 15;
        constexpr std::size_t PublicInputColumns = 1;
        constexpr std::size_t ConstantColumns = 5;
        constexpr std::size_t SelectorColumns = 35;

        using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
        using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
        using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

        auto bp_ptr = std::make_shared<circuit<ArithmetizationType>>();
        std::vector<circuit_proxy<ArithmetizationType>> circuits;
        circuits.emplace_back(bp_ptr, 0);
        circuits.emplace_back(bp_ptr, 1);

        circuits[0].add_copy_constraint({var(0, 0, true, var::column_type::witness), var(0, -1, true, var::column_type::witness)});
        circuits[0].add_copy_constraint({var(0, 1, true, var::column_type::witness), var(0, -1, true, var::column_type::witness)});
        circuits[1].add_copy_constraint({var(0, 2, true, var::column_type::witness), var(0, -1, true, var::column_type::witness)});

        std::set<uint32_t> used_copy_constraints_0 = {0, 1};
        BOOST_ASSERT(circuits[0].get_used_copy_constraints() == used_copy_constraints_0);
        std::set<uint32_t> used_copy_constraints_1 = {2};
        BOOST_ASSERT(circuits[1].get_used_copy_constraints() == used_copy_constraints_1);
}

BOOST_AUTO_TEST_CASE(blueprint_circuit_proxy_lookup_tables_test) {
        using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
        constexpr std::size_t WitnessColumns = 15;
        constexpr std::size_t PublicInputColumns = 1;
        constexpr std::size_t ConstantColumns = 5;
        constexpr std::size_t SelectorColumns = 35;

        using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
        using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
        using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
        typedef nil::crypto3::zk::snark::plonk_lookup_table<BlueprintFieldType> lookup_table_type;

        auto bp_ptr = std::make_shared<circuit<ArithmetizationType>>();
        std::vector<circuit_proxy<ArithmetizationType>> circuits;
        circuits.emplace_back(bp_ptr, 0);
        circuits.emplace_back(bp_ptr, 1);

        const std::string lookup_tbale_name_0 = "sha256_sparse_base4/full";
        const std::string lookup_tbale_name_1 = "sha256_sparse_base4/first_column";
        const std::string lookup_tbale_name_2 = "sha256_reverse_sparse_base4/full";

        circuits[0].reserve_table(lookup_tbale_name_0);
        circuits[0].reserve_table(lookup_tbale_name_1);
        circuits[1].reserve_table(lookup_tbale_name_2);

        std::set<uint32_t> used_lookup_tables_0 = {0, 1};
        BOOST_ASSERT(circuits[0].get_used_lookup_tables() == used_lookup_tables_0);
        std::set<uint32_t> used_lookup_tables_1 = {2};
        BOOST_ASSERT(circuits[1].get_used_lookup_tables() == used_lookup_tables_1);
}

BOOST_AUTO_TEST_CASE(blueprint_assignment_proxy_selector_test) {
        using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
        constexpr std::size_t WitnessColumns = 15;
        constexpr std::size_t PublicInputColumns = 1;
        constexpr std::size_t ConstantColumns = 5;
        constexpr std::size_t SelectorColumns = 35;

        using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
        using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

        auto assignment_ptr = std::make_shared<assignment<ArithmetizationType>>();
        std::vector<assignment_proxy<ArithmetizationType>> assignments;
        assignments.emplace_back(assignment_ptr, 0);
        assignments.emplace_back(assignment_ptr, 1);

        // add selectors
        assignments[0].selector(0, 0);
        assignments[0].selector(0, 1);
        assignments[1].selector(1, 2);

        BOOST_ASSERT(assignments[0].rows_amount() == assignments[1].rows_amount());
        BOOST_ASSERT(assignments[0].rows_amount() == 3);

        BOOST_ASSERT(assignments[0].selector_column_size(0) == assignments[1].selector_column_size(0));
        BOOST_ASSERT(assignments[0].selector_column_size(0) == 2);
        BOOST_ASSERT(assignments[0].selector_column_size(1) == assignments[1].selector_column_size(1));
        BOOST_ASSERT(assignments[0].selector_column_size(1) == 3);

        std::set<uint32_t> used_rows_0 = {0, 1};
        BOOST_ASSERT(assignments[0].get_used_rows() == used_rows_0);
        std::set<uint32_t> used_rows_1 = {2};
        BOOST_ASSERT(assignments[1].get_used_rows() == used_rows_1);

        // enable selectors
        assignments[0].enable_selector(2, 3, 5, 2); // selectors in col 2 rows 3 and 5
        assignments[1].enable_selector(3, 6, 7); // selectors in col 3 rows 6 and 7

        BOOST_ASSERT(assignments[0].rows_amount() == assignments[1].rows_amount());
        BOOST_ASSERT(assignments[0].rows_amount() == 8);

        BOOST_ASSERT(assignments[0].selector_column_size(2) == assignments[1].selector_column_size(2));
        BOOST_ASSERT(assignments[0].selector_column_size(2) == 6);
        BOOST_ASSERT(assignments[0].selector_column_size(3) == assignments[1].selector_column_size(3));
        BOOST_ASSERT(assignments[0].selector_column_size(3) == 8);

        used_rows_0 = {0, 1, 3, 5};
        BOOST_ASSERT(assignments[0].get_used_rows() == used_rows_0);
        used_rows_1 = {2, 6, 7};
        BOOST_ASSERT(assignments[1].get_used_rows() == used_rows_1);
}

BOOST_AUTO_TEST_CASE(blueprint_assignment_proxy_shared_test) {
        using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
        constexpr std::size_t WitnessColumns = 15;
        constexpr std::size_t PublicInputColumns = 1;
        constexpr std::size_t ConstantColumns = 5;
        constexpr std::size_t SelectorColumns = 35;

        using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
        using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

        auto assignment_ptr = std::make_shared<assignment<ArithmetizationType>>();
        std::vector<assignment_proxy<ArithmetizationType>> assignments;
        assignments.emplace_back(assignment_ptr, 0);
        assignments.emplace_back(assignment_ptr, 1);

        // add shareds
        assignments[0].shared(0, 0);
        assignments[0].shared(0, 1);
        assignments[1].shared(0, 2);

        BOOST_ASSERT(assignments[0].shared_column_size(0) == assignments[1].shared_column_size(0));
        BOOST_ASSERT(assignments[0].shared_column_size(0) == 3);

        std::set<uint32_t> used_rows_0 = {};
        BOOST_ASSERT(assignments[0].get_used_rows() == used_rows_0);
        std::set<uint32_t> used_rows_1 = {};
        BOOST_ASSERT(assignments[1].get_used_rows() == used_rows_1);
}

BOOST_AUTO_TEST_CASE(blueprint_assignment_proxy_witness_test) {
        using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
        constexpr std::size_t WitnessColumns = 15;
        constexpr std::size_t PublicInputColumns = 1;
        constexpr std::size_t ConstantColumns = 5;
        constexpr std::size_t SelectorColumns = 35;

        using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
        using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

        auto assignment_ptr = std::make_shared<assignment<ArithmetizationType>>();
        std::vector<assignment_proxy<ArithmetizationType>> assignments;
        assignments.emplace_back(assignment_ptr, 0);
        assignments.emplace_back(assignment_ptr, 1);

        // add witness
        assignments[0].witness(0, 0);
        assignments[0].witness(0, 1);
        assignments[1].witness(1, 2);

        BOOST_ASSERT(assignments[0].rows_amount() == assignments[1].rows_amount());
        BOOST_ASSERT(assignments[0].rows_amount() == 3);

        BOOST_ASSERT(assignments[0].allocated_rows() == assignments[1].allocated_rows());
        BOOST_ASSERT(assignments[0].allocated_rows() == 3);

        BOOST_ASSERT(assignments[0].witness_column_size(0) == assignments[1].witness_column_size(0));
        BOOST_ASSERT(assignments[0].witness_column_size(0) == 2);
        BOOST_ASSERT(assignments[0].witness_column_size(1) == assignments[1].witness_column_size(1));
        BOOST_ASSERT(assignments[0].witness_column_size(1) == 3);

        std::set<uint32_t> used_rows_0 = {0, 1};
        BOOST_ASSERT(assignments[0].get_used_rows() == used_rows_0);
        std::set<uint32_t> used_rows_1 = {2};
        BOOST_ASSERT(assignments[1].get_used_rows() == used_rows_1);
}

BOOST_AUTO_TEST_CASE(blueprint_assignment_proxy_constant_test) {
        using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
        constexpr std::size_t WitnessColumns = 15;
        constexpr std::size_t PublicInputColumns = 1;
        constexpr std::size_t ConstantColumns = 5;
        constexpr std::size_t SelectorColumns = 35;

        using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
        using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

        auto assignment_ptr = std::make_shared<assignment<ArithmetizationType>>();
        std::vector<assignment_proxy<ArithmetizationType>> assignments;
        assignments.emplace_back(assignment_ptr, 0);
        assignments.emplace_back(assignment_ptr, 1);

        // add constants
        assignments[0].constant(0, 0);
        assignments[0].constant(0, 1);
        assignments[1].constant(1, 2);

        BOOST_ASSERT(assignments[0].rows_amount() == assignments[1].rows_amount());
        BOOST_ASSERT(assignments[0].rows_amount() == 3);

        BOOST_ASSERT(assignments[0].allocated_rows() == assignments[1].allocated_rows());
        BOOST_ASSERT(assignments[0].allocated_rows() == 3);

        BOOST_ASSERT(assignments[0].constant_column_size(0) == assignments[1].constant_column_size(0));
        BOOST_ASSERT(assignments[0].constant_column_size(0) == 2);
        BOOST_ASSERT(assignments[0].constant_column_size(1) == assignments[1].constant_column_size(1));
        BOOST_ASSERT(assignments[0].constant_column_size(1) == 3);

        std::set<uint32_t> used_rows_0 = {0, 1};
        BOOST_ASSERT(assignments[0].get_used_rows() == used_rows_0);
        std::set<uint32_t> used_rows_1 = {2};
        BOOST_ASSERT(assignments[1].get_used_rows() == used_rows_1);
}

BOOST_AUTO_TEST_CASE(blueprint_assignment_proxy_public_input_test) {
        using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
        constexpr std::size_t WitnessColumns = 15;
        constexpr std::size_t PublicInputColumns = 1;
        constexpr std::size_t ConstantColumns = 5;
        constexpr std::size_t SelectorColumns = 35;

        using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
        using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

        auto assignment_ptr = std::make_shared<assignment<ArithmetizationType>>();
        std::vector<assignment_proxy<ArithmetizationType>> assignments;
        assignments.emplace_back(assignment_ptr, 0);
        assignments.emplace_back(assignment_ptr, 1);

        // add public_inputs
        assignments[0].public_input(0, 0);
        assignments[0].public_input(0, 1);
        assignments[1].public_input(0, 2);

        BOOST_ASSERT(assignments[0].rows_amount() == assignments[1].rows_amount());
        BOOST_ASSERT(assignments[0].rows_amount() == 3);


        BOOST_ASSERT(assignments[0].public_input_column_size(0) == assignments[1].public_input_column_size(0));
        BOOST_ASSERT(assignments[0].public_input_column_size(0) == 3);

        std::set<uint32_t> used_rows_0 = {};
        BOOST_ASSERT(assignments[0].get_used_rows() == used_rows_0);
        std::set<uint32_t> used_rows_1 = {};
        BOOST_ASSERT(assignments[1].get_used_rows() == used_rows_1);
}

BOOST_AUTO_TEST_CASE(blueprint_assignment_proxy_save_shared_test) {
        using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
        constexpr std::size_t WitnessColumns = 15;
        constexpr std::size_t PublicInputColumns = 1;
        constexpr std::size_t ConstantColumns = 5;
        constexpr std::size_t SelectorColumns = 35;

        using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
        using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
        using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

        auto assignment_ptr = std::make_shared<assignment<ArithmetizationType>>();
        assignment_proxy<ArithmetizationType> assignment(assignment_ptr, 0);

        const std::vector<var> v = {var(0, 0, true, var::column_type::witness), var(0, 1, true, var::column_type::witness)};
        assignment.witness(0, 0) = 1;
        assignment.witness(0, 1) = 2;
        const auto res = save_shared_var(assignment, v);

        BOOST_ASSERT(res.size() == 2);
        BOOST_ASSERT(res[0].index == 1);
        BOOST_ASSERT(res[1].index == 1);
        BOOST_ASSERT(res[0].rotation == 0);
        BOOST_ASSERT(res[1].rotation == 1);
        BOOST_ASSERT(res[0].type == var::column_type::public_input);
        BOOST_ASSERT(res[1].type == var::column_type::public_input);
        BOOST_ASSERT(var_value(assignment, res[0]) == 1);
        BOOST_ASSERT(var_value(assignment, res[1]) == 2);

        BOOST_ASSERT(assignment.shared_column_size(0) == 2);
}

BOOST_AUTO_TEST_CASE(blueprint_proxy_call_pack_lookup_tables_test) {
        using BlueprintFieldType = typename nil::crypto3::algebra::curves::pallas::base_field_type;
        constexpr std::size_t WitnessColumns = 15;
        constexpr std::size_t PublicInputColumns = 1;
        constexpr std::size_t ConstantColumns = 5;
        constexpr std::size_t SelectorColumns = 35;

        using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
        using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
        using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
        using column_type = typename nil::crypto3::zk::snark::plonk_column<BlueprintFieldType>;
        typedef nil::crypto3::zk::snark::plonk_lookup_table<BlueprintFieldType> lookup_table_type;

        auto bp_ptr = std::make_shared<circuit<ArithmetizationType>>();
        circuit_proxy<ArithmetizationType> bp(bp_ptr, 0);
        auto assignment_ptr = std::make_shared<assignment<ArithmetizationType>>();
        assignment_proxy<ArithmetizationType> assignment(assignment_ptr, 0);

        std::vector<std::size_t> lookup_columns_indices = {0, 1, 2, 3, 4};
        std::size_t usable_rows_amount = assignment.allocated_rows();
        bp.reserve_table("binary_xor_table/full");

        nil::crypto3::zk::snark::pack_lookup_tables(
                bp.get_reserved_indices(),
                bp.get_reserved_tables(),
                bp.get(), assignment.get(), lookup_columns_indices,
                usable_rows_amount);

        std::set<uint32_t> lookup_constant_cols = {0, 1, 2, 3, 4};
        BOOST_ASSERT(assignment.get_lookup_constant_cols() == lookup_constant_cols);
        std::set<uint32_t> lookup_selector_cols = {1};
        BOOST_ASSERT(assignment.get_lookup_selector_cols() == lookup_selector_cols);
}