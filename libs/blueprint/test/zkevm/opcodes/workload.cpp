//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"
#define BOOST_TEST_MODULE zkevm_workload_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include "nil/blueprint/zkevm/zkevm_word.hpp"

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit_proxy.hpp>
#include <nil/blueprint/blueprint/plonk/assignment_proxy.hpp>

#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include "../opcode_tester.hpp"

#include <boost/json/src.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/optional.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <boost/log/trivial.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <ios>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint_system.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/assignment_table.hpp>

#include <future>
#include <thread>
#include <chrono>

using namespace nil;
using namespace nil::crypto3;
using namespace nil::blueprint;
using namespace nil::crypto3::algebra;

template<typename Endianness, typename ArithmetizationType, typename ConstraintSystemType>
void print_circuit(const circuit_proxy<ArithmetizationType> &circuit_proxy,
                   const assignment_proxy<ArithmetizationType> &table_proxy,
                   bool multi_prover, std::uint32_t idx, std::ostream &out = std::cout) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using value_marshalling_type =
        nil::crypto3::marshalling::types::plonk_constraint_system<TTypeBase, ConstraintSystemType>;
    using AssignmentTableType = assignment_proxy<ArithmetizationType>;
    using variable_type = crypto3::zk::snark::plonk_variable<typename AssignmentTableType::field_type::value_type>;

    const auto& gates = circuit_proxy.gates();
    const auto& used_gates_idx = circuit_proxy.get_used_gates();
    typename ConstraintSystemType::gates_container_type used_gates;
    for (const auto &it : used_gates_idx) {
        used_gates.push_back(gates[it]);
    }

    const auto& copy_constraints = circuit_proxy.copy_constraints();
    typename ConstraintSystemType::copy_constraints_container_type used_copy_constraints;
    const auto& used_copy_constraints_idx = circuit_proxy.get_used_copy_constraints();
    for (const auto &it : used_copy_constraints_idx) {
        used_copy_constraints.push_back(copy_constraints[it]);
    }

    if (multi_prover && idx > 0) {
        const auto& used_rows = table_proxy.get_used_rows();
        std::uint32_t local_row = 0;
        for (const auto &row : used_rows) {
            for (auto &constraint : used_copy_constraints) {
                const auto first_var = constraint.first;
                const auto second_var = constraint.second;
                if ((first_var.type == variable_type::column_type::witness ||
                     first_var.type == variable_type::column_type::constant) &&
                    first_var.rotation == row) {
                    constraint.first = variable_type(first_var.index, local_row, first_var.relative,
                                                     first_var.type);
                }
                if ((second_var.type == variable_type::column_type::witness ||
                     second_var.type == variable_type::column_type::constant) &&
                    second_var.rotation == row) {
                    constraint.second = variable_type(second_var.index, local_row,
                                                      second_var.relative, second_var.type);
                }
            }
            local_row++;
        }
    }

    const auto& lookup_gates = circuit_proxy.lookup_gates();
    typename ConstraintSystemType::lookup_gates_container_type used_lookup_gates;
    const auto& used_lookup_gates_idx = circuit_proxy.get_used_lookup_gates();
    for (const auto &it : used_lookup_gates_idx) {
        used_lookup_gates.push_back(lookup_gates[it]);
    }

    const auto& lookup_tables = circuit_proxy.lookup_tables();
    typename ConstraintSystemType::lookup_tables_type used_lookup_tables;
    const auto& used_lookup_tables_idx = circuit_proxy.get_used_lookup_tables();
    for (const auto &it : used_lookup_tables_idx) {
        used_lookup_tables.push_back(lookup_tables[it]);
    }


    // fill public input sizes
    nil::crypto3::marshalling::types::public_input_sizes_type<TTypeBase> public_input_sizes;
    using public_input_size_type = typename nil::crypto3::marshalling::types::public_input_sizes_type<TTypeBase>::element_type;
    const auto public_input_size = table_proxy.public_inputs_amount();
    for (std::uint32_t i = 0; i < public_input_size; i++) {
        public_input_sizes.value().push_back(public_input_size_type(table_proxy.public_input_column_size(i)));
    }
    if (multi_prover) {
        public_input_sizes.value().push_back(public_input_size_type(table_proxy.shared_column_size(0)));
    }

    auto filled_val =
        value_marshalling_type(std::make_tuple(
            nil::crypto3::marshalling::types::fill_plonk_gates<Endianness, typename ConstraintSystemType::gates_container_type::value_type>(used_gates),
            nil::crypto3::marshalling::types::fill_plonk_copy_constraints<Endianness, typename ConstraintSystemType::field_type>(used_copy_constraints),
            nil::crypto3::marshalling::types::fill_plonk_lookup_gates<Endianness, typename ConstraintSystemType::lookup_gates_container_type::value_type>(used_lookup_gates),
            nil::crypto3::marshalling::types::fill_plonk_lookup_tables<Endianness, typename ConstraintSystemType::lookup_tables_type::value_type>(used_lookup_tables),
            public_input_sizes
    ));

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);
    auto cv_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(cv_iter, cv.size());
    out.write(reinterpret_cast<char*>(cv.data()), cv.size());
}

enum class print_table_kind {
    MULTI_PROVER,
    SINGLE_PROVER
};

enum class print_column_kind {
    WITNESS,
    SHARED,
    PUBLIC_INPUT,
    CONSTANT,
    SELECTOR
};

template<typename Endianness>
void print_size_t(
    std::size_t input,
    std::ostream &out
) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    auto integer_container = nil::marshalling::types::integral<TTypeBase, std::size_t>(input);
    std::array<std::uint8_t, integer_container.length()> char_array{};
    auto write_iter = char_array.begin();
    integer_container.write(write_iter, char_array.size());
    out.write(reinterpret_cast<char*>(char_array.data()), char_array.size());
}

template<typename Endianness, typename ArithmetizationType>
inline void print_zero_field(
    std::ostream &out
) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using AssignmentTableType = assignment_proxy<ArithmetizationType>;
    using field_element = nil::crypto3::marshalling::types::field_element<
        TTypeBase, typename AssignmentTableType::field_type::value_type>;
    std::array<std::uint8_t, field_element().length()> array{};
    out.write(reinterpret_cast<char*>(array.data()), array.size());
}


template<typename Endianness, typename ArithmetizationType>
void print_field(
    const typename assignment_proxy<ArithmetizationType>::field_type::value_type &input,
    std::ostream &out
) {
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using AssignmentTableType = assignment_proxy<ArithmetizationType>;
    auto field_container = nil::crypto3::marshalling::types::field_element<TTypeBase, typename AssignmentTableType::field_type::value_type>(input);
    std::array<std::uint8_t, field_container.length()> char_array{};
    auto write_iter = char_array.begin();
    field_container.write(write_iter, char_array.size());
    out.write(reinterpret_cast<char*>(char_array.data()), char_array.size());
}

template<typename Endianness, typename ArithmetizationType, typename ContainerType>
void print_vector_value(
    const std::size_t padded_rows_amount,
    const ContainerType &table_col,
    std::ostream &out
) {
    for (std::size_t i = 0; i < padded_rows_amount; i++) {
        if (i < table_col.size()) {
            print_field<Endianness, ArithmetizationType>(table_col[i], out);
        } else {
            print_zero_field<Endianness, ArithmetizationType>(out);
        }
    }
}


template<typename Endianness, typename ArithmetizationType, typename BlueprintFieldType>
void print_assignment_table(const assignment_proxy<ArithmetizationType> &table_proxy,
                            print_table_kind print_kind,
                            std::uint32_t ComponentConstantColumns, std::uint32_t ComponentSelectorColumns,
                            std::ostream &out = std::cout) {
    using AssignmentTableType = assignment_proxy<ArithmetizationType>;
    std::uint32_t usable_rows_amount;
    std::uint32_t total_columns;
    std::uint32_t total_size;
    std::uint32_t shared_size = (print_kind == print_table_kind::MULTI_PROVER) ? 1 : 0;
    std::uint32_t public_input_size = table_proxy.public_inputs_amount();
    std::uint32_t witness_size = table_proxy.witnesses_amount();
    std::uint32_t constant_size = table_proxy.constants_amount();
    std::uint32_t selector_size = table_proxy.selectors_amount();
    const auto lookup_constant_cols = table_proxy.get_lookup_constant_cols();
    const auto lookup_selector_cols = table_proxy.get_lookup_selector_cols();

    std::uint32_t max_public_inputs_size = 0;
    std::uint32_t max_constant_size = 0;
    std::uint32_t max_selector_size = 0;

    for (std::uint32_t i = 0; i < public_input_size; i++) {
        max_public_inputs_size = std::max(max_public_inputs_size, table_proxy.public_input_column_size(i));
    }

    if (print_kind == print_table_kind::MULTI_PROVER) {
        total_columns = witness_size + shared_size + public_input_size + constant_size + selector_size;
        std::uint32_t max_shared_size = 0;
        for (std::uint32_t i = 0; i < shared_size; i++) {
            max_shared_size = std::max(max_shared_size, table_proxy.shared_column_size(i));
        }
        for (const auto &i : lookup_constant_cols) {
            max_constant_size = std::max(max_constant_size, table_proxy.constant_column_size(i));
        }
        for (const auto &i : lookup_selector_cols) {
            max_selector_size = std::max(max_selector_size, table_proxy.selector_column_size(i));
        }
        usable_rows_amount = table_proxy.get_used_rows().size();
        usable_rows_amount = std::max({usable_rows_amount, max_shared_size, max_public_inputs_size, max_constant_size, max_selector_size});
    } else { // SINGLE_PROVER
        total_columns = witness_size + shared_size + public_input_size + constant_size + selector_size;
        std::uint32_t max_witness_size = 0;
        for (std::uint32_t i = 0; i < witness_size; i++) {
            max_witness_size = std::max(max_witness_size, table_proxy.witness_column_size(i));
        }
        for (std::uint32_t i = 0; i < constant_size; i++) {
            max_constant_size = std::max(max_constant_size, table_proxy.constant_column_size(i));
        }
        for (std::uint32_t i = 0; i < selector_size; i++) {
            max_selector_size = std::max(max_selector_size, table_proxy.selector_column_size(i));
        }
        usable_rows_amount = std::max({max_witness_size, max_public_inputs_size, max_constant_size, max_selector_size});
    }

    std::uint32_t padded_rows_amount = std::pow(2, std::ceil(std::log2(usable_rows_amount)));
    if (padded_rows_amount == usable_rows_amount) {
        padded_rows_amount *= 2;
    }
    if (padded_rows_amount < 8) {
        padded_rows_amount = 8;
    }
    total_size = padded_rows_amount * total_columns;

    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using table_value_marshalling_type =
        nil::crypto3::marshalling::types::plonk_assignment_table<TTypeBase, AssignmentTableType>;

    using column_type = typename crypto3::zk::snark::plonk_column<BlueprintFieldType>;


    print_size_t<Endianness>(witness_size, out);
    print_size_t<Endianness>(public_input_size + shared_size, out);
    print_size_t<Endianness>(constant_size, out);
    print_size_t<Endianness>(selector_size, out);
    print_size_t<Endianness>(usable_rows_amount, out);
    print_size_t<Endianness>(padded_rows_amount, out);

    if (print_kind == print_table_kind::SINGLE_PROVER) {
    print_size_t<Endianness>(witness_size * padded_rows_amount, out);
        for (std::uint32_t i = 0; i < witness_size; i++) {
            print_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount, table_proxy.witness(i), out);
        }
    print_size_t<Endianness>((public_input_size + shared_size) * padded_rows_amount, out);
        for (std::uint32_t i = 0; i < public_input_size; i++) {
            print_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount, table_proxy.public_input(i), out);
        }
    print_size_t<Endianness>(constant_size * padded_rows_amount, out);
        for (std::uint32_t i = 0; i < constant_size; i++) {
            print_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount, table_proxy.constant(i), out);
        }
    print_size_t<Endianness>(selector_size * padded_rows_amount, out);
        for (std::uint32_t i = 0; i < selector_size; i++) {
            print_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount, table_proxy.selector(i), out);
        }
    } else {
        const auto& rows = table_proxy.get_used_rows();
        const auto& selector_rows = table_proxy.get_used_selector_rows();
        std::uint32_t witness_idx = 0;

        // witness
        print_size_t<Endianness>(witness_size * padded_rows_amount, out);
        for( std::size_t i = 0; i < witness_size; i++ ){
            const auto column_size = table_proxy.witness_column_size(i);
            std::uint32_t offset = 0;
            for(const auto& j : rows){
                if (j < column_size) {
                    print_field<Endianness, ArithmetizationType>(table_proxy.witness(i, j), out);
                    offset++;
                }
            }
            while(offset < padded_rows_amount) {
                print_zero_field<Endianness, ArithmetizationType>(out);
                offset++;
            }
            witness_idx += padded_rows_amount;
        }
        // public input
        std::uint32_t pub_inp_idx = 0;
        print_size_t<Endianness>((public_input_size + shared_size) * padded_rows_amount, out);
        for (std::uint32_t i = 0; i < public_input_size; i++) {
            print_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount, table_proxy.public_input(i), out);
            pub_inp_idx += padded_rows_amount;
        }
        for (std::uint32_t i = 0; i < shared_size; i++) {
            print_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount, table_proxy.shared(i), out);
            pub_inp_idx += padded_rows_amount;
        }
        // constant
        print_size_t<Endianness>(constant_size * padded_rows_amount, out);
        std::uint32_t constant_idx = 0;
        for (std::uint32_t i = 0; i < ComponentConstantColumns; i++) {
            const auto column_size = table_proxy.constant_column_size(i);
            std::uint32_t offset = 0;
            for(const auto& j : rows){
                if (j < column_size) {
                    print_field<Endianness, ArithmetizationType>(table_proxy.constant(i, j), out);
                    offset++;
                }
            }
            while(offset < padded_rows_amount) {
                print_zero_field<Endianness, ArithmetizationType>(out);
                offset++;
            }

            constant_idx += padded_rows_amount;
        }

        for (std::uint32_t i = ComponentConstantColumns; i < constant_size; i++) {
            print_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount, table_proxy.constant(i), out);
            constant_idx += padded_rows_amount;
        }

        // selector
        print_size_t<Endianness>(selector_size * padded_rows_amount, out);
        std::uint32_t selector_idx = 0;
        for (std::uint32_t i = 0; i < ComponentSelectorColumns; i++) {
            const auto column_size = table_proxy.selector_column_size(i);
            std::uint32_t offset = 0;
            for(const auto& j : rows){
                if (j < column_size) {
                    if (selector_rows.find(j) != selector_rows.end()) {
                        print_field<Endianness, ArithmetizationType>(table_proxy.selector(i, j), out);
                    } else {
                        print_zero_field<Endianness, ArithmetizationType>(out);
                    }
                    offset++;
                }
            }
            while(offset < padded_rows_amount) {
                print_zero_field<Endianness, ArithmetizationType>(out);
                offset++;
            }

            selector_idx += padded_rows_amount;
        }

        for (std::uint32_t i = ComponentSelectorColumns; i < selector_size; i++) {
            print_vector_value<Endianness, ArithmetizationType, column_type>(padded_rows_amount, table_proxy.selector(i), out);
            selector_idx += padded_rows_amount;
        }
    }
}

BOOST_AUTO_TEST_SUITE(zkevm_workload_test_suite)

BOOST_AUTO_TEST_CASE(zkevm_workload_test) {
    using field_type = fields::pallas_base_field;
    using arithmentization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using assignment_type = assignment<arithmentization_type>;
    using circuit_type = circuit<arithmentization_type>;
    using zkevm_machine_type = zkevm_machine_interface;
    const std::vector<zkevm_opcode> implemented_opcodes = {
        zkevm_opcode::ADD, zkevm_opcode::SUB, zkevm_opcode::AND, zkevm_opcode::OR, zkevm_opcode::XOR,
        zkevm_opcode::BYTE, zkevm_opcode::SHL, zkevm_opcode::SHR, zkevm_opcode::SAR, zkevm_opcode::SIGNEXTEND,
        zkevm_opcode::EQ, zkevm_opcode::GT, zkevm_opcode::LT, zkevm_opcode::SGT, zkevm_opcode::SLT,
        zkevm_opcode::DIV, zkevm_opcode::MOD, zkevm_opcode::SDIV, zkevm_opcode::SMOD, zkevm_opcode::ISZERO,
        zkevm_opcode::ADDMOD, zkevm_opcode::MULMOD, zkevm_opcode::MUL, zkevm_opcode::NOT};
    const std::size_t num_of_opcodes = implemented_opcodes.size(),
                      workload = 32767;
//                      workload = 63;

    std::shared_ptr<assignment_type> assignment = std::make_shared<assignment_type>(0, 0, 0, 0);

    std::shared_ptr<circuit_type> circuit = std::make_shared<circuit_type>();
    zkevm_circuit<field_type> zkevm_circuit(*assignment, *circuit);
    zkevm_machine_type machine = get_empty_machine();
    // incorrect test logic, but we have no memory operations so
    for(std::size_t i = 0; i < workload; i++) {
        zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1234567890_cppui_modular257));
        zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0x1b70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
        zkevm_circuit.assign_opcode(zkevm_opcode::PUSH32, machine, zwordc(0xFb70726fb8d3a24da9ff9647225a18412b8f010425938504d73ebc8801e2e016_cppui_modular257));
        zkevm_circuit.assign_opcode(implemented_opcodes[i % num_of_opcodes], machine);
    }
    zkevm_circuit.finalize_test();


    std::vector<size_t> lookup_columns_indices;
    for(std::size_t i = 0; i < assignment->constants_amount(); i++) {
        lookup_columns_indices.push_back(i);
    }

    std::size_t cur_selector_id = 0;
    for(const auto &gate: circuit->gates()){
        cur_selector_id = std::max(cur_selector_id, gate.selector_index);
    }
    for(const auto &lookup_gate: circuit->lookup_gates()){
        cur_selector_id = std::max(cur_selector_id, lookup_gate.tag_index);
    }
    cur_selector_id++;
    zk::snark::pack_lookup_tables_horizontal(
                    circuit->get_reserved_indices(),
                    circuit->get_reserved_tables(),
                    *circuit, *assignment,
                    lookup_columns_indices,
                    cur_selector_id,
                    assignment->rows_amount(),
                    500000
                );

    //
    // witnesses_size: 100 public_inputs_size: 0 constants_size: 5 selectors_size: 3
    // 5 lookup_constant_columns, 1 lookup_selector
    const std::size_t ComponentConstantColumns = 0;
    const std::size_t LookupConstantColumns = 5;
    const std::size_t ComponentSelectorColumns = 3;
    const std::size_t LookupSelectorColumns = 2; // for lookup table packing
    const std::size_t WitnessColumns = 100;
    const std::size_t PublicInputColumns = 0;

    const std::size_t ConstantColumns = ComponentConstantColumns + LookupConstantColumns;
    const std::size_t SelectorColumns = ComponentSelectorColumns + LookupSelectorColumns;

    using BlueprintFieldType = field_type;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using ConstraintSystemType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using ConstraintSystemProxyType = zk::snark::plonk_table<BlueprintFieldType, zk::snark::plonk_column<BlueprintFieldType>>;
    using ArithmetizationType =
            crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentTableType = zk::snark::plonk_table<BlueprintFieldType, zk::snark::plonk_column<BlueprintFieldType>>;
    // Print assignment table
std::cout << "Our assignment has " << assignment->rows_amount() << " elements" << std::endl;
    std::ofstream otable;
    assignment_proxy<arithmentization_type> assignment_proxy(assignment, 0);
    assignment_proxy.make_all_rows_used();

    otable.open("big2_assignment.tbl",
                std::ios_base::binary | std::ios_base::out);
    print_assignment_table<nil::marshalling::option::big_endian, ArithmetizationType, BlueprintFieldType>(
        assignment_proxy, print_table_kind::MULTI_PROVER, ComponentConstantColumns, ComponentSelectorColumns, otable);

    otable.close();

    // Print circuit
std::cout << "Our circuit has " << circuit->num_gates() << " gates" << std::endl;
    circuit_proxy<arithmentization_type> circuit_proxy(circuit, 0);
    std::ofstream ocircuit;

    ocircuit.open("big2_circuit.crt", std::ios_base::binary | std::ios_base::out);

    print_circuit<nil::marshalling::option::big_endian, ArithmetizationType, ConstraintSystemType>(
        circuit_proxy, assignment_proxy, false, 0, ocircuit);
    ocircuit.close();

//    nil::crypto3::zk::snark::basic_padding(*assignment);
//    BOOST_ASSERT(is_satisfied(*circuit, *assignment) == true);
}

BOOST_AUTO_TEST_SUITE_END()
