//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#pragma once

#include <iterator>
#include <map>
#include <memory>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/gate_id.hpp>

#include <nil/blueprint/zkevm/state.hpp>
#include <nil/blueprint/zkevm/index_selector.hpp>
#include <nil/blueprint/zkevm/zkevm_opcodes.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/zkevm_operation.hpp>

#include <nil/blueprint/zkevm/operations/iszero.hpp>
#include <nil/blueprint/zkevm/operations/add_sub.hpp>
#include <nil/blueprint/zkevm/operations/mul.hpp>
#include <nil/blueprint/zkevm/operations/div_mod.hpp>
#include <nil/blueprint/zkevm/operations/sdiv_smod.hpp>
#include <nil/blueprint/zkevm/operations/cmp.hpp>
#include <nil/blueprint/zkevm/operations/not.hpp>
#include <nil/blueprint/zkevm/operations/byte.hpp>
#include <nil/blueprint/zkevm/operations/signextend.hpp>
#include <nil/blueprint/zkevm/operations/bitwise.hpp>
#include <nil/blueprint/zkevm/operations/shl.hpp>
#include <nil/blueprint/zkevm/operations/shr.hpp>
#include <nil/blueprint/zkevm/operations/sar.hpp>
#include <nil/blueprint/zkevm/operations/addmod.hpp>
#include <nil/blueprint/zkevm/operations/mulmod.hpp>
#include <nil/blueprint/zkevm/operations/pushx.hpp>
#include <nil/blueprint/zkevm/operations/err0.hpp>
#include <nil/blueprint/zkevm/operations/memory.hpp>
#include <nil/blueprint/zkevm/operations/storage.hpp>
#include <nil/blueprint/zkevm/operations/callvalue.hpp>
#include <nil/blueprint/zkevm/operations/calldatasize.hpp>
#include <nil/blueprint/zkevm/operations/calldataload.hpp>
#include <nil/blueprint/zkevm/operations/dupx.hpp>
#include <nil/blueprint/zkevm/operations/swapx.hpp>
#include <nil/blueprint/zkevm/operations/jump.hpp>
#include <nil/blueprint/zkevm/operations/pop.hpp>
#include <nil/blueprint/zkevm/operations/padding.hpp>
#include <nil/blueprint/zkevm/operations/return.hpp>

#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include <nil/blueprint/zkevm/bytecode.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType>
        class columns_manager;

        template<typename BlueprintFieldType>
        class zkevm_circuit;

        template<typename BlueprintFieldType>
        class zkevm_table {
        public:
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using assignment_type = nil::blueprint::assignment<arithmetization_type>;
            using circuit_type = nil::blueprint::circuit<arithmetization_type>;
            using zkevm_state_type = zkevm_vars<BlueprintFieldType>;
            using columns_manager_type = columns_manager<BlueprintFieldType>;
            using zkevm_operation_type = zkevm_operation<BlueprintFieldType>;
            using zkevm_opcode_gate_class = typename zkevm_operation<BlueprintFieldType>::gate_class;
            using index_selector_type = components::index_selector<arithmetization_type, BlueprintFieldType>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename crypto3::zk::snark::plonk_variable<value_type>;

            zkevm_table(const zkevm_circuit<BlueprintFieldType> &circuit_, assignment_type &assignment_):
                circuit(circuit_), assignment(assignment_), curr_row(circuit.get_start_row_index()){
            }

            void finalize_test(
                const typename zkevm_circuit<BlueprintFieldType>::bytecode_table_component::input_type &bytecode_input
            ) {
                finalize(bytecode_input);
                std::cout << "Assignment rows amount = " << assignment.rows_amount() << std::endl;
            }

            void finalize(
                const typename zkevm_circuit<BlueprintFieldType>::bytecode_table_component::input_type &bytecode_input
            ) {
                BOOST_ASSERT_MSG(curr_row != 0, "Row underflow in finalization");

                zkevm_machine_interface empty_machine(0, 0);
                empty_machine.padding_state();
                while(curr_row - circuit.get_start_row_index() < circuit.get_max_rows()-1){
                    assign_opcode(empty_machine);
                }

                // Assign dynamic lookup tables
                typename zkevm_circuit<BlueprintFieldType>::bytecode_table_component bytecode_table({
                    circuit.get_bytecode_witnesses()[0], circuit.get_bytecode_witnesses()[1], circuit.get_bytecode_witnesses()[2],
                    circuit.get_bytecode_witnesses()[3], circuit.get_bytecode_witnesses()[4], circuit.get_bytecode_witnesses()[5]
                }, {}, {}, 10);

                std::cout << "Assign bytecode_table" << std::endl;
                generate_assignments(bytecode_table, assignment, bytecode_input, 0);
            }

            void assign_opcode(zkevm_machine_interface &machine) {
                auto opcode = machine.opcode;
                std::cout << "Assign opcode " << opcode_to_string(machine.opcode)
                    << " on row " << curr_row
                    << " pc = " << machine.pc
                    << " stack_size = " << machine.stack.size()
                    << " gas = " << machine.gas
                    << std::endl;
                const auto &opcodes = circuit.get_opcodes();
                auto opcode_it = opcodes.find(opcode);
                if (opcode_it == opcodes.end()) {
                    BOOST_ASSERT_MSG(false, (std::string("Unimplemented opcode: ") + opcode_to_string(opcode)) != "");
                }
                // Generate all state columns
                advance_rows(machine);

                std::set<zkevm_opcode> opcodes_with_args = { zkevm_opcode::PUSH0, zkevm_opcode::PUSH1, zkevm_opcode::PUSH2,
                    zkevm_opcode::PUSH3, zkevm_opcode::PUSH4, zkevm_opcode::PUSH5, zkevm_opcode::PUSH6, zkevm_opcode::PUSH7,
                    zkevm_opcode::PUSH8, zkevm_opcode::PUSH9, zkevm_opcode::PUSH10, zkevm_opcode::PUSH11, zkevm_opcode::PUSH12,
                    zkevm_opcode::PUSH13, zkevm_opcode::PUSH14, zkevm_opcode::PUSH15, zkevm_opcode::PUSH16, zkevm_opcode::PUSH17,
                    zkevm_opcode::PUSH18, zkevm_opcode::PUSH19, zkevm_opcode::PUSH20, zkevm_opcode::PUSH21, zkevm_opcode::PUSH22,
                    zkevm_opcode::PUSH23, zkevm_opcode::PUSH24, zkevm_opcode::PUSH25, zkevm_opcode::PUSH26, zkevm_opcode::PUSH27,
                    zkevm_opcode::PUSH28, zkevm_opcode::PUSH29, zkevm_opcode::PUSH30, zkevm_opcode::PUSH31, zkevm_opcode::PUSH32,
                    zkevm_opcode::err0
                };
                if (opcodes_with_args.find(opcode) == opcodes_with_args.end()) {
                     opcode_it->second->generate_assignments(*this, machine);
                } else {
                    // for push opcodes we use the additional argument
                    using pushx_op_type = zkevm_pushx_operation<BlueprintFieldType>;
                    using err0_op_type = zkevm_err0_operation<BlueprintFieldType>;
                    if (opcode == zkevm_opcode::err0) {
                        auto err0_implementation = std::static_pointer_cast<err0_op_type>(opcode_it->second);
                        err0_implementation->generate_assignments(*this, machine, machine.additional_input);
                    } else {
                        auto pushx_implementation = std::static_pointer_cast<pushx_op_type>(opcode_it->second);
                        pushx_implementation->generate_assignments(*this, machine, machine.additional_input);
                    }
                }
                curr_row += opcode_it->second->rows_amount() + opcode_it->second->rows_amount() % 2;
                if( curr_row - circuit.get_start_row_index() > circuit.get_max_rows() )
                    std::cout << "Curr_row = " << curr_row << " max_rows = " <<  circuit.get_max_rows()  << std::endl;
                BOOST_ASSERT(curr_row - circuit.get_start_row_index() < circuit.get_max_rows());
            }

            void advance_rows(
                const zkevm_machine_interface &machine
            ) {
                const auto &opcodes = circuit.get_opcodes();
                auto opcode = machine.opcode;
                auto opcode_it = opcodes.find(machine.opcode);
                if (opcode_it == opcodes.end()) {
                    BOOST_ASSERT_MSG(false, (std::string("Unimplemented opcode: ") + opcode_to_string(opcode)) != "");
                }
                std::size_t opcode_height = opcode_it->second->rows_amount();

                const auto &state = circuit.get_state();
                // state management
                value_type step_start = 1;          // internal variables
                value_type row_counter_inv;

                // for opcodes with odd height append one row
                if (opcode_it->second->rows_amount() % 2 ) {
                    opcode_height++;
                }
                row_counter_inv = value_type(opcode_height - 1).inversed();

                std::size_t current_internal_row = opcode_height - 1;
                auto &opcodes_info_instance = circuit.get_opcodes_info();

                // TODO: figure out what is going to happen on state change
                std::size_t local_row = curr_row;
                std::size_t opcode_num = opcodes_info_instance.get_opcode_number(opcode);
                std::size_t opcode_half = ((opcode_num % 4 == 3) || (opcode_num % 4 == 2));
                for (std::size_t i = 0; i < opcode_height; i++) {
                    assignment.witness(state.opcode.index, local_row) = opcode_num;
                    assignment.witness(state.real_opcode.index, local_row) = opcodes_info_instance.get_opcode_value(opcode);
                    assignment.witness(state.bytecode_hash_hi.index, local_row) = w_hi<BlueprintFieldType>(machine.bytecode_hash);
                    assignment.witness(state.bytecode_hash_lo.index, local_row) = w_lo<BlueprintFieldType>(machine.bytecode_hash);

                    if (i % 2 == opcode_half) {
                        components::generate_assignments(*circuit.get_opcode_selector(), assignment, {opcode_num/4}, local_row);
                    }
                    assignment.witness(state.opcode_parity.index, local_row) = opcode_num%2;

                    assignment.witness(state.row_counter.index, local_row) = current_internal_row;
                    components::generate_assignments(*(circuit.get_row_selector()), assignment, {current_internal_row/2}, local_row);

                    assignment.witness(state.pc.index, local_row) = machine.pc;
                    assignment.witness(state.gas.index, local_row) = machine.gas;
                    assignment.witness(state.stack_size.index, local_row) = machine.stack.size();
                    assignment.witness(state.memory_size.index, local_row) = machine.memory.size();

                    assignment.witness(state.step_start.index, local_row) = step_start;
                    assignment.witness(state.row_counter_inv.index, local_row) = row_counter_inv;

                    if (i == 0) step_start = 0;

                    current_internal_row--;
                    row_counter_inv = current_internal_row == 0 ? 0 : value_type(current_internal_row).inversed();
                    local_row++;
                }
            }

            const opcodes_info get_opcodes_info() const{
                return circuit.get_opcodes_info();
            }

            const std::vector<std::size_t> &get_opcode_cols() const{
                return circuit.get_opcode_cols();
            }

            const std::size_t get_opcode_range_checked_cols_amount() const {
                return circuit.get_opcode_range_checked_cols_amount();
            }

            assignment_type &get_assignment(){
                return assignment;
            }

            std::size_t get_current_row(){
                return curr_row;
            }
        private:
            assignment_type &assignment;
            const zkevm_circuit<BlueprintFieldType> &circuit;
            // current row maintained between different calls to the circuit object
            std::size_t curr_row;
        };
    }   // namespace blueprint
}   // namespace nil
