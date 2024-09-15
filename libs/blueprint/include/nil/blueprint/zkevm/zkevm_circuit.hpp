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
#include <nil/blueprint/zkevm/state_selector.hpp>
#include <nil/blueprint/zkevm/zkevm_opcodes.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>

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

#include <nil/blueprint/zkevm/bytecode.hpp>

namespace nil {
    namespace blueprint {
        // abstracts control over column indices
        // selectors are already tracked by circuit object by default
        // we implement only automatic extension of the amount of colunmns taken for convinience
        template<typename BlueprintFieldType>
        class columns_manager {
        public:
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using assignment_type = nil::blueprint::assignment<arithmetization_type>;
            using circuit_type = nil::blueprint::circuit<arithmetization_type>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

            columns_manager(assignment_type &assignment_)
                : assignment(assignment_), witness_index(0), constant_index(0), selector_index(0) {}

            std::size_t allocate_witness_column() {
                if (witness_index >= assignment.witnesses_amount()) {
                    assignment.resize_witnesses(witness_index + 1);
                }
                return witness_index++;
            }

            std::size_t allocate_constant_column() {
                if (constant_index >= assignment.constants_amount()) {
                    assignment.resize_constants(constant_index + 1);
                }
                return constant_index++;
            }

            std::size_t allocate_selector_column(){
                if (selector_index >= assignment.selectors_amount()) {
                    assignment.resize_selectors(selector_index + 1);
                }
                return selector_index++;
            }
        private:
            assignment_type &assignment;
            std::size_t witness_index;
            std::size_t constant_index;
            std::size_t selector_index;
        };

        template<typename BlueprintFieldType>
        class zkevm_operation;

        template<typename BlueprintFieldType>
        class zkevm_circuit {
        public:
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using assignment_type = nil::blueprint::assignment<arithmetization_type>;
            using circuit_type = nil::blueprint::circuit<arithmetization_type>;
//            using state_var_type = state_var<BlueprintFieldType>;
            using zkevm_state_type = zkevm_vars<BlueprintFieldType>;
            using columns_manager_type = columns_manager<BlueprintFieldType>;
            using zkevm_operation_type = zkevm_operation<BlueprintFieldType>;
            using zkevm_opcode_gate_class = typename zkevm_operation<BlueprintFieldType>::gate_class;
            using state_selector_type = components::state_selector<arithmetization_type, BlueprintFieldType>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename crypto3::zk::snark::plonk_variable<value_type>;
            using bytecode_table_component = typename components::plonk_zkevm_bytecode_table<BlueprintFieldType>;

            zkevm_circuit(assignment_type &assignment_, circuit_type &circuit, std::size_t _max_rows = 249, std::size_t start_row_index_ = 1)
                :assignment(assignment_), opcodes_info_instance(opcodes_info::instance()),
                 start_row_index(start_row_index_), max_rows(_max_rows),
                 lookup_tables_indices(circuit.get_reserved_indices()
            ){
                columns_manager_type col_manager(assignment); // Just helps us to deal with assignment table columns

                // 5(?) constant columns. I'm not sure we really need them: satisfiability check passes even without them
                for(std::size_t i = 0; i < 5; i++) {
                    col_manager.allocate_constant_column();
                }

                for (auto &lookup_table : zkevm_circuit_lookup_tables()) {
                    if( lookup_table.second == 0 ){
                        std::cout << "Static table " << lookup_table.first << std::endl;
                        circuit.reserve_table(lookup_table.first);
                    }else{
                        std::cout << "Dynamic table " << lookup_table.first << std::endl;
                        circuit.reserve_dynamic_table(lookup_table.first);
                    }
                }
                lookup_tables_indices = circuit.get_reserved_indices();

                BOOST_ASSERT_MSG(start_row_index > 0,
                    "Start row index must be greater than zero, otherwise some gates would access non-existent rows.");
                init_state(col_manager);
                init_opcodes(circuit, col_manager);

                col_manager.allocate_selector_column();
                col_manager.allocate_selector_column();
                assignment.resize_selectors(assignment.selectors_amount() + 2 + dynamic_tables_amount); // for lookup table packing

                allocate_dynamic_tables_columns(col_manager);
                // Add for dynamic lookup tables for the constraint system
                bytecode_table_component bytecode_table({
                    bytecode_witnesses[0], bytecode_witnesses[1], bytecode_witnesses[2],
                    bytecode_witnesses[3], bytecode_witnesses[4], bytecode_witnesses[5]
                }, {}, {}, 10);
                typename bytecode_table_component::input_type input({},{});// Add input variables

                col_manager.allocate_selector_column(); // Bytecode_table needs only one selector
                generate_circuit(bytecode_table, circuit, assignment, input, 0);

                assignment.enable_selector(end_selector, start_row_index + max_rows - 1);
                assignment.enable_selector(start_selector, start_row_index);
                assignment.enable_selector(middle_selector, start_row_index, max_rows-1);

                lookup_tables_indices = circuit.get_reserved_indices();
            }

            std::map<std::string, std::size_t> zkevm_circuit_lookup_tables() const {
                std::map<std::string, std::size_t> lookup_tables;
                lookup_tables["chunk_16_bits/full"] = 0;
                lookup_tables["byte_and_xor_table/and"] = 0;
                lookup_tables["byte_and_xor_table/xor"] = 0;
                lookup_tables["zkevm_bytecode"] = 1;
                return lookup_tables;
            }

            // May be reviewed somehow. Now I'll do the most straight way
            // Each table has its separate columns and selectors.
            // They definitely may be packed more effectively
            void allocate_dynamic_tables_columns(columns_manager_type &col_manager){
                // Bytecode table
                for( std::size_t i = 0; i < bytecode_table_component::witness_amount; i++){
                    bytecode_witnesses.push_back(col_manager.allocate_witness_column());
                }
            }

            const std::shared_ptr<state_selector_type> get_opcode_row_selector() const{
                return opcode_row_selector;
            }

            const std::shared_ptr<state_selector_type> get_state_selector() const{
                return state_selector;
            }

            const opcodes_info get_opcodes_info() const{
                return opcodes_info_instance;
            }

            const std::map<zkevm_opcode, std::shared_ptr<zkevm_operation<BlueprintFieldType>>> &get_opcodes() const{
                return opcodes;
            }

            const zkevm_state_type &get_state() const{
                return state;
            }

            const std::vector<std::size_t> &get_state_selector_cols() const{
                return state_selector_cols;
            }

            const std::vector<std::size_t> &get_opcode_cols() const{
                return opcode_cols;
            }

            std::size_t get_start_row_index() const {
                return start_row_index;
            }

            std::size_t get_max_rows() const{
                return max_rows;
            }

            assignment_type &get_assignment() {
                return assignment;
            }

            const typename lookup_library<BlueprintFieldType>::left_reserved_type &get_reserved_indices() const{
                return lookup_tables_indices;
            }
            // for opcode constraints at certain row of opcode execution
            // note that rows are counted "backwards", starting from opcode rows amount minus one
            // and ending in zero
            constraint_type get_opcode_row_constraint(std::size_t row, std::size_t opcode_height) const {
                BOOST_ASSERT(row < opcode_height);

                var height_var = opcode_row_selector->option_variable();
                var height_var_inv = state.rows_counter_inv;
                // ordering here is important: minimising the degree when possible
                if (row == opcode_height - 1) {
                    return state.step_selection;
                }
                if (row == opcode_height - 2) {
                    return state.step_selection.prev();
                }
                if (row == 0) {
                    return 1 - height_var * height_var_inv;
                }
                // TODO: this is probably possible to optimise
                return opcode_row_selector->option_constraint(row);
            }

            const std::vector<std::uint32_t> &get_bytecode_witnesses() const{
                return bytecode_witnesses;
            }

        private:
            void init_state(columns_manager_type &col_manager) {
                state.pc = typename zkevm_state_type::state_var(col_manager.allocate_witness_column());
                state.stack_size = typename zkevm_state_type::state_var(col_manager.allocate_witness_column());
                state.memory_size = typename zkevm_state_type::state_var(col_manager.allocate_witness_column());
                state.gas = typename zkevm_state_type::state_var(col_manager.allocate_witness_column());
                state.rows_counter_inv = typename zkevm_state_type::state_var(col_manager.allocate_witness_column());
                state.step_selection = typename zkevm_state_type::state_var(col_manager.allocate_witness_column());
                state.last_row_indicator = typename zkevm_state_type::state_var(col_manager.allocate_witness_column());
            }

            std::vector<constraint_type> generate_generic_transition_constraints(
                std::size_t start_selector,
                std::size_t end_selector
            ) {
                std::vector<constraint_type> constraints;

                state_var rows_counter = opcode_row_selector->option_variable();
                state_var rows_counter_inv = state.rows_counter_inv;
                state_var step_selection = state.step_selection;
                state_var option = state.option;

                constraints.push_back(rows_counter() * (rows_counter() * rows_counter_inv() - 1 ));                  //GEN1
                constraints.push_back(rows_counter_inv() * (rows_counter() * rows_counter_inv() - 1));               //GEN2
                // rows_counter decrementing (unless we are at the last row of opcode)
                constraints.push_back(rows_counter() * (rows_counter.next() - rows_counter() + 1));                  //GEN3
                // step_selection is 0 or 1
                constraints.push_back((1 - step_selection()) * step_selection());                                    //GEN4
                // step_selection = 1 if previous row_counter is 0
                constraints.push_back(step_selection() * rows_counter.prev());                                       //GEN5
                // step is copied unless new opcode is next
                constraints.push_back((1 - step_selection()) * (option() - option.prev()));                          //GEN6
                // new opcode selection is forced if new opcode is next
                constraints.push_back((1 - rows_counter_inv.prev() * rows_counter.prev()) * (1 - step_selection())); //GEN7

                // Other state variables does not changed inside one opcode change it if necessary.
                constraints.push_back((1 - step_selection()) * (state.pc() - state.pc.prev()));                      //GEN8
                constraints.push_back((1 - step_selection()) * (state.gas() - state.gas.prev()));                    //GEN9
                constraints.push_back((1 - step_selection()) * (state.stack_size() - state.stack_size.prev()));      //GEN10
                constraints.push_back((1 - step_selection()) * (state.memory_size() - state.memory_size.prev()));    //GEN11

                // All transitions between states will be done in opcodes
                // or we are at the end of the circuit
/*              auto partial_state_transition_constraints = generate_transition_constraints(
                    state, generate_frozen_state_transition());
                // the initially problematic constraints are here \/ \/ \/
                for (auto constraint : partial_state_transition_constraints) {
                    constraints.push_back(
                        (1 - last_row_indicator_var) *
                        // ^^^ this fixes the problem from the commented line below
//                        (1 - var(end_selector, 0, true, var::column_type::selector)) *
                        (1 - step_selection_next_var) * constraint);
                }*/
                return constraints;
            }

            void init_opcodes(circuit_type &circuit, columns_manager_type &col_manager) {
                // add all the implemented opcodes here
                // STOP
                opcodes[zkevm_opcode::ADD] = std::make_shared<zkevm_add_sub_operation<BlueprintFieldType>>(true);
                opcodes[zkevm_opcode::MUL] = std::make_shared<zkevm_mul_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::SUB] = std::make_shared<zkevm_add_sub_operation<BlueprintFieldType>>(false);
                opcodes[zkevm_opcode::DIV] = std::make_shared<zkevm_div_mod_operation<BlueprintFieldType>>(true);
                opcodes[zkevm_opcode::SDIV] = std::make_shared<zkevm_sdiv_smod_operation<BlueprintFieldType>>(true);
                opcodes[zkevm_opcode::MOD] = std::make_shared<zkevm_div_mod_operation<BlueprintFieldType>>(false);
                opcodes[zkevm_opcode::SMOD] = std::make_shared<zkevm_sdiv_smod_operation<BlueprintFieldType>>(false);
                opcodes[zkevm_opcode::ADDMOD] = std::make_shared<zkevm_addmod_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::MULMOD] = std::make_shared<zkevm_mulmod_operation<BlueprintFieldType>>();
                // EXP
                opcodes[zkevm_opcode::SIGNEXTEND] = std::make_shared<zkevm_signextend_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::LT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_LT);
                opcodes[zkevm_opcode::GT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_GT);
                opcodes[zkevm_opcode::SLT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_SLT);
                opcodes[zkevm_opcode::SGT] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_SGT);
                opcodes[zkevm_opcode::EQ] = std::make_shared<zkevm_cmp_operation<BlueprintFieldType>>(cmp_type::C_EQ);
                opcodes[zkevm_opcode::ISZERO] = std::make_shared<zkevm_iszero_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::AND] = std::make_shared<zkevm_bitwise_operation<BlueprintFieldType>>(bitwise_type::B_AND);
                opcodes[zkevm_opcode::OR] = std::make_shared<zkevm_bitwise_operation<BlueprintFieldType>>(bitwise_type::B_OR);
                opcodes[zkevm_opcode::XOR] = std::make_shared<zkevm_bitwise_operation<BlueprintFieldType>>(bitwise_type::B_XOR);
                opcodes[zkevm_opcode::NOT] = std::make_shared<zkevm_not_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::BYTE] = std::make_shared<zkevm_byte_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::SHL] = std::make_shared<zkevm_shl_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::SHR] = std::make_shared<zkevm_shr_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::SAR] = std::make_shared<zkevm_sar_operation<BlueprintFieldType>>();

                // Memory operations
                opcodes[zkevm_opcode::MSTORE] = std::make_shared<zkevm_mstore_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::MLOAD] = std::make_shared<zkevm_mload_operation<BlueprintFieldType>>();

                // Storage operations
                opcodes[zkevm_opcode::SLOAD] = std::make_shared<zkevm_sstore_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::SSTORE] = std::make_shared<zkevm_sload_operation<BlueprintFieldType>>();

                // CALL operaitions
                opcodes[zkevm_opcode::CALLVALUE] = std::make_shared<zkevm_callvalue_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::CALLDATASIZE] = std::make_shared<zkevm_calldatasize_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::CALLDATALOAD] = std::make_shared<zkevm_calldataload_operation<BlueprintFieldType>>();

                // PC operations
                opcodes[zkevm_opcode::JUMPI] = std::make_shared<zkevm_jumpi_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::JUMP] = std::make_shared<zkevm_jumpi_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::JUMPDEST] = std::make_shared<zkevm_jumpdest_operation<BlueprintFieldType>>();

                opcodes[zkevm_opcode::PUSH0] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(0);
                opcodes[zkevm_opcode::PUSH1] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(1);
                opcodes[zkevm_opcode::PUSH2] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(2);
                opcodes[zkevm_opcode::PUSH3] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(3);
                opcodes[zkevm_opcode::PUSH4] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(4);
                opcodes[zkevm_opcode::PUSH5] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(5);
                opcodes[zkevm_opcode::PUSH6] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(6);
                opcodes[zkevm_opcode::PUSH7] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(7);
                opcodes[zkevm_opcode::PUSH8] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(8);
                opcodes[zkevm_opcode::PUSH9] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(9);
                opcodes[zkevm_opcode::PUSH10] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(10);
                opcodes[zkevm_opcode::PUSH11] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(11);
                opcodes[zkevm_opcode::PUSH12] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(12);
                opcodes[zkevm_opcode::PUSH13] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(13);
                opcodes[zkevm_opcode::PUSH14] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(14);
                opcodes[zkevm_opcode::PUSH15] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(15);
                opcodes[zkevm_opcode::PUSH16] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(16);
                opcodes[zkevm_opcode::PUSH17] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(17);
                opcodes[zkevm_opcode::PUSH18] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(18);
                opcodes[zkevm_opcode::PUSH19] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(19);
                opcodes[zkevm_opcode::PUSH20] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(20);
                opcodes[zkevm_opcode::PUSH21] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(21);
                opcodes[zkevm_opcode::PUSH22] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(22);
                opcodes[zkevm_opcode::PUSH23] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(23);
                opcodes[zkevm_opcode::PUSH24] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(24);
                opcodes[zkevm_opcode::PUSH25] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(25);
                opcodes[zkevm_opcode::PUSH26] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(26);
                opcodes[zkevm_opcode::PUSH27] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(27);
                opcodes[zkevm_opcode::PUSH28] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(28);
                opcodes[zkevm_opcode::PUSH29] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(29);
                opcodes[zkevm_opcode::PUSH30] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(30);
                opcodes[zkevm_opcode::PUSH31] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(31);
                opcodes[zkevm_opcode::PUSH32] = std::make_shared<zkevm_pushx_operation<BlueprintFieldType>>(32);

                opcodes[zkevm_opcode::POP] = std::make_shared<zkevm_pop_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::RETURN] = std::make_shared<zkevm_return_operation<BlueprintFieldType>>();

                // DUP
                opcodes[zkevm_opcode::DUP1] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(1);
                opcodes[zkevm_opcode::DUP2] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(2);
                opcodes[zkevm_opcode::DUP3] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(3);
                opcodes[zkevm_opcode::DUP4] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(4);
                opcodes[zkevm_opcode::DUP5] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(5);
                opcodes[zkevm_opcode::DUP6] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(6);
                opcodes[zkevm_opcode::DUP7] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(7);
                opcodes[zkevm_opcode::DUP8] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(8);
                opcodes[zkevm_opcode::DUP9] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(9);
                opcodes[zkevm_opcode::DUP10] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(10);
                opcodes[zkevm_opcode::DUP11] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(11);
                opcodes[zkevm_opcode::DUP12] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(12);
                opcodes[zkevm_opcode::DUP13] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(13);
                opcodes[zkevm_opcode::DUP14] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(14);
                opcodes[zkevm_opcode::DUP15] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(15);
                opcodes[zkevm_opcode::DUP16] = std::make_shared<zkevm_dupx_operation<BlueprintFieldType>>(16);

                // SWAP
                opcodes[zkevm_opcode::SWAP1] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(1);
                opcodes[zkevm_opcode::SWAP2] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(2);
                opcodes[zkevm_opcode::SWAP3] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(3);
                opcodes[zkevm_opcode::SWAP4] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(4);
                opcodes[zkevm_opcode::SWAP5] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(5);
                opcodes[zkevm_opcode::SWAP6] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(6);
                opcodes[zkevm_opcode::SWAP7] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(7);
                opcodes[zkevm_opcode::SWAP8] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(8);
                opcodes[zkevm_opcode::SWAP9] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(9);
                opcodes[zkevm_opcode::SWAP10] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(10);
                opcodes[zkevm_opcode::SWAP11] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(11);
                opcodes[zkevm_opcode::SWAP13] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(13);
                opcodes[zkevm_opcode::SWAP14] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(14);
                opcodes[zkevm_opcode::SWAP15] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(15);
                opcodes[zkevm_opcode::SWAP16] = std::make_shared<zkevm_swapx_operation<BlueprintFieldType>>(16);

                // fake opcodes for errors and padding
                opcodes[zkevm_opcode::err0] = std::make_shared<zkevm_err0_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::padding] = std::make_shared<zkevm_padding_operation<BlueprintFieldType>>();

                const std::size_t range_check_table_index = circuit.get_reserved_indices().at("chunk_16_bits/full");

                std::vector<constraint_type> middle_constraints;
                std::vector<constraint_type> first_constraints;
                std::vector<constraint_type> last_constraints;

                std::vector<lookup_constraint_type> middle_lookup_constraints;

                // TODO: This should be checked for all transactions' first opcode. Not only for the first row.
                first_constraints.push_back(state.stack_size); // stack size at start is 0.
                                                                          // NB: no need for range checks before first real transition,
                                                                          // it's all ensured by "frozen" transition constraints.
                first_constraints.push_back(state.step_selection - 1); // first step is step selection

                col_manager.allocate_selector_column(); // Start
                col_manager.allocate_selector_column(); // End
                col_manager.allocate_selector_column(); // Middle

                start_selector = circuit.add_gate(first_constraints);

//                middle_constraints.push_back(state.last_row_indicator.prev());
                // ensure that stack_size is always between 0 and max_stack_size.
                // This allows simpler transitions of stack size without the need to control validity of updated stack size

                // TODO: stack size validity will be checked by RW table.
//                middle_lookup_constraints.push_back({range_check_table_index, { state.stack_size } });
//                middle_lookup_constraints.push_back({range_check_table_index, { state.stack_size + 65535 - max_stack_size } });

                // TODO: proper end constraints zkevm_padding_operation
                last_constraints.push_back(state.last_row_indicator.prev() - 1);
                end_selector = circuit.add_gate(last_constraints);

                std::vector<std::size_t> opcode_range_checked_cols;

                const std::size_t opcodes_amount = opcodes_info_instance.get_opcodes_amount();
                const std::size_t state_selector_cols_amount =
                    state_selector_type::get_manifest(opcodes_amount,true).witness_amount->max_value_if_sat();

                for (std::size_t i = 0; i < state_selector_cols_amount; i++) {
                    state_selector_cols.push_back(col_manager.allocate_witness_column());
                }
                for(std::size_t i = 0; i < opcode_range_checked_cols_amount; i++) {
                    opcode_range_checked_cols.push_back(col_manager.allocate_witness_column());
                }

                opcode_cols = opcode_range_checked_cols; // range-checked columns are the first part of opcode columns

                for (std::size_t i = 0; i < opcode_other_cols_amount; i++) { // followed by some non-range-checked columns
                    opcode_cols.push_back(col_manager.allocate_witness_column());
                }
                state_selector = std::make_shared<state_selector_type>(
                    state_selector_cols, std::array<std::uint32_t, 0>({}), std::array<std::uint32_t, 0>({}),
                    opcodes_amount,true
                );
                state.option = state_selector->option_variable();

                auto state_selector_constraints = state_selector->generate_constraints();

                const std::size_t opcode_row_selection_cols_amount =
                    state_selector_type::get_manifest(max_opcode_height,false).witness_amount->max_value_if_sat();
                for (std::size_t i = 0; i < opcode_row_selection_cols_amount; i++) {
                    opcode_row_selection_cols.push_back(col_manager.allocate_witness_column());
                }
                opcode_row_selector = std::make_shared<state_selector_type>(
                    opcode_row_selection_cols, std::array<std::uint32_t, 0>({}), std::array<std::uint32_t, 0>({}),
                    max_opcode_height,false);
                auto opcode_row_selector_constraints = opcode_row_selector->generate_constraints();

                if (state_selector->is_compressed) {
                    // for a compressed state selector we rely upon opcode_row_selector parity data to apply constraints once in 2 rows
                    var parity_var = opcode_row_selector->parity_variable();
                    for(auto constraint : state_selector_constraints) {
                        middle_constraints.push_back(constraint * parity_var);
                    }
                } else {
                    middle_constraints.insert(middle_constraints.end(), state_selector_constraints.begin(), state_selector_constraints.end());
                }

                middle_constraints.insert(middle_constraints.end(), opcode_row_selector_constraints.begin(),
                                          opcode_row_selector_constraints.end());

                auto generic_state_transition_constraints = generate_generic_transition_constraints(
                    start_selector, end_selector);
                middle_constraints.insert(
                    middle_constraints.end(), generic_state_transition_constraints.begin(), generic_state_transition_constraints.end()
                );

                // "unconditional" range checks for some opcode columns
                for(std::size_t i = 0; i < opcode_range_checked_cols_amount; i++) {
                    middle_lookup_constraints.push_back({range_check_table_index,
                        {var(opcode_range_checked_cols[i], 0 ,true, var::column_type::witness) } });
                }

                using gate_id_type = gate_id<BlueprintFieldType>;
                std::map<gate_id_type, constraint_type> constraint_list;
                std::map<gate_id_type, constraint_type> virtual_selector;

                constraint_type opcode_first_line_constraint;
                constraint_type stack_size_transitions;
                constraint_type gas_transitions;

                for (auto opcode_it : opcodes) {
                    std::size_t opcode_height = opcode_it.second->rows_amount();
                    std::cout << "Gates for " << opcode_to_string(opcode_it.first) << std::endl;

                    if (opcode_height > max_opcode_height) {
                        BOOST_ASSERT("Opcode height exceeds maximum, please update max_opcode_height constant.");
                    }
                    // force opcode height to be always even
                    std::size_t adj_opcode_height = opcode_height + (opcode_height % 2);

                    std::size_t opcode_num = opcodes_info_instance.get_opcode_number(opcode_it.first);
                    auto  curr_opt_constraint = state_selector->option_constraint(opcode_num),
                        curr_opt_constraint_even = state_selector->option_constraint_even(opcode_num), // Why do we need it?
                        curr_opt_constraint_odd = state_selector->option_constraint_odd(opcode_num);   // Why do we need it?

                    // save constraints to ensure later that internal row number has proper value at the start of the opcode
                    opcode_first_line_constraint +=
                        curr_opt_constraint * (opcode_row_selector->option_variable() - (adj_opcode_height - 1));
                    // ^^^ curr_opt_constraint is in _odd_ version because it's applied
                    // at row with internal number adj_opcode_height-1, that always odd

                    // save constraints to ensure correct updates of stack size
                    // TODO: Done for each opcode individually
                    // Static case will be hardcoded in zkevm_operatoin
                    /* stack_size_transitions += curr_opt_constraint_even * (state.stack_size
                                                    - opcodes_info_instance.get_opcode_stack_input(opcode_it.first)
                                                    + opcodes_info_instance.get_opcode_stack_output(opcode_it.first)
                                                    - state.stack_size.next());*/
                    // curr_opt_constraint is in _even_ version because it's applied at row with internal number 0

                    // save constraints to ensure correct updates of remaining gas NB: only static costs now! TODO: include dynamic costs
                    // TODO: Done for each opcode individually
                    // Static case will be hardcoded in zkevm_operatoin
                    /*if( !opcodes_info_instance.is_opcode_dynamic(opcode_it.first) ) {
                        gas_transitions += curr_opt_constraint_even * (state.gas
                            - opcodes_info_instance.get_opcode_cost(opcode_it.first)
                            - state.gas.next());
                    }*/
                    // curr_opt_constraint is in _even_ version because it's applied at row with internal number 0

                    auto opcode_gates = opcode_it.second->generate_gates(*this);
                    for (auto gate_it : opcode_gates) {
                        switch (gate_it.first) {
                            case zkevm_opcode_gate_class::FIRST_OP:
                                for (auto constraint_pair : gate_it.second.first) {
                                    std::size_t local_row = constraint_pair.first;
                                    constraint_type curr_opt_constraint =
                                        (local_row % 2 == 0) ? curr_opt_constraint_even : curr_opt_constraint_odd;
                                    constraint_type constraint = get_opcode_row_constraint(local_row, adj_opcode_height)
                                                                     * constraint_pair.second;

                                    constraint_list[gate_id_type(constraint_pair.second)] = constraint_pair.second;
                                    virtual_selector[gate_id_type(constraint_pair.second)] +=
                                        get_opcode_row_constraint(local_row, adj_opcode_height) * curr_opt_constraint * start_selector;
                                }
                                for (auto lookup_constraint_pair : gate_it.second.second) {
                                    std::size_t local_row = lookup_constraint_pair.first;
                                    constraint_type curr_opt_constraint =
                                        (local_row % 2 == 0) ? curr_opt_constraint_even : curr_opt_constraint_odd;
                                    lookup_constraint_type lookup_constraint = lookup_constraint_pair.second;
                                    auto lookup_table = lookup_constraint.table_id;
                                    auto lookup_expressions = lookup_constraint.lookup_input;
                                    constraint_type row_selector = get_opcode_row_constraint(local_row, adj_opcode_height);
                                    std::vector<constraint_type> new_lookup_expressions;

                                    for(auto lookup_expr : lookup_expressions) {
                                        new_lookup_expressions.push_back(curr_opt_constraint * lookup_expr * row_selector * start_selector);
                                    }
                                    middle_lookup_constraints.push_back({lookup_table, new_lookup_expressions});
                                }
                                break;
                            case zkevm_opcode_gate_class::MIDDLE_OP:
                                std::cout << "Middle constraints from " << opcode_to_string(opcode_it.first) << std::endl;
                                for (auto constraint_pair : gate_it.second.first) {
                                    std::cout << "\t" << constraint_pair.first << ": " << constraint_pair.second << std::endl;
                                    std::size_t local_row = constraint_pair.first;
                                    if(local_row > 1) continue;
                                    if( opcode_it.second->rows_amount() % 2 ) local_row++;
                                    //constraint_type curr_opt_constraint =
                                    //    (local_row % 2 == 0) ? curr_opt_constraint_odd : curr_opt_constraint_even;
                                    constraint_type row_constraint = get_opcode_row_constraint(local_row, adj_opcode_height)
                                                                    * constraint_pair.second;

                                    constraint_list[gate_id_type(constraint_pair.second)] = constraint_pair.second;
                                    virtual_selector[gate_id_type(constraint_pair.second)] +=
                                        get_opcode_row_constraint(local_row, adj_opcode_height) * curr_opt_constraint;
                                }
                                for (auto lookup_constraint_pair : gate_it.second.second) {
                                    std::size_t local_row = lookup_constraint_pair.first;
                                    //constraint_type curr_opt_constraint =
                                    //    (local_row % 2 == 0) ? curr_opt_constraint_even : curr_opt_constraint_odd;
                                    lookup_constraint_type lookup_constraint = lookup_constraint_pair.second;
                                    auto lookup_table = lookup_constraint.table_id;
                                    auto lookup_expressions = lookup_constraint.lookup_input;
                                    constraint_type row_selector = get_opcode_row_constraint(local_row, adj_opcode_height);
                                    std::vector<constraint_type> new_lookup_expressions;

                                    for(auto lookup_expr : lookup_expressions) {
                                        new_lookup_expressions.push_back(curr_opt_constraint * lookup_expr * row_selector);
                                    }
                                    middle_lookup_constraints.push_back({lookup_table, new_lookup_expressions});
                                }
                                break;
                            case zkevm_opcode_gate_class::LAST_OP:
                                BOOST_ASSERT("Unimplemented");
                                break;
                            case zkevm_opcode_gate_class::NOT_LAST_OP:
                                BOOST_ASSERT("Unimplemented");
                                break;
                            default:
                                BOOST_ASSERT("Unknown gate class");
                        }
                    }
                }
                // ensure first line of each opcode has correct internal row number
                middle_constraints.push_back(opcode_first_line_constraint * state.step_selection());

                // ensure the last line of each opcode updates stack_size and gas correctly
//                middle_constraints.push_back(stack_size_transitions * state.step_selection.next());
//                middle_constraints.push_back(gas_transitions * state.step_selection.next());

                // increase program counter, unless the opcode is JUMP or JUMPI
//                middle_constraints.push_back((state.pc() + 1 - state.pc.next())
//                    * (1 - state_selector->option_constraint_even(opcodes_info_instance.get_opcode_number(zkevm_opcode::JUMP))
//                         - state_selector->option_constraint_even(opcodes_info_instance.get_opcode_number(zkevm_opcode::JUMPI)))
//                    * state.step_selection.next());
                // TODO: JUMP and JUMPI need special constraints for program counter
                // we also need to check that they are followed by either JUMPDEST or an error opcode

                for(const auto c : virtual_selector) {
                    constraint_type constraint = constraint_list[c.first];
                    middle_constraints.push_back(constraint * c.second);
                }

                middle_selector = circuit.add_gate(middle_constraints);
                circuit.add_lookup_gate(middle_selector, middle_lookup_constraints);
            }

            zkevm_state_type state;
            // static selectors used to mark the places where the circuit starts/ends and when the circuit is acitve
            std::size_t start_selector;
            std::size_t end_selector;
            std::size_t middle_selector;
            // selectors for dynamic tables
            std::size_t bytecode_selector;
            // witness columns for opcodes
            std::vector<std::size_t> opcode_cols;
            // dynamic selectors for the state selector circuit
            std::vector<std::size_t> state_selector_cols;
            // columns for selecting specific rows from the opcode
            std::vector<std::size_t> opcode_row_selection_cols;
            // ---------------------------------------------------------------------------------------------
            // |Variables below this point are internal to the object and do not go into the actual circuit|
            // ---------------------------------------------------------------------------------------------
            // reference to the assignment/circuit objects

            assignment_type &assignment;
            // information about opcode metadata (mapping, etc.)
            const opcodes_info &opcodes_info_instance;
            std::shared_ptr<state_selector_type> state_selector;
            std::shared_ptr<state_selector_type> opcode_row_selector;
            // opcode objects
            std::map<zkevm_opcode, std::shared_ptr<zkevm_operation<BlueprintFieldType>>> opcodes;
            // start and end rows for the circuit; both have to be fixed
            std::size_t max_rows; // Should be odd number because all opcodes has even rows amount and last row is also used by last_row selector
            std::size_t start_row_index;
            std::size_t end_row_index;
            typename lookup_library<BlueprintFieldType>::left_reserved_type lookup_tables_indices;

            static const std::size_t opcode_range_checked_cols_amount = 32;
            static const std::size_t opcode_other_cols_amount = 16;
            static const std::size_t max_opcode_cols = opcode_range_checked_cols_amount + opcode_other_cols_amount;
            static const std::size_t max_opcode_height = 8;
            static const std::size_t max_stack_size = 1024;
            static const std::size_t dynamic_tables_amount = 1;
            std::vector<std::uint32_t> bytecode_witnesses;
        };
        template<typename BlueprintFieldType>
        const std::size_t zkevm_circuit<BlueprintFieldType>::max_opcode_height;
        template<typename BlueprintFieldType>
        const std::size_t zkevm_circuit<BlueprintFieldType>::max_stack_size;
    }   // namespace blueprint
}   // namespace nil