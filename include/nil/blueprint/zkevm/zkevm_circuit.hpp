//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <nil/blueprint/zkevm/state.hpp>
#include <nil/blueprint/zkevm/state_selector.hpp>
#include <nil/blueprint/zkevm/zkevm_opcodes.hpp>

#include <nil/blueprint/zkevm/operations/iszero.hpp>
#include <nil/blueprint/zkevm/operations/add_sub.hpp>
#include <nil/blueprint/zkevm/operations/mul.hpp>
#include <nil/blueprint/zkevm/operations/div.hpp>

namespace nil {
    namespace blueprint {
        // abstracts control over column indices
        // selectors are already tracked by circuit object by default
        // we implement only automatic extension of the amount of colunmns taken for convinience
        template<typename BlueprintFieldType>
        class selector_manager {
        public:
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using assignment_type = nil::blueprint::assignment<arithmetization_type>;
            using circuit_type = nil::blueprint::circuit<arithmetization_type>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;

            selector_manager(assignment_type &assignment_, circuit_type &circuit_)
                : assignment(assignment_), circuit(circuit_),
                  witness_index(0), constant_index(0) {}

            std::size_t allocate_witess_column() {
                if (witness_index >= assignment.witnesses_amount()) {
                    assignment.resize_witnesses(2 * witness_index);
                }
                return witness_index++;
            }

            std::size_t allocate_constant_column() {
                if (constant_index >= assignment.constants_amount()) {
                    assignment.resize_constants(2 * constant_index);
                }
                return constant_index++;
            }

            template<typename T>
            std::size_t add_gate(const T &args) {
                std::size_t selector = circuit.add_gate(args);
                if (selector >= assignment.selectors_amount()) {
                    assignment.resize_selectors(selector + 1);
                }
                return selector;
            }
        private:
            assignment_type &assignment;
            circuit_type &circuit;
            std::size_t witness_index;
            std::size_t constant_index;
        };

        template<typename BlueprintFieldType>
        class zkevm_operation;

        template<typename BlueprintFieldType>
        class zkevm_circuit {
        public:
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using assignment_type = nil::blueprint::assignment<arithmetization_type>;
            using circuit_type = nil::blueprint::circuit<arithmetization_type>;
            using state_var_type = state_var<BlueprintFieldType>;
            using zkevm_state_type = zkevm_state<BlueprintFieldType>;
            using selector_manager_type = selector_manager<BlueprintFieldType>;
            using zkevm_operation_type = zkevm_operation<BlueprintFieldType>;
            using zkevm_opcode_gate_class = typename zkevm_operation<BlueprintFieldType>::gate_class;
            using state_selector_type = components::state_selector<arithmetization_type, BlueprintFieldType>;
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename crypto3::zk::snark::plonk_variable<value_type>;

            std::map<std::string, std::size_t> zkevm_circuit_lookup_tables() const {
                std::map<std::string, std::size_t> lookup_tables;
                lookup_tables["chunk_16_bits/full"] = 0;
                return lookup_tables;
            }

            zkevm_circuit(assignment_type &assignment_, circuit_type &circuit_, std::size_t start_row_index_ = 1)
                :assignment(assignment_), circuit(circuit_), opcodes_info_instance(opcodes_info::instance()),
                 sel_manager(assignment_, circuit_),
                 curr_row(start_row_index_), start_row_index(start_row_index_) {

                BOOST_ASSERT_MSG(start_row_index > 0,
                    "Start row index must be greater than zero, otherwise some gates would access non-existent rows.");
                for (auto &lookup_table : zkevm_circuit_lookup_tables()) {
                    circuit.reserve_table(lookup_table.first);
                }
                init_state();
                init_opcodes();
            }

            void assign_state() {
                state.assign_state(assignment, curr_row);
            }

            void finalize_test() {
                finalize();
                // this is done in order for the vizualiser export to work correctly before padding the circuit.
                // otherwise constraints try to access non-existent rows
                assignment.witness(state_selector->W(0), curr_row) = value_type(0xC0FFEE);
            }

            void finalize() {
                BOOST_ASSERT_MSG(curr_row != 0, "Row underflow in finalization");
                assignment.enable_selector(end_selector, curr_row - 1);
            }

            void assign_opcode(const zkevm_opcode opcode, zkevm_machine_interface &machine) {
                auto opcode_it = opcodes.find(opcode);
                if (opcode_it == opcodes.end()) {
                    BOOST_ASSERT_MSG(false, (std::string("Unimplemented opcode: ") + opcode_to_string(opcode)) != "");
                }
                opcode_it->second->generate_assignments(*this, machine);
                // state management
                state.step_selection.value = 1;
                state.rows_until_next_op.value = opcode_it->second->rows_amount() - 1;
                state.rows_until_next_op_inv.value =
                    state.rows_until_next_op.value == 0 ? 0 : state.rows_until_next_op.value.inversed();
                advance_rows(opcode, opcode_it->second->rows_amount());
            }

            void advance_rows(const zkevm_opcode opcode, std::size_t rows) {
                assignment.enable_selector(middle_selector, curr_row, curr_row + rows - 1);
                // TODO: figure out what is going to happen on state change
                value_type opcode_val = opcodes_info_instance.get_opcode_value(opcode);
                for (std::size_t i = 0; i < rows; i++) {
                    // TODO: switch to real bytecode
                    assignment.witness(state_selector->W(0), curr_row) = opcode_val;
                    components::generate_assignments(
                        *state_selector, assignment,
                        {var(state_selector->W(0), curr_row, false, var::column_type::witness)}, curr_row);
                    assignment.witness(opcode_row_selector->W(0), curr_row) = state.rows_until_next_op.value;
                    components::generate_assignments(
                        *opcode_row_selector, assignment,
                        {var(opcode_row_selector->W(0), curr_row, false, var::column_type::witness)}, curr_row);
                    assign_state();
                    if (i == 0) {
                        state.step_selection.value = 0;
                    }
                    assignment.witness(state_selector->W(0), curr_row) = opcode_val;
                    state.rows_until_next_op.value = state.rows_until_next_op.value - 1;
                    state.rows_until_next_op_inv.value = state.rows_until_next_op.value == 0 ?
                        0 : state.rows_until_next_op.value.inversed();
                    curr_row++;
                }
            }

            zkevm_state_type &get_state() {
                return state;
            }

            selector_manager_type &get_selector_manager() {
                return sel_manager;
            }

            const std::vector<std::size_t> &get_state_selector_cols() {
                return state_selector_cols;
            }

            const std::vector<std::size_t> &get_opcode_cols() {
                return opcode_cols;
            }

            std::size_t get_current_row() const {
                return curr_row;
            }

            assignment_type &get_assignment() {
                return assignment;
            }

            circuit_type &get_circuit() {
                return circuit;
            }

            // for opcode constraints at certain row of opcode execution
            // note that rows are counted "backwards", starting from opcode rows amount minus one
            // and ending in zero
            constraint_type get_opcode_row_constraint(std::size_t row, std::size_t opcode_height) const {
                BOOST_ASSERT(row < opcode_height);
                var height_var = state.rows_until_next_op.variable();
                var height_var_inv = state.rows_until_next_op_inv.variable();
                // ordering here is important: minimising the degree when possible
                if (row == opcode_height - 1) {
                    return state.step_selection.variable();
                }
                if (row == opcode_height - 2) {
                    return state.step_selection.variable(-1);
                }
                if (row == 0) {
                    return 1 - height_var * height_var_inv;
                }
                // TODO: this is probably possible to optimise
                return opcode_row_selector->option_constraint(row);
            }

        private:
            void init_state() {
                state.pc = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 1);
                state.stack_size = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.memory_size = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.curr_gas = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.rows_until_next_op = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.rows_until_next_op_inv = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 0);
                state.step_selection = state_var_type(
                   sel_manager.allocate_witess_column(), state_var_type::column_type::witness, 1);
            }

            std::vector<constraint_type> generate_generic_transition_constraints(
                std::size_t start_selector,
                std::size_t end_selector
            ) {
                std::vector<constraint_type> constraints;

                auto rows_until_next_op_var = state.rows_until_next_op.variable();
                auto rows_until_next_op_prev_var = state.rows_until_next_op.variable(-1);
                auto rows_until_next_op_next_var = state.rows_until_next_op.variable(+1);
                auto rows_until_next_op_inv_var = state.rows_until_next_op_inv.variable();
                auto rows_until_next_op_inv_prev_var = state.rows_until_next_op_inv.variable(-1);
                auto step_selection_var = state.step_selection.variable();
                auto step_selection_next_var = state.step_selection.variable(+1);
                auto option_variable = state_selector->option_variable(0);
                auto option_variable_prev = state_selector->option_variable(-1);
                // inverse or zero for rows_until_next_op/rows_until_next_op_inv
                constraints.push_back(
                    rows_until_next_op_var * rows_until_next_op_var * rows_until_next_op_inv_var
                    - rows_until_next_op_var);
                constraints.push_back(
                    (rows_until_next_op_var * rows_until_next_op_inv_var - 1) * rows_until_next_op_inv_var);
                // rows_until_next_op decrementing (unless we are at the last row of opcode)
                constraints.push_back(
                    rows_until_next_op_var * (rows_until_next_op_next_var - rows_until_next_op_var + 1));
                // step is copied unless new opcode is next
                constraints.push_back(
                    (1 - step_selection_var) * (option_variable - option_variable_prev));
                // new opcode selection is forced if new opcode is next
                constraints.push_back(
                    (1 - rows_until_next_op_inv_prev_var * rows_until_next_op_prev_var) * (1 - step_selection_var));
                // freeze some of the the state variables unless new opcode is next
                // or we are at the end of the circuit
                auto partial_state_transition_constraints = generate_transition_constraints(
                    state, generate_frozen_state_transition());
                for (auto constraint : partial_state_transition_constraints) {
                    constraints.push_back(
                        (1 - var(end_selector, 0, true, var::column_type::selector)) *
                        (1 - step_selection_next_var) * constraint);
                }
                return constraints;
            }

            void init_opcodes() {
                // add all the implemented opcodes here
                opcodes[zkevm_opcode::ISZERO] = std::make_shared<zkevm_iszero_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::ADD] = std::make_shared<zkevm_add_sub_operation<BlueprintFieldType>>(true);
                opcodes[zkevm_opcode::SUB] = std::make_shared<zkevm_add_sub_operation<BlueprintFieldType>>(false);
                opcodes[zkevm_opcode::MUL] = std::make_shared<zkevm_mul_operation<BlueprintFieldType>>();
                opcodes[zkevm_opcode::DIV] = std::make_shared<zkevm_div_operation<BlueprintFieldType>>();

                std::vector<constraint_type> middle_constraints;
                std::vector<constraint_type> first_constraints;
                std::vector<constraint_type> last_constraints;
                // first step is step selection
                first_constraints.push_back(state.step_selection.variable() - 1);
                start_selector = sel_manager.add_gate(first_constraints);
                // TODO: proper end constraints
                end_selector = circuit.add_gate(last_constraints);

                const std::size_t opcodes_amount = opcodes_info_instance.get_opcodes_amount();
                const std::size_t state_selector_cols_amount =
                    state_selector_type::get_manifest(opcodes_amount).witness_amount->max_value_if_sat();
                for (std::size_t i = 0; i < state_selector_cols_amount; i++) {
                    state_selector_cols.push_back(sel_manager.allocate_witess_column());
                }
                for (std::size_t i = 0; i < max_opcode_cols; i++) {
                    opcode_cols.push_back(sel_manager.allocate_witess_column());
                }
                state_selector = std::make_shared<state_selector_type>(
                    state_selector_cols, std::array<std::uint32_t, 0>({}), std::array<std::uint32_t, 0>({}),
                    opcodes_amount);

                auto state_selector_constraints = state_selector->generate_constraints();
                middle_constraints.insert(middle_constraints.end(), state_selector_constraints.begin(),
                                          state_selector_constraints.end());

                static constexpr std::size_t max_opcode_height = 20;
                const std::size_t opcode_row_selection_cols_amount =
                    state_selector_type::get_manifest(max_opcode_height).witness_amount->max_value_if_sat();
                for (std::size_t i = 0; i < opcode_row_selection_cols_amount; i++) {
                    opcode_row_selection_cols.push_back(sel_manager.allocate_witess_column());
                }
                opcode_row_selector = std::make_shared<state_selector_type>(
                    opcode_row_selection_cols, std::array<std::uint32_t, 0>({}), std::array<std::uint32_t, 0>({}),
                    max_opcode_height);
                auto opcode_row_selector_constraints = opcode_row_selector->generate_constraints();
                middle_constraints.insert(middle_constraints.end(), opcode_row_selector_constraints.begin(),
                                          opcode_row_selector_constraints.end());

                auto generic_state_transition_constraints = generate_generic_transition_constraints(
                    start_selector, end_selector);
                middle_constraints.insert(middle_constraints.end(), generic_state_transition_constraints.begin(),
                                          generic_state_transition_constraints.end());

                for (auto opcode_it : opcodes) {
                    std::size_t opcode_height = opcode_it.second->rows_amount();
                    if (opcode_height > max_opcode_height) {
                        BOOST_ASSERT("Opcode height exceeds maximum, please update max_opcode_height constant.");
                    }

                    std::size_t opcode_num = opcodes_info_instance.get_opcode_value(opcode_it.first);
                    auto curr_opt_constraint = state_selector->option_constraint(opcode_num);
                    // force current height to be proper value at the start of the opcode
                    if (opcode_height == 1) {
                        // minor optimisation here: we have only a single step so can just set 0
                        middle_constraints.push_back(curr_opt_constraint * state.rows_until_next_op.variable());
                    } else {
                        middle_constraints.push_back(
                            curr_opt_constraint * (state.rows_until_next_op.variable() - (opcode_height - 1)) *
                            state.step_selection.variable());
                    }

                    auto opcode_gates = opcode_it.second->generate_gates(*this);
                    for (auto gate_it : opcode_gates) {
                        switch (gate_it.first) {
                            case zkevm_opcode_gate_class::FIRST_OP:
                                for (auto constraint : gate_it.second) {
                                    middle_constraints.push_back(
                                        curr_opt_constraint * constraint * start_selector);
                                }
                                break;
                            case zkevm_opcode_gate_class::MIDDLE_OP:
                                for (auto constraint : gate_it.second) {
                                    middle_constraints.push_back(
                                        curr_opt_constraint * constraint);
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
                middle_selector = sel_manager.add_gate(middle_constraints);

                assignment.enable_selector(start_selector, curr_row);
                assignment.enable_selector(middle_selector, curr_row);
            }

            zkevm_state_type state;
            // static selectors used to mark the places where the circuit starts/ends
            std::size_t start_selector;
            std::size_t end_selector;
            // dynamic selector: indicates when the circuit is acitve
            // currently represented as a selector column; hopefully this is possible to do in practice
            std::size_t middle_selector;
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
            circuit_type &circuit;
            // information about opcode metadata (mapping, etc.)
            const opcodes_info &opcodes_info_instance;
            selector_manager_type sel_manager;
            std::shared_ptr<state_selector_type> state_selector;
            std::shared_ptr<state_selector_type> opcode_row_selector;
            // opcode objects
            std::map<zkevm_opcode, std::shared_ptr<zkevm_operation<BlueprintFieldType>>> opcodes;
            // current row maintained between different calls to the circuit object
            std::size_t curr_row;
            // start and end rows for the circuit; both have to be fixed
            std::size_t start_row_index;
            std::size_t end_row_index;

            static const std::size_t max_opcode_cols = 64;
        };
    }   // namespace blueprint
}   // namespace nil
