//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/zkevm_operation.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType>
        class zkevm_operation;

        template<typename BlueprintFieldType>
        class zkevm_table;

        template<typename BlueprintFieldType>
        class zkevm_jumpi_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using zkevm_table_type = typename op_type::zkevm_table_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;
            using state_var = state_var<BlueprintFieldType>;

            zkevm_jumpi_operation() {
                this->stack_input = 2;
                this->stack_output = 0;
                this->gas_cost = 10;
            }

            constexpr static const value_type two_16 = 65536;
            constexpr static const value_type two_32 = 4294967296;
            constexpr static const value_type two_48 = 281474976710656;
            constexpr static const value_type two_64 = 0x10000000000000000_cppui_modular254;
            constexpr static const value_type two128 = 0x100000000000000000000000000000000_cppui_modular254;
            constexpr static const value_type two192 = 0x1000000000000000000000000000000000000000000000000_cppui_modular254;

            // Table layout                                             Row #
            // +------------------+-+----------------+---+--------------+
            // |    condition     |r|                |1/A|  dest |      | 0
            // +------------------+-+----------------+---+--------------+

            struct jumpi_map{
                jumpi_map(std::vector<std::size_t> W, std::size_t range_checked_cols_amount = 32){
                    for(std::size_t i = 0; i < 16; i++){
                        chunks[i] = var(W[i],0); // No rotations used, so, use just var instead of state_var
                    }
                    non_zero = state_var(W[17]);
                    dest = state_var(W[18]);

                    // dest will be range checked by the bytecode table.
                    // but range_checks are free. So we place it to range check columns
                    s_inv = state_var(W[range_checked_cols_amount]);
                }
                std::array<var,16> chunks;
                state_var non_zero;
                state_var s_inv;
                state_var dest;
            };

            std::map<gate_class, std::pair<
                std::vector<std::pair<std::size_t, constraint_type>>,
                std::vector<std::pair<std::size_t, lookup_constraint_type>>
            >>   generate_gates(zkevm_circuit_type &zkevm_circuit) override {
                // TODO : add lookups
                // 2 lookups to RW circuit
                // Lookup to bytecode with JUMPDEST

                auto witness_cols = zkevm_circuit.get_opcode_cols();
                std::size_t range_checked_cols_amount = zkevm_circuit.get_opcode_range_checked_cols_amount();
                jumpi_map m(witness_cols, range_checked_cols_amount);

                std::vector<std::pair<std::size_t, constraint_type>> constraints;

                // May be checked not all chunks but lower for example
                // Should be checked for EVM
                constraint_type sum_constraint;
                for(std::size_t i = 0; i < m.chunks.size(); i++){
                    sum_constraint += m.chunks[i];
                }
                constraints.push_back({0, m.non_zero() * 1 - m.non_zero()});
                constraints.push_back({0, m.non_zero() - sum_constraint * m.s_inv()});
                return {{gate_class::MIDDLE_OP, {constraints, {}}}};
            }

            void generate_assignments(zkevm_table_type &zkevm_table, const zkevm_machine_interface &machine) override {
                zkevm_word_type dest = machine.stack_top();
                zkevm_word_type condition = machine.stack_top(1);
                const std::vector<value_type> chunks = zkevm_word_to_field_element<BlueprintFieldType>(condition);

                assignment_type &assignment = zkevm_table.get_assignment();
                const std::size_t curr_row = zkevm_table.get_current_row();
                auto witness_cols = zkevm_table.get_opcode_cols();
                std::size_t range_checked_cols_amount = zkevm_table.get_opcode_range_checked_cols_amount();

                jumpi_map m(witness_cols, range_checked_cols_amount);

                // TODO: replace with memory access, which would also do range checks!
                value_type c = 0;
                for (std::size_t i = 0; i < chunks.size(); i++) {
                    assignment.witness(m.chunks[i].index, curr_row) = chunks[i];
                    c += chunks[i];
                }
                assignment.witness(m.non_zero.index, curr_row) = (c != 0);
                assignment.witness(m.s_inv.index, curr_row) = (c==0 ? 0 : c.inversed());
                assignment.witness(m.dest.index, curr_row) = w_lo<BlueprintFieldType>(dest);
            }

            virtual constraint_type pc_transition(const zkevm_circuit_type &zkevm_circuit) override{
                // pc_transition switched on opcode's last row. All meaningful data is placed on 0-th row.
                // So, we'll have -1 rotation
                auto witness_cols = zkevm_circuit.get_opcode_cols();
                std::size_t range_checked_cols_amount = zkevm_circuit.get_opcode_range_checked_cols_amount();
                const auto &state = zkevm_circuit.get_state();
                constraint_type c;

                jumpi_map m(witness_cols, range_checked_cols_amount);
                c = state.pc.next() - m.non_zero.prev() * m.dest.prev() - (1 - m.non_zero.prev()) * (state.pc() + 1);
                return c;
            }

            std::size_t rows_amount() override {
                return 1;
            }
        };
    }   // namespace blueprint
}   // namespace nil
