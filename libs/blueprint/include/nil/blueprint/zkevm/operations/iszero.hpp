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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/zkevm_operation.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType>
        class zkevm_iszero_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_iszero_operation() = default;

            std::map<gate_class, std::vector<constraint_type>> generate_gates(zkevm_circuit_type &zkevm_circuit) override {
                std::vector<constraint_type> constraints;
                constexpr const std::size_t chunk_amount = 16;
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                auto var_gen = [&witness_cols](std::size_t i, int32_t offset = 0) {
                    return zkevm_operation<BlueprintFieldType>::var_gen(witness_cols, i, offset);
                };
                constraint_type chunk_sum = var_gen(0);
                std::size_t i = 1;
                for (; i < chunk_amount; i++) {
                    chunk_sum += var_gen(i);
                }
                var result = var_gen(i++);
                for (; i < 2 * chunk_amount; i++) {
                    // force other chunks to be zero
                    constraints.emplace_back(var_gen(i));
                }
                var chunk_sum_inverse = var_gen(i);
                constraints.emplace_back(chunk_sum * chunk_sum_inverse + result - 1);
                constraints.emplace_back(chunk_sum * result);
                return {{gate_class::MIDDLE_OP, constraints}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                zkevm_stack &stack = machine.stack;
                using word_type = typename zkevm_stack::word_type;
                word_type a = stack.pop();
                const std::vector<value_type> chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                assignment_type &assignment = zkevm_circuit.get_assignment();
                std::size_t i = 0;
                const std::size_t curr_row = zkevm_circuit.get_current_row();
                // TODO: replace with memory access
                for (; i < chunks.size(); i++) {
                    assignment.witness(witness_cols[i], curr_row) = chunks[i];
                }
                if (a == 0u) {
                    assignment.witness(witness_cols[i], curr_row) = 1;
                } else {
                    assignment.witness(witness_cols[i], curr_row) = 0;
                }
                i++;
                for (; i < 2 * chunks.size(); i++) {
                    assignment.witness(witness_cols[i], curr_row) = 0;
                }
                const value_type chunk_sum = std::accumulate(chunks.begin(), chunks.end(), value_type::zero());
                assignment.witness(witness_cols[i], curr_row) =
                    chunk_sum == 0 ? value_type::zero() : value_type::one() * chunk_sum.inversed();
                // reset the machine state; hope that we won't have to do this manually
                stack.push(a);
            }

            std::size_t rows_amount() override {
                return 1;
            }
        };
    }   // namespace blueprint
}   // namespace nil
