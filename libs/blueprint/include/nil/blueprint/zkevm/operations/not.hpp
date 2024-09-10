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

#pragma once

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/zkevm_operation.hpp>

namespace nil {
    namespace blueprint {

        template<typename BlueprintFieldType>
        class zkevm_not_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_not_operation() {}

            constexpr static const std::size_t carry_amount = 16 / 3 + 1;
            constexpr static const value_type two_16 = 65536;
            constexpr static const value_type two_32 = 4294967296;
            constexpr static const value_type two_48 = 281474976710656;
            constexpr static const value_type ffff = two_16 - 1;

            std::map<gate_class, std::pair<
                std::vector<std::pair<std::size_t, constraint_type>>,
                std::vector<std::pair<std::size_t, lookup_constraint_type>>
                >>
                generate_gates(zkevm_circuit_type &zkevm_circuit) override {

                std::vector<std::pair<std::size_t, constraint_type>> constraints;

                constexpr const std::size_t chunk_amount = 16;
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                auto var_gen = [&witness_cols](std::size_t i, int32_t offset = 0) {
                    return zkevm_operation<BlueprintFieldType>::var_gen(witness_cols, i, offset);
                };

                std::size_t position = 0;
                auto constraint_gen = [&constraints, &position]
                        (var a_0, var a_1, var a_2,
                         var b_0, var b_1, var b_2,
                         var last_carry, var result_carry, bool first_constraint = false) {
                    if (first_constraint) {
                        // no last carry for first constraint
                        constraints.push_back({ position, (
                                (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                                - ffff - ffff * two_16 - ffff * two_32 - result_carry * two_48)});
                    } else {
                        constraints.push_back({ position, (
                                last_carry + (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                                - ffff - ffff * two_16 - ffff * two_32 - result_carry * two_48)});
                    }
                    constraints.push_back({position, result_carry * (result_carry - 1)});
                };
                auto last_constraint_gen = [&constraints, &position]
                        (var a_0, var b_0, var last_carry, var result_carry) {
                    constraints.push_back({ position, (last_carry + a_0 + b_0 - ffff - result_carry * two_16)});
                    constraints.push_back({ position, result_carry * (result_carry - 1)});
                };
                std::vector<var> a_chunks;
                std::vector<var> b_chunks;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    a_chunks.push_back(var_gen(i, -1));
                    b_chunks.push_back(var_gen(i, 0));
                }
                std::vector<var> r_carry;
                for (std::size_t i = 0; i < carry_amount; i++) {
                    r_carry.push_back(var_gen(i + chunk_amount, -1));
                }
                // special first constraint
                constraint_gen(a_chunks[0], a_chunks[1], a_chunks[2],
                               b_chunks[0], b_chunks[1], b_chunks[2],
                               r_carry[0], r_carry[0], true);
                for (std::size_t i = 1; i < carry_amount - 1; i++) {
                    constraint_gen(a_chunks[3 * i], a_chunks[3 * i + 1], a_chunks[3 * i + 2],
                                   b_chunks[3 * i], b_chunks[3 * i + 1], b_chunks[3 * i + 2],
                                   r_carry[i - 1], r_carry[i]);
                }
                last_constraint_gen(a_chunks[3 * (carry_amount - 1)], b_chunks[3 * (carry_amount - 1)],
                                    r_carry[carry_amount - 2], r_carry[carry_amount - 1]);

                return {{gate_class::MIDDLE_OP, {constraints, {}}}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                zkevm_stack &stack = machine.stack;
                using word_type = typename zkevm_stack::word_type;
                using integral_type = boost::multiprecision::number<
                    boost::multiprecision::backends::cpp_int_modular_backend<257>>;
                word_type a = stack.pop();
                word_type result = word_type((~integral_type(a)) % zkevm_modulus);

                const std::vector<value_type> a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(result);

                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                assignment_type &assignment = zkevm_circuit.get_assignment();
                const std::size_t curr_row = zkevm_circuit.get_current_row();
                // TODO: replace with memory access, which would also do range checks!
                for (std::size_t i = 0; i < a_chunks.size(); i++) {
                    assignment.witness(witness_cols[i], curr_row) = a_chunks[i];
                }
                for (std::size_t i = 0; i < b_chunks.size(); i++) {
                    assignment.witness(witness_cols[i], curr_row + 1) = b_chunks[i];
                }
                // we might want to pack carries more efficiently?
                bool carry = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + a_chunks[3 * i    ] + b_chunks[3 * i    ] +
                                    (a_chunks[3 * i + 1] + b_chunks[3 * i + 1]) * two_16 +
                                    (a_chunks[3 * i + 2] + b_chunks[3 * i + 2]) * two_32 ) >= two_48;
                    assignment.witness(witness_cols[i + a_chunks.size()], curr_row + 1) = carry;
                }
                carry = (carry + a_chunks[3 * (carry_amount - 1)] + b_chunks[3 * (carry_amount - 1)]) >= two_16;
                assignment.witness(witness_cols[a_chunks.size() + carry_amount - 1], curr_row + 1) = carry;

                stack.push(result);
            }

            std::size_t rows_amount() override {
                return 2;
            }
        };
    }   // namespace blueprint
}   // namespace nil
