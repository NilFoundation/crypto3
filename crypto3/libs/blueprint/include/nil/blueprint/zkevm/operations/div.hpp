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
        class zkevm_div_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_div_operation() {}

            constexpr static const std::size_t carry_amount = 16 / 3 + 1;
            constexpr static const value_type two_16 = 65536;
            constexpr static const value_type two_32 = 4294967296;
            constexpr static const value_type two_48 = 281474976710656;
            constexpr static const value_type two_64 = 0x10000000000000000_cppui_modular254;
            constexpr static const value_type two128 = 0x100000000000000000000000000000000_cppui_modular254;
            constexpr static const value_type two192 = 0x1000000000000000000000000000000000000000000000000_cppui_modular254;

            template<typename T, typename V = T>
            T chunk_sum_64(const std::vector<V> &chunks, const unsigned char chunk_idx) const {
                BOOST_ASSERT(chunk_idx < 4);
                return chunks[4 * chunk_idx] + chunks[4 * chunk_idx + 1] * two_16 +
                       chunks[4 * chunk_idx + 2] * two_32 + chunks[4 * chunk_idx + 3] * two_48;
            }

                        template<typename T>
            T first_carryless_consrtruct(
                const std::vector<T> &a_64_chunks, const std::vector<T> &b_64_chunks,
                const std::vector<T> &r_64_chunks, const std::vector<T> &q_64_chunks
            ) const {
                return
                    r_64_chunks[0] * b_64_chunks[0] + q_64_chunks[0] +
                    two_64 * (r_64_chunks[0] * b_64_chunks[1] + r_64_chunks[1] * b_64_chunks[0] + q_64_chunks[1])
                    - a_64_chunks[0] - two_64 * a_64_chunks[1];
            }

            template<typename T>
            T second_carryless_construct(
                const std::vector<T> &a_64_chunks, const std::vector<T> &b_64_chunks,
                const std::vector<T> &r_64_chunks, const std::vector<T> &q_64_chunks
            ) const {
                return
                    (r_64_chunks[0] * b_64_chunks[2] + r_64_chunks[1] * b_64_chunks[1] +
                     r_64_chunks[2] * b_64_chunks[0] + q_64_chunks[2] - a_64_chunks[2]) +
                    two_64 * (r_64_chunks[0] * b_64_chunks[3] + r_64_chunks[1] * b_64_chunks[2] +
                              r_64_chunks[2] * b_64_chunks[1] + r_64_chunks[3] * b_64_chunks[0] +
                              q_64_chunks[3] - a_64_chunks[3]);
            }

            std::map<gate_class, std::vector<constraint_type>> generate_gates(zkevm_circuit_type &zkevm_circuit) override {
                std::vector<constraint_type> constraints;
                constexpr const std::size_t chunk_amount = 16;
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                auto var_gen = [&witness_cols](std::size_t i, int32_t offset = 0) {
                    return zkevm_operation<BlueprintFieldType>::var_gen(witness_cols, i, offset);
                };
                const std::size_t range_check_table_index =
                    zkevm_circuit.get_circuit().get_reserved_indices().at("chunk_16_bits/full");
                constraint_type position_1 = zkevm_circuit.get_opcode_row_constraint(2, this->rows_amount());
                std::vector<var> a_chunks;
                std::vector<var> b_chunks_1;
                // we have two different constraints at two different positions
                // first we prove division or zero
                std::vector<var> r_chunks_1;
                std::vector<var> q_chunks_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    a_chunks.push_back(var_gen(i, -1));
                    b_chunks_1.push_back(var_gen(i, 0));
                    r_chunks_1.push_back(var_gen(i, +1));
                    q_chunks_1.push_back(var_gen(i + chunk_amount, +1));
                }
                std::vector<var> c_1_chunks;
                std::vector<var> c_3_chunks;
                for (std::size_t i = chunk_amount; i < chunk_amount + 4; i++) {
                    c_1_chunks.push_back(var_gen(i, -1));
                    c_3_chunks.push_back(var_gen(i, 0));
                }
                var c_2 = var_gen(chunk_amount + 4, -1);
                var c_4 = var_gen(chunk_amount + 4, 0);
                var b_sum_inverse_1 = var_gen(chunk_amount + 5, 0);
                std::vector<constraint_type> a_64_chunks = {
                    chunk_sum_64<constraint_type, var>(a_chunks, 0),
                    chunk_sum_64<constraint_type, var>(a_chunks, 1),
                    chunk_sum_64<constraint_type, var>(a_chunks, 2),
                    chunk_sum_64<constraint_type, var>(a_chunks, 3)
                };
                std::vector<constraint_type> b_64_chunks_1 = {
                    chunk_sum_64<constraint_type, var>(b_chunks_1, 0),
                    chunk_sum_64<constraint_type, var>(b_chunks_1, 1),
                    chunk_sum_64<constraint_type, var>(b_chunks_1, 2),
                    chunk_sum_64<constraint_type, var>(b_chunks_1, 3)
                };
                std::vector<constraint_type> r_64_chunks_1 = {
                    chunk_sum_64<constraint_type, var>(r_chunks_1, 0),
                    chunk_sum_64<constraint_type, var>(r_chunks_1, 1),
                    chunk_sum_64<constraint_type, var>(r_chunks_1, 2),
                    chunk_sum_64<constraint_type, var>(r_chunks_1, 3)
                };
                std::vector<constraint_type> q_64_chunks_1 = {
                    chunk_sum_64<constraint_type, var>(q_chunks_1, 0),
                    chunk_sum_64<constraint_type, var>(q_chunks_1, 1),
                    chunk_sum_64<constraint_type, var>(q_chunks_1, 2),
                    chunk_sum_64<constraint_type, var>(q_chunks_1, 3)
                };
                constraint_type c_1_64 = chunk_sum_64<constraint_type, var>(c_1_chunks, 0);
                constraint_type c_3_64 = chunk_sum_64<constraint_type, var>(c_3_chunks, 0);
                // inverse or zero for b_sum_inverse
                constraint_type b_sum_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_sum_1 += b_chunks_1[i];
                }
                constraints.push_back(position_1 * b_sum_inverse_1 * (b_sum_inverse_1 * b_sum_1 - 1));
                constraints.push_back(position_1 * b_sum_1 * (b_sum_inverse_1 * b_sum_1 - 1));
                // prove that the multiplication + addition is correct
                constraint_type first_carryless = first_carryless_consrtruct<constraint_type>(
                    a_64_chunks, b_64_chunks_1, r_64_chunks_1, q_64_chunks_1);
                constraints.push_back(position_1 * (first_carryless - c_1_64 * two128 - c_2 * two192));
                constraint_type second_carryless = second_carryless_construct<constraint_type>(
                    a_64_chunks, b_64_chunks_1, r_64_chunks_1, q_64_chunks_1);
                constraints.push_back(
                    position_1 * (second_carryless + c_1_64 + c_2 * two_64 - c_3_64 * two128 - c_4 * two192));
                // add constraints for c_2/c_4: c_2 is 0/1, c_4 is 0/1/2/3
                constraints.push_back(position_1 * c_2 * (c_2 - 1));
                constraints.push_back(position_1 * c_4 * (c_4 - 1) * (c_4 - 2) * (c_4 - 3));
                // TODO: figure out how to add lookup constraints to constrain chunks of q
                // force r = 0 if b = 0
                constraint_type b_zero = 1 - b_sum_inverse_1 * b_sum_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    constraints.push_back(position_1 * b_zero * r_chunks_1[i]);
                }

                // prove that q < result or b = r = 0
                // note that in this case we do not care about the value of q in this case and can
                // just set it to be equal to a
                constraint_type position_2 = zkevm_circuit.get_opcode_row_constraint(1, this->rows_amount());
                std::vector<var> b_chunks_2;
                std::vector<var> q_chunks_2;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_chunks_2.push_back(var_gen(i, -1));
                }
                var b_sum_inverse_2 = var_gen(chunk_amount + 5, -1);
                for (std::size_t i = chunk_amount; i < 2 * chunk_amount; i++) {
                    q_chunks_2.push_back(var_gen(i, 0));
                }
                std::vector<var> t;
                std::vector<var> v;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    t.push_back(var_gen(i, +1));
                }
                for (std::size_t i = chunk_amount; i < 2 * chunk_amount; i++) {
                    v.push_back(var_gen(i, +1));
                }
                constraint_type b_sum_2;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_sum_2 += b_chunks_2[i];
                }
                constraint_type b_nonzero = b_sum_inverse_2 * b_sum_2;
                // t_i = t_{i+1} + (1 - t_{i+1}) * v_i * (r_i - q_i)
                // and v_i is inverse or zero of b_i - q_i
                // first constraint is special as we start from zero: t_{-1} = 0
                // TODO: figure out how to add lookup constraints to constrain delta
                constraint_type delta = b_chunks_2[chunk_amount - 1] - q_chunks_2[chunk_amount - 1];
                constraints.push_back(position_2 * b_nonzero * (t[chunk_amount - 1] - v[chunk_amount - 1] * delta));
                constraints.push_back(position_2 * b_nonzero * v[chunk_amount - 1] * (v[chunk_amount - 1] * delta - 1));
                constraints.push_back(position_2 * b_nonzero * delta * (v[chunk_amount - 1] * delta - 1));
                for (int32_t i = chunk_amount - 2; i >= 0; i--) {
                    delta = b_chunks_2[i] - q_chunks_2[i];
                    constraints.push_back(position_2 * b_nonzero * (t[i] - t[i + 1] - (1 - t[i + 1]) * v[i] * delta));
                    constraints.push_back(position_2 * b_nonzero * (v[i] * (v[i] * delta - 1)));
                    constraints.push_back(position_2 * b_nonzero * (delta * (v[i] * delta - 1)));
                }
                // last t should be 1, as we have a strict inequality
                constraints.push_back(position_2 * b_nonzero * (t[0] - 1));

                return {{gate_class::MIDDLE_OP, constraints}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                using word_type = typename zkevm_stack::word_type;
                zkevm_stack &stack = machine.stack;
                word_type a = stack.pop();
                word_type b = stack.pop();
                using integral_type = boost::multiprecision::number<
                    boost::multiprecision::backends::cpp_int_modular_backend<257>>;
                integral_type result_integral = b != 0u ? integral_type(a) / integral_type(b) : 0u;
                word_type result = word_type::backend_type(result_integral.backend());
                word_type q = b != 0u ? a % b : a;

                const std::vector<value_type> a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b);
                const std::vector<value_type> r_chunks = zkevm_word_to_field_element<BlueprintFieldType>(result);
                const std::vector<value_type> q_chunks = zkevm_word_to_field_element<BlueprintFieldType>(q);
                const std::size_t chunk_amount = a_chunks.size();
                // note that we don't assign 64-chunks for a/b, as we can build them from 16-chunks with constraints
                // under the same logic we only assign the 16-bit chunks for carries
                std::vector<value_type> a_64_chunks, b_64_chunks, r_64_chunks, q_64_chunks;
                for (std::size_t i = 0; i < 4; i++) {
                    a_64_chunks.push_back(chunk_sum_64<value_type>(a_chunks, i));
                    b_64_chunks.push_back(chunk_sum_64<value_type>(b_chunks, i));
                    r_64_chunks.push_back(chunk_sum_64<value_type>(r_chunks, i));
                    q_64_chunks.push_back(chunk_sum_64<value_type>(q_chunks, i));
                }
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                assignment_type &assignment = zkevm_circuit.get_assignment();
                const std::size_t curr_row = zkevm_circuit.get_current_row();
                // caluclate first row carries
                auto first_row_carries =
                    first_carryless_consrtruct(a_64_chunks, b_64_chunks, r_64_chunks, q_64_chunks).data >> 128;
                value_type c_1 = static_cast<value_type>(first_row_carries & (two_64 - 1).data);
                value_type c_2 = static_cast<value_type>(first_row_carries >> 64);
                std::vector<value_type> c_1_chunks = chunk_64_to_16<BlueprintFieldType>(c_1);
                // no need for c_2 chunks as there is only a single chunk
                auto second_row_carries =
                    (second_carryless_construct(a_64_chunks, b_64_chunks, r_64_chunks, q_64_chunks)
                     + c_1 + c_2 * two_64).data >> 128;
                value_type c_3 = static_cast<value_type>(second_row_carries & (two_64 - 1).data);
                value_type c_4 = static_cast<value_type>(second_row_carries >> 64);
                std::vector<value_type> c_3_chunks = chunk_64_to_16<BlueprintFieldType>(c_3);
                value_type b_sum = std::accumulate(b_chunks.begin(), b_chunks.end(), value_type(0));
                // TODO: replace with memory access, which would also do range checks!
                // also we can pack slightly more effectively
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row) = a_chunks[i];
                }
                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row) = c_1_chunks[i];
                }
                assignment.witness(witness_cols[4 + chunk_amount], curr_row) = c_2;

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 1) = b_chunks[i];
                }
                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 1) = c_3_chunks[i];
                }
                assignment.witness(witness_cols[4 + chunk_amount], curr_row + 1) = c_4;
                assignment.witness(witness_cols[5 + chunk_amount], curr_row + 1) =
                    b_sum == 0 ? 0 : b_sum.inversed();

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 2) = r_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 2) = q_chunks[i];
                }
                // comparison bit calculations
                bool t_val = false;
                for (int32_t i = chunk_amount - 1; i >= 0; i--) {
                    assignment.witness(witness_cols[i], curr_row + 3) =
                        t_val = t_val || (b_chunks[i] > q_chunks[i]);
                }
                // inverse calculations
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 3) =
                        (b_chunks[i] - q_chunks[i]) != 0 ?
                            1 * (b_chunks[i] - q_chunks[i]).inversed()
                            : 0;
                }

                // reset the machine state; hope that we won't have to do this manually
                stack.push(b);
                stack.push(a);
            }

            std::size_t rows_amount() override {
                return 4;
            }
        };
    }   // namespace blueprint
}   // namespace nil
