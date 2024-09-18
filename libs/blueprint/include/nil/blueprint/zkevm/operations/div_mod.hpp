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

#include <numeric>
#include <algorithm>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/zkevm_operation.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType>
        class zkevm_operation;

        template<typename BlueprintFieldType>
        class zkevm_div_mod_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using zkevm_table_type = typename op_type::zkevm_table_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_div_mod_operation(bool _is_div) : is_div(_is_div) {
                this->stack_input = 2;
                this->stack_output = 1;
                this->gas_cost = 5;
            }

            bool is_div;

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
            T first_carryless_construct(
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

            template<typename T>
            T third_carryless_construct(
                const std::vector<T> &b_64_chunks, const std::vector<T> &r_64_chunks
            ) const {
                return
                    (r_64_chunks[1] * b_64_chunks[3] + r_64_chunks[2] * b_64_chunks[2] +
                     r_64_chunks[3] * b_64_chunks[1]) +
                    two_64 * (r_64_chunks[2] * b_64_chunks[3] + r_64_chunks[3] * b_64_chunks[2]);
            }

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

                // The central relation is a = br + q, q < b.
                // For b = 0 we must assure r = 0. For the MOD operation we should
                // have q = 0 if b = 0, so we use a special q_out value.
                //
                // Table layout:                                                Internal row #:
                // +--------------------------------+--------+--+--------------------+---+
                // |                a               |   c1   |c2|                    |   | 3
                // +--------------------------------+--------+--+---+--------+-------+---+
                // |                b               |               |   t    |       |1/B| 2
                // +--------------------------------+---------------+--------+-------+---+
                // |                r               |                 q              |   | 1
                // +--------------------------------+--------------------------------+---+
                // |                v               |  q_out (optional, for MOD)     |   | 0
                // +--------------------------------+--------------------------------+---+

                std::size_t position_1 = 2;

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
                for (std::size_t i = chunk_amount; i < chunk_amount + 4; i++) {
                    c_1_chunks.push_back(var_gen(i, -1));
                }
                var c_2 = var_gen(chunk_amount + 4, -1);
                var b_sum_inverse_1 = var_gen(2*chunk_amount, 0);

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
                // inverse or zero for b_sum_inverse
                constraint_type b_sum_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_sum_1 += b_chunks_1[i];
                }
                constraints.push_back({position_1, b_sum_inverse_1 * (b_sum_inverse_1 * b_sum_1 - 1)});
                constraints.push_back({position_1, b_sum_1 * (b_sum_inverse_1 * b_sum_1 - 1)});
                // prove that the multiplication + addition is correct
                constraint_type first_carryless = first_carryless_construct<constraint_type>(
                    a_64_chunks, b_64_chunks_1, r_64_chunks_1, q_64_chunks_1);
                constraints.push_back({position_1, (first_carryless - c_1_64 * two128 - c_2 * two192)});
                constraint_type second_carryless = second_carryless_construct<constraint_type>(
                    a_64_chunks, b_64_chunks_1, r_64_chunks_1, q_64_chunks_1);
                constraints.push_back({position_1, (second_carryless + c_1_64 + c_2 * two_64)});
                // add constraints: c_2 is 0/1
                constraints.push_back({position_1, c_2 * (c_2 - 1)});

                constraint_type third_carryless = third_carryless_construct<constraint_type>(b_64_chunks_1, r_64_chunks_1);
                constraints.push_back({position_1, third_carryless});
                constraints.push_back({position_1, b_64_chunks_1[3] * r_64_chunks_1[3]}); // forth_carryless

                // force r = 0 if b = 0
                constraint_type b_zero = 1 - b_sum_inverse_1 * b_sum_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    constraints.push_back({position_1, b_zero * r_chunks_1[i]});
                }

                // prove that (q < b) or (b = r = 0)
                // note that in the latter case we have q = a to satisfy a = br + q
                std::size_t position_2 = 1;
                std::vector<var> b_chunks_2;
                std::vector<var> q_chunks_2;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_chunks_2.push_back(var_gen(i, -1));
                }
                var b_sum_inverse_2 = var_gen(2*chunk_amount, -1);
                for (std::size_t i = chunk_amount; i < 2 * chunk_amount; i++) {
                    q_chunks_2.push_back(var_gen(i, 0));
                }
                std::vector<var> v_chunks_2;
                std::vector<var> t;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    v_chunks_2.push_back(var_gen(i, +1));
                }
                for (std::size_t i = chunk_amount + 6; i < chunk_amount + 6 + carry_amount; i++) {
                    t.push_back(var_gen(i, -1));
                }
                constraint_type b_sum_2;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_sum_2 += b_chunks_2[i];
                }
                constraint_type b_nonzero = b_sum_inverse_2 * b_sum_2;

                // q < b <=> b + v = q + 2^T, i.e. the last carry is 1.
                // We use t to store the addition carries and enforce the above constraint
                // if b != 0
                auto carry_on_addition_constraint = [](var a_0, var a_1, var a_2,
                                                       var b_0, var b_1, var b_2,
                                                       var r_0, var r_1, var r_2,
                         var last_carry, var result_carry, bool first_constraint = false) {
                    constraint_type res;
                    if (first_constraint) {
                        // no last carry for first constraint
                        res = (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                                - r_0 - r_1 * two_16 - r_2 * two_32 - result_carry * two_48;
                    } else {
                        res = last_carry + (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                                - r_0 - r_1 * two_16 - r_2 * two_32 - result_carry * two_48;
                    }
                    return res;
                };
                auto last_carry_on_addition_constraint = [](var a_0, var b_0, var r_0, var last_carry, var result_carry) {
                    constraint_type res = (last_carry + a_0 + b_0 - r_0 - result_carry * two_16);
                    return res;
                };
                constraints.push_back({position_2, carry_on_addition_constraint(b_chunks_2[0], b_chunks_2[1], b_chunks_2[2],
                                                                                v_chunks_2[0], v_chunks_2[1], v_chunks_2[2],
                                                                                q_chunks_2[0], q_chunks_2[1], q_chunks_2[2],
                                                                                t[0],t[0],true)});
                constraints.push_back({position_2, t[0] * (1 - t[0])}); // t[0] is 0 or 1
                for (std::size_t i = 1; i < carry_amount - 1; i++) {
                     constraints.push_back({position_2, carry_on_addition_constraint(
                                                                   b_chunks_2[3*i], b_chunks_2[3*i + 1], b_chunks_2[3*i + 2],
                                                                   v_chunks_2[3*i], v_chunks_2[3*i + 1], v_chunks_2[3*i + 2],
                                                                   q_chunks_2[3*i], q_chunks_2[3*i + 1], q_chunks_2[3*i + 2],
                                                                   t[i-1],t[i])});
                     constraints.push_back({position_2, t[i] * (1 - t[i])}); // t[i] is 0 or 1
                }
                constraints.push_back({position_2, last_carry_on_addition_constraint(
                                                                        b_chunks_2[3*(carry_amount-1)],
                                                                        v_chunks_2[3*(carry_amount-1)],
                                                                        q_chunks_2[3*(carry_amount-1)],
                                                                        t[carry_amount - 2], t[carry_amount - 1])});
                // t[carry_amount-1] is 0 or 1, but should be 1 if b_nonzero = 1
                constraints.push_back({position_2, (b_nonzero  + (1 - b_nonzero)* t[carry_amount-1]) * (1 - t[carry_amount-1])});

                // for MOD only
                if (!is_div) {
                    std::vector<var> q_out_chunks;
                    for (std::size_t i = chunk_amount; i < 2 * chunk_amount; i++) {
                        q_out_chunks.push_back(var_gen(i, +1));
                    }
                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        constraints.push_back({position_2, (b_nonzero*(q_chunks_2[i] - q_out_chunks[i]) + (1-b_nonzero)*q_out_chunks[i])});
                    }
                }

                return {{gate_class::MIDDLE_OP, {constraints, {}}}};
            }

            void generate_assignments(zkevm_table_type &zkevm_table, const zkevm_machine_interface &machine) override {
                using word_type = typename zkevm_stack::word_type;
                zkevm_stack stack = machine.stack;
                word_type a = stack.pop();
                word_type b = stack.pop();
                using integral_type = boost::multiprecision::number<
                    boost::multiprecision::backends::cpp_int_modular_backend<257>>;
                integral_type r_integral = b != 0u ? integral_type(a) / integral_type(b) : 0u;
                word_type r = word_type::backend_type(r_integral.backend());
                word_type q = b != 0u ? a % b : a;
                word_type q_out = b != 0u ? q : 0; // according to EVM spec a % 0 = 0

                bool t_last = integral_type(q) < integral_type(b);
                word_type v = word_type(integral_type(q) + integral_type(t_last)*zkevm_modulus - integral_type(b));

                word_type result = is_div ? r : q_out;

                const std::vector<value_type> a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b);
                const std::vector<value_type> r_chunks = zkevm_word_to_field_element<BlueprintFieldType>(r);
                const std::vector<value_type> q_chunks = zkevm_word_to_field_element<BlueprintFieldType>(q);
                const std::vector<value_type> v_chunks = zkevm_word_to_field_element<BlueprintFieldType>(v);
                const std::vector<value_type> q_out_chunks = zkevm_word_to_field_element<BlueprintFieldType>(q_out);

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
                const std::vector<std::size_t> &witness_cols = zkevm_table.get_opcode_cols();
                assignment_type &assignment = zkevm_table.get_assignment();
                const std::size_t curr_row = zkevm_table.get_current_row();
                // caluclate first row carries
                auto first_row_carries =
                    first_carryless_construct(a_64_chunks, b_64_chunks, r_64_chunks, q_64_chunks).data >> 128;
                value_type c_1 = static_cast<value_type>(first_row_carries & (two_64 - 1).data);
                value_type c_2 = static_cast<value_type>(first_row_carries >> 64);
                std::vector<value_type> c_1_chunks = chunk_64_to_16<BlueprintFieldType>(c_1);
                // no need for c_2 chunks as there is only a single chunk

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
                assignment.witness(witness_cols[2*chunk_amount], curr_row + 1) = b_sum == 0 ? 0 : b_sum.inversed();

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 2) = r_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 2) = q_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 3) = v_chunks[i];
                }
                bool carry = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + b_chunks[3 * i    ] + v_chunks[3 * i    ] +
                                    (b_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                                    (b_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32 ) >= two_48;
                    assignment.witness(witness_cols[chunk_amount + 6 + i], curr_row + 1) = carry;
                }
                carry = (carry + b_chunks[3 * (carry_amount - 1)] + v_chunks[3 * (carry_amount - 1)]) >= two_16;
                assignment.witness(witness_cols[chunk_amount + 6 + carry_amount - 1], curr_row + 1) = carry;

                // optional part, for MOD only
                if (!is_div) {
                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        assignment.witness(witness_cols[i + chunk_amount], curr_row + 3) = q_out_chunks[i];
                    }
                }

                // stack.push(b);
                // stack.push(a);
                stack.push(result);
            }

            std::size_t rows_amount() override {
                return 4;
            }
        };
    }   // namespace blueprint
}   // namespace nil