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
        class zkevm_shr_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

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
                std::vector<std::pair<std::size_t, lookup_constraint_type>> lookup_constraints;

                constexpr const std::size_t chunk_amount = 16;
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                auto var_gen = [&witness_cols](std::size_t i, int32_t offset = 0) {
                    return zkevm_operation<BlueprintFieldType>::var_gen(witness_cols, i, offset);
                };
                const std::size_t range_check_table_index = zkevm_circuit.get_circuit().get_reserved_indices().at("chunk_16_bits/full");

                // The central relation is a = br + q, q < b.
                // For b = 0 we must assure r = 0.
                //
                // Table layout:                                                                 Internal row #:
                // +--------------------------------+--------+--+--------------------+---+------------+
                // |                a               |   c1   |c2|                    |1/B|            | 4
                // +--------------------------------+--------+--+--------------------+---+------------+
                // |                r               |                 q              |                | 3
                // +--------------------------------+--------------------------------+--+--+----------+
                // |                b               |                 v              |I1|I2|          | 2
                // +--------------------------------+---+---+----+-----+-+--+-------++--+--+----------+
                // |             input_b            |b0'|b0"|b0"'|     |z|tp|   t   || (j - b0')^{-1} | 1
                // +--------------------------------+---+---+----+-----+-+--+-------++----------------+
                // |                                |                                | (j - b0")^{-1} | 0
                // +--------------------------------+--------------------------------+----------------+


                std::size_t position_1 = 3;
                std::vector<var> a_chunks;
                std::vector<var> b_chunks_1;
                // we have two different constraints at two different positions
                // first we prove division or zero
                std::vector<var> r_chunks_1;
                std::vector<var> q_chunks_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    a_chunks.push_back(var_gen(i, -1));
                    r_chunks_1.push_back(var_gen(i, 0));
                    b_chunks_1.push_back(var_gen(i, +1));
                    q_chunks_1.push_back(var_gen(i + chunk_amount, 0));
                }
                std::vector<var> c_1_chunks;
                for (std::size_t i = chunk_amount; i < chunk_amount + 4; i++) {
                    c_1_chunks.push_back(var_gen(i, -1));
                }
                var c_2 = var_gen(chunk_amount + 4, -1);
                var b_sum_inverse_1 = var_gen(2*chunk_amount, -1);

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
                std::size_t position_2 = 2;
                std::vector<var> b_chunks_2;
                std::vector<var> q_chunks_2;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_chunks_2.push_back(var_gen(i, 0));
                }
                for (std::size_t i = chunk_amount; i < 2 * chunk_amount; i++) {
                    q_chunks_2.push_back(var_gen(i, -1));
                }
                std::vector<var> v_chunks_2;
                std::vector<var> t;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    v_chunks_2.push_back(var_gen(chunk_amount + i, 0));
                }

                for (std::size_t i = chunk_amount + 6; i < chunk_amount + 7 + carry_amount; i++) {
                    t.push_back(var_gen(i, +1));
                }
                var z_var_2 = var_gen(chunk_amount + 5, +1);

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
                // t[carry_amount-1] is 0 or 1, but should be 1 if z_var_2 = 1
                constraints.push_back({position_2, (z_var_2  + (1 - z_var_2)* t[carry_amount-1]) * (1 - t[carry_amount-1])});

                std::size_t position_3 = 1;
                std::vector<var> input_b_chunks;
                std::vector<var> indic_1;
                std::vector<var> indic_2;
                std::vector<var> b_chunks_3;
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    b_chunks_3.push_back(var_gen(i, -1));
                    input_b_chunks.push_back(var_gen(i, 0));
                    indic_1.push_back(var_gen(2*chunk_amount + i, 0));
                    indic_2.push_back(var_gen(2*chunk_amount + i, +1));
                }

                var b0p_var = var_gen(chunk_amount, 0),
                    b0pp_var = var_gen(chunk_amount + 1, 0),
                    b0ppp_var = var_gen(chunk_amount + 2, 0),
                    I1_var = var_gen(2*chunk_amount, -1),
                    I2_var = var_gen(2*chunk_amount + 1, -1),
                    z_var = var_gen(chunk_amount + 5, 0),
                    tp_var = var_gen(chunk_amount + 5, 0);

                // lookup constrain b0p < 16, b0pp < 16, b0ppp < 256
                lookup_constraints.push_back({position_3, {range_check_table_index, {4096 * b0p_var}}});
                lookup_constraints.push_back({position_3, {range_check_table_index, {4096 * b0pp_var}}});
                lookup_constraints.push_back({position_3, {range_check_table_index, {256 * b0ppp_var}}});
                constraints.push_back({position_3, (input_b_chunks[0] - b0p_var - 16*b0pp_var - 256*b0ppp_var)});
                constraints.push_back({position_3, b0ppp_var * (1 - b0ppp_var * I1_var)});

                constraint_type sum_part_b;
                for(std::size_t i = 1; i < chunk_amount; i++) {
                    sum_part_b += input_b_chunks[i];
                }
                constraints.push_back({position_3, sum_part_b * (1 - sum_part_b * I2_var)});
                constraints.push_back({position_3, (z_var - (1 - b0ppp_var * I1_var) * (1 - sum_part_b * I2_var))});

                for(std::size_t j = 0; j < chunk_amount; j++) {
                    constraints.push_back({position_3, (b0p_var - j)*(1 - (b0p_var - j) * indic_1[j])});
                    constraints.push_back({position_3, (b0pp_var - j)*(1 - (b0pp_var - j) * indic_2[j])});
                }

                constraint_type two_powers;
                unsigned int pow = 1;
                for(std::size_t j = 0; j < chunk_amount; j++) {
                    two_powers += (1 - (b0p_var - j)*indic_1[j])*pow;
                    pow *= 2;
                }
                constraints.push_back({position_3, (tp_var - z_var * two_powers)});

                for(std::size_t j = 0; j < chunk_amount; j++) {
                    constraints.push_back({position_3, (b_chunks_3[j] - tp_var * (1 - (b0pp_var - j)*indic_2[j]))});
                }

                return {{gate_class::MIDDLE_OP, {constraints, lookup_constraints}}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                zkevm_stack &stack = machine.stack;
                using word_type = typename zkevm_stack::word_type;
                using integral_type = boost::multiprecision::number<
                    boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                word_type a = stack.pop();
                word_type input_b = stack.pop();

                int shift = (integral_type(input_b) < 256) ? int(integral_type(input_b)) : 256;
                integral_type r_integral = integral_type(a) << shift;

                word_type b = word_type(integral_type(1) << shift);

                word_type result = word_type::backend_type(r_integral.backend());
                word_type q = b != 0u ? a % b : a;

                bool t_last = integral_type(q) < integral_type(b);
                word_type v = word_type(integral_type(q) + integral_type(t_last)*zkevm_modulus - integral_type(b));

                const std::vector<value_type> a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b);
                const std::vector<value_type> r_chunks = zkevm_word_to_field_element<BlueprintFieldType>(result);
                const std::vector<value_type> q_chunks = zkevm_word_to_field_element<BlueprintFieldType>(q);
                const std::vector<value_type> v_chunks = zkevm_word_to_field_element<BlueprintFieldType>(v);
                const std::vector<value_type> input_b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(input_b);

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

                assignment.witness(witness_cols[2*chunk_amount], curr_row) = b_sum == 0 ? 0 : b_sum.inversed();

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 1) = r_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 1) = q_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 2) = b_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 2) = v_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 3) = input_b_chunks[i];
                }
                value_type b0p   = integral_type(input_b) % 16,
                           b0pp  = (integral_type(input_b) / 16) % 16,
                           b0ppp = (integral_type(input_b) % 65536) / 256,
                           I1    = b0ppp.is_zero() ? 0 : b0ppp.inversed();

                value_type sum_part_b = 0;
                for(std::size_t i = 1; i < chunk_amount; i++) {
                    sum_part_b += input_b_chunks[i];
                }
                value_type I2 = sum_part_b.is_zero() ? 0 : sum_part_b.inversed(),
                           z = (1 - b0ppp * I1) * (1 - sum_part_b * I2), // z is zero if input_b >= 256, otherwise it is 1
                           tp = z * (static_cast<unsigned int>(1) << int(integral_type(input_b) % 16));

                assignment.witness(witness_cols[chunk_amount], curr_row + 3) = b0p;
                assignment.witness(witness_cols[chunk_amount + 1], curr_row + 3) = b0pp;
                assignment.witness(witness_cols[chunk_amount + 2], curr_row + 3) = b0ppp;
                assignment.witness(witness_cols[2*chunk_amount], curr_row + 2) = I1;
                assignment.witness(witness_cols[2*chunk_amount + 1], curr_row + 2) = I2;
                assignment.witness(witness_cols[chunk_amount + 5], curr_row + 3) = z;
                assignment.witness(witness_cols[chunk_amount + 6], curr_row + 3) = tp;

                bool carry = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + b_chunks[3 * i    ] + v_chunks[3 * i    ] +
                                    (b_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                                    (b_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32 ) >= two_48;
                    assignment.witness(witness_cols[chunk_amount + 7 + i], curr_row + 3) = carry; // the t's
                }
                carry = (carry + b_chunks[3 * (carry_amount - 1)] + v_chunks[3 * (carry_amount - 1)]) >= two_16;
                assignment.witness(witness_cols[chunk_amount + 7 + carry_amount - 1], curr_row + 3) = carry;

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[2*chunk_amount + i], curr_row + 3) = (b0p - i).is_zero()? 0 : (b0p - i).inversed();
                    assignment.witness(witness_cols[2*chunk_amount + i], curr_row + 4) = (b0pp - i).is_zero()? 0 : (b0pp - i).inversed();
                }

                // stack.push(input_b);
                // stack.push(a);
                stack.push(result);
            }

            std::size_t rows_amount() override {
                return 5;
            }
        };
    }   // namespace blueprint
}   // namespace nil
