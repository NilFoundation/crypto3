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
        class zkevm_sdiv_smod_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_sdiv_smod_operation(bool _is_div) : is_div(_is_div) {}

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

                // The central relation is a = br + q. We also require that sgn(q) = sgn(a) and
                // that |q| < |b| if b != 0.
                // For b = 0 we must assure r = 0. For the SMOD operation we should
                // have q = 0 if b = 0, so we use a special q_out value.
                //
                // Table layout:                                                                              Internal row #:
                // +--------------------------------+--------------------------------+---------------------------+
                // |             b_input            |                                | (a = -2^255) & (b = -1) ? | 5  6
                // +--------------------------------+--------+--+--+--+--+-----------+---------------------------+
                // |                a               |   c1   |c2|ax|bx|qx|           |                           | 4  5
                // +--------------------------------+--------+--+--++-++-++--+-------+---+-----------------------+
                // |                b               |               |a-|b-|q-|  tb   |1/B|                       | 3  4
                // +--------------------------------+---------------+--+--+--+-------+---+-----------------------+
                // |                r               |                 q              |                           | 2  3
                // +--------------------------------+--+--+--+---------+----------+--+---------------------------+
                // |               |b|              |BI|b-|q-|    tq   |    t     |  |                           | 1  2
                // +--------------------------------+--+--+--+---------+----------+--+---------------------------+
                // |        SDIV: v, SMOD: q        |               |q|              |                           | 0  1
                // +--------------------------------+--------------------------------+---------------------------+
                // |            SMOD: v             |          SMOD: q_out           |                           |    0
                // +--------------------------------+--------------------------------+---------------------------+

                std::size_t position_0 = 4 + !is_div; // SMOD has extra row
                std::vector<var> b_input_chunks;
                std::vector<var> a_chunks_0;
                std::vector<var> b_chunks_0;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                     b_input_chunks.push_back(var_gen(i,-1));
                     a_chunks_0.push_back(var_gen(i, 0));
                     b_chunks_0.push_back(var_gen(i, +1));
                }

                var a_inv  = var_gen(2*chunk_amount, -1),
                    b1_inv = var_gen(2*chunk_amount + 1, -1),
                    b2_inv = var_gen(2*chunk_amount + 2, -1),
                    a_ind  = var_gen(2*chunk_amount + 3, -1),
                    b1_ind = var_gen(2*chunk_amount + 4, -1),
                    b2_ind = var_gen(2*chunk_amount + 5, -1),
                    is_overflow = var_gen(2*chunk_amount + 6, -1);

                constraint_type a_sum_0;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    a_sum_0 += a_chunks_0[i];
                }
                a_sum_0 -= 16*65535;
                constraints.push_back({position_0, a_sum_0 * (1 - a_sum_0 * a_inv)});

                constraint_type b_sum_0;
                for(std::size_t i = 0; i < chunk_amount - 1; i++) {
                    b_sum_0 += b_input_chunks[i];
                }
                constraints.push_back({position_0, b_sum_0 * (1 - b_sum_0 * b1_inv)});
                constraints.push_back({position_0, (b_input_chunks[chunk_amount - 1] - 32768)
                                                 * (1 - (b_input_chunks[chunk_amount - 1] - 32768)*b2_inv)});
                constraints.push_back({position_0, (a_ind - (1 - a_sum_0 * a_inv))});
                constraints.push_back({position_0, (b1_ind - (1 - b_sum_0 * b1_inv))});
                constraints.push_back({position_0, (b2_ind - (1 - (b_input_chunks[chunk_amount - 1] - 32768)*b2_inv))});
                constraints.push_back({position_0, (is_overflow - a_ind * b1_ind * b2_ind)});

                // b = is_overflow ? 1 : b_input
                constraints.push_back({position_0, (b_chunks_0[0] - is_overflow - (1-is_overflow)*b_input_chunks[0])});
                for(std::size_t i = 1; i < chunk_amount; i++) {
                    constraints.push_back({position_0, (b_chunks_0[i] - (1-is_overflow)*b_input_chunks[i])});
                }

                std::size_t position_1 = 3 + !is_div; // SMOD has extra row
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

                // signs of a,b and q
                var a_top = a_chunks[chunk_amount - 1],
                    b_top = b_chunks_1[chunk_amount - 1],
                    q_top = q_chunks_1[chunk_amount - 1],
                    a_aux = var_gen(chunk_amount + 5, -1),
                    b_aux = var_gen(chunk_amount + 6, -1),
                    q_aux = var_gen(chunk_amount + 7, -1),
                    a_neg = var_gen(chunk_amount + 6, 0),
                    b_neg = var_gen(chunk_amount + 7, 0),
                    q_neg = var_gen(chunk_amount + 8, 0);
                value_type two_15 = 32768;
                // a_top + 2^15 = a_aux + 2^16 * a_neg
                constraints.push_back({position_1, a_neg * (1 - a_neg)});
                constraints.push_back({position_1, (a_top + two_15 - two_16 * a_neg - a_aux)});
                // b_top + 2^15 = b_aux + 2^16 * b_neg
                constraints.push_back({position_1, b_neg * (1 - b_neg)});
                constraints.push_back({position_1, (b_top + two_15 - two_16 * b_neg - b_aux)});
                // q_top + 2^15 = q_aux + 2^16 * q_neg
                constraints.push_back({position_1, q_neg * (1 - q_neg)});
                constraints.push_back({position_1, (q_top + two_15 - two_16 * q_neg - q_aux)});

                // q = 0 OR sgn(a) = sgn(q) TODO: Recheck for a = -2^255, b = -1 !!!
                constraint_type q_sum_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    q_sum_1 += q_chunks_1[i];
                }
                constraints.push_back({position_1, q_sum_1 * (a_neg - q_neg)});

                std::size_t position_2 = 2 + !is_div; // SMOD has extra row
                // b_non_zero indicator
                std::vector<var> b_chunks_2;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_chunks_2.push_back(var_gen(i, -1));
                }
                constraint_type b_sum_2;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_sum_2 += b_chunks_2[i];
                }
                var b_sum_inverse_2 = var_gen(2*chunk_amount, -1),
                    b_non_zero_2 = var_gen(chunk_amount, +1);
                constraints.push_back({position_2, (b_non_zero_2 - b_sum_2 * b_sum_inverse_2)});

                // assure b_neg and q_neg are valid copies of the original
                var b_neg_orig = var_gen(chunk_amount + 7, -1),
                    b_neg_2 = var_gen(chunk_amount + 1, +1),
                    q_neg_orig = var_gen(chunk_amount + 8, -1),
                    q_neg_2 = var_gen(chunk_amount + 2, +1);
                constraints.push_back({position_2, (b_neg_orig - b_neg_2)});
                constraints.push_back({position_2, (q_neg_orig - q_neg_2)});

                std::vector<var> b_abs_chunks_2;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_abs_chunks_2.push_back(var_gen(i, +1));
                }

                // constraint generators for carry-on addition
                auto carry_on_addition_constraint = [](constraint_type a_0, constraint_type a_1, constraint_type a_2,
                                                       constraint_type b_0, constraint_type b_1, constraint_type b_2,
                                                       constraint_type r_0, constraint_type r_1, constraint_type r_2,
                         constraint_type last_carry, constraint_type result_carry, bool first_constraint = false) {
                    if (first_constraint) {
                        // no last carry for first constraint
                        return (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                                - r_0 - r_1 * two_16 - r_2 * two_32 - result_carry * two_48;
                    } else {
                        return last_carry + (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                                - r_0 - r_1 * two_16 - r_2 * two_32 - result_carry * two_48;
                    }
                };
                auto last_carry_on_addition_constraint = [](constraint_type a_0, constraint_type b_0, constraint_type r_0,
                                                            constraint_type last_carry, constraint_type result_carry) {
                    return (last_carry + a_0 + b_0 - r_0 - result_carry * two_16);
                };
                // constant constraints for future use
                constraint_type c_zero,
                                c_one = c_zero + 1;

                // carries for b + |b| = 2^256
                std::vector<var> tb;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    tb.push_back(var_gen(chunk_amount + 9 + i, -1));
                }
                // constraints for b + |b| = 2^256, only for negative b, i.e. b_neg_2 = 1
                constraints.push_back({position_2, b_neg_2 * carry_on_addition_constraint(
                                                                 b_chunks_2[0], b_chunks_2[1], b_chunks_2[2],
                                                                 b_abs_chunks_2[0], b_abs_chunks_2[1], b_abs_chunks_2[2],
                                                                 c_zero, c_zero, c_zero,
                                                                 tb[0],tb[0],true)});
                constraints.push_back({position_2, b_neg_2 * tb[0] * (1 - tb[0])}); // tb[0] is 0 or 1
                for (std::size_t i = 1; i < carry_amount - 1; i++) {
                     constraints.push_back({position_2, b_neg_2 * carry_on_addition_constraint(
                                                           b_chunks_2[3*i], b_chunks_2[3*i + 1], b_chunks_2[3*i + 2],
                                                           b_abs_chunks_2[3*i], b_abs_chunks_2[3*i + 1], b_abs_chunks_2[3*i + 2],
                                                           c_zero, c_zero, c_zero,
                                                           tb[i-1],tb[i])});
                     constraints.push_back({position_2, b_neg_2 * tb[i] * (1 - tb[i])}); // t[i] is 0 or 1
                }
                constraints.push_back({position_2, b_neg_2 * last_carry_on_addition_constraint(
                                                                        b_chunks_2[3*(carry_amount-1)],
                                                                        b_abs_chunks_2[3*(carry_amount-1)],
                                                                        c_zero, tb[carry_amount - 2], c_one)});
                // ^^^ if ever b + |b| = 2^256 is used, the last carry should be 1 since it is actually an overflow
                // if b_neg_2 = 0, we should have b = |b|
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    constraints.push_back({position_2, (1 - b_neg_2) * (b_chunks_2[i] - b_abs_chunks_2[i])});
                }

                std::size_t position_3 = 1 + !is_div; // SMOD has extra row
                std::vector<var> q_chunks_3;
                std::vector<var> q_abs_chunks_3;
                var q_neg_3 = var_gen(chunk_amount + 2, 0);
                for(std::size_t i = chunk_amount; i < 2*chunk_amount; i++) {
                    q_chunks_3.push_back(var_gen(i,-1));
                    q_abs_chunks_3.push_back(var_gen(i,+1));
                }

                // carries for q + |q| = 2^256
                std::vector<var> tq;
                for (std::size_t i = chunk_amount + 3; i < chunk_amount + 3 + carry_amount - 1; i++) {
                    tq.push_back(var_gen(i, 0));
                }
                constraints.push_back({position_3, q_neg_3 * carry_on_addition_constraint(
                                                                 q_chunks_3[0], q_chunks_3[1], q_chunks_3[2],
                                                                 q_abs_chunks_3[0], q_abs_chunks_3[1], q_abs_chunks_3[2],
                                                                 c_zero, c_zero, c_zero,
                                                                 tq[0],tq[0],true)});
                constraints.push_back({position_3, q_neg_3 * tq[0] * (1 - tq[0])}); // tq[0] is 0 or 1
                for (std::size_t i = 1; i < carry_amount - 1; i++) {
                     constraints.push_back({position_3, q_neg_3 * carry_on_addition_constraint(
                                                           q_chunks_3[3*i], q_chunks_3[3*i + 1], q_chunks_3[3*i + 2],
                                                           q_abs_chunks_3[3*i], q_abs_chunks_3[3*i + 1], q_abs_chunks_3[3*i + 2],
                                                           c_zero, c_zero, c_zero,
                                                           tq[i-1],tq[i])});
                     constraints.push_back({position_3, q_neg_3 * tq[i] * (1 - tq[i])}); // t[i] is 0 or 1
                }
                constraints.push_back({position_3, q_neg_3 * last_carry_on_addition_constraint(
                                                                        q_chunks_3[3*(carry_amount-1)],
                                                                        q_abs_chunks_3[3*(carry_amount-1)],
                                                                        c_zero, tq[carry_amount - 2], c_one)});
                // ^^^ if ever q + |q| = 2^256 is used, the last carry should be 1 since it is actually an overflow
                // if q_neg_3 = 0, we should have q = |q|
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    constraints.push_back({position_3, (1 - q_neg_3) * (q_chunks_3[i] - q_abs_chunks_3[i])});
                }

                if (!is_div) { // we need to make a copy of q
                    std::vector<var> q_copy_3;
                    for(std::size_t i = 0; i < chunk_amount; i++) {
                        q_copy_3.push_back(var_gen(i,+1));
                        constraints.push_back({position_3, (q_chunks_3[i] - q_copy_3[i])});
                    }
                }
                std::size_t position_4 = 0 + !is_div; // SMOD has extra row
                // prove that (|q| < |b|) or (b = r = 0)
                // note that in the latter case we have q = a to satisfy a = br + q
                std::vector<var> b_abs_chunks_4;
                std::vector<var> q_abs_chunks_4;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_abs_chunks_4.push_back(var_gen(i, -1));
                    q_abs_chunks_4.push_back(var_gen(chunk_amount + i, 0));
                }
                var b_nonzero_4 = var_gen(chunk_amount, -1);

                std::vector<var> v_chunks_4;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    v_chunks_4.push_back(var_gen(i, is_div ? 0 : +1));
                }

                std::vector<var> t;
                for (std::size_t i = chunk_amount + 3 + carry_amount - 1;
                                 i < chunk_amount + 3 + carry_amount - 1 + carry_amount; i++) {
                    t.push_back(var_gen(i, -1));
                }
                // |q| < |b| <=> |b| + v = |q| + 2^T, i.e. the last carry is 1.
                // We use t to store the addition carries and enforce the above constraint
                // if b != 0
                constraints.push_back({position_4, carry_on_addition_constraint(b_abs_chunks_4[0], b_abs_chunks_4[1], b_abs_chunks_4[2],
                                                                                v_chunks_4[0], v_chunks_4[1], v_chunks_4[2],
                                                                                q_abs_chunks_4[0], q_abs_chunks_4[1], q_abs_chunks_4[2],
                                                                                t[0],t[0],true)});
                constraints.push_back({position_4, t[0] * (1 - t[0])}); // t[0] is 0 or 1

                for (std::size_t i = 1; i < carry_amount - 1; i++) {
                     constraints.push_back({position_4, carry_on_addition_constraint(
                                                                   b_abs_chunks_4[3*i], b_abs_chunks_4[3*i + 1], b_abs_chunks_4[3*i + 2],
                                                                   v_chunks_4[3*i], v_chunks_4[3*i + 1], v_chunks_4[3*i + 2],
                                                                   q_abs_chunks_4[3*i], q_abs_chunks_4[3*i + 1], q_abs_chunks_4[3*i + 2],
                                                                   t[i-1],t[i])});
                     constraints.push_back({position_4, t[i] * (1 - t[i])}); // t[i] is 0 or 1
                }

                constraints.push_back({position_4, last_carry_on_addition_constraint(
                                                                        b_abs_chunks_4[3*(carry_amount-1)],
                                                                        v_chunks_4[3*(carry_amount-1)],
                                                                        q_abs_chunks_4[3*(carry_amount-1)],
                                                                        t[carry_amount - 2], t[carry_amount - 1])});
                // t[carry_amount-1] is 0 or 1, but should be 1 if b_nonzero = 1
                constraints.push_back({position_4, (b_nonzero_4 + (1 - b_nonzero_4)*t[carry_amount-1]) * (1 - t[carry_amount-1])});

                // for SMOD only
                if (!is_div) {
                    std::vector<var> q_chunks_4;
                    std::vector<var> q_out_chunks_4;
                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        q_chunks_4.push_back(var_gen(i,0));
                    }
                    for (std::size_t i = chunk_amount; i < 2 * chunk_amount; i++) {
                        q_out_chunks_4.push_back(var_gen(i, +1));
                    }

                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        constraints.push_back({position_4,
                                              (b_nonzero_4*(q_chunks_4[i] - q_out_chunks_4[i]) + (1-b_nonzero_4)*q_out_chunks_4[i])});
                    }
                }

                return {{gate_class::MIDDLE_OP, {constraints, {}}}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                using word_type = typename zkevm_stack::word_type;
                using integral_type = boost::multiprecision::number<
                    boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                zkevm_stack &stack = machine.stack;
                word_type a = stack.pop();
                word_type b_input = stack.pop();

                // According to Yellow paper, the result of -2^255 / -1 should be -2^255 (Yellow paper, page 30)
                // To achive that we need to replace b = -1 by b = 1 in this special case. This also helps the SMOD operation

                word_type b = (integral_type(a) == zkevm_modulus - 1) && (integral_type(b_input) == zkevm_modulus/2) ? 1 : b_input;

                auto is_negative = [](word_type x) {
                     return (integral_type(x) > zkevm_modulus/2 - 1);
                };
                auto negate_word = [](word_type x) {
                    return word_type(zkevm_modulus - integral_type(x));
                };
                auto abs_word = [&is_negative, &negate_word](word_type x) {
                    return is_negative(x)? negate_word(x) : x;
                };

                word_type a_abs = abs_word(a),
                          b_abs = abs_word(b);

                integral_type r_integral = (b != 0u)? integral_type(a_abs) / integral_type(b_abs) : 0u;
                word_type r_abs = word_type::backend_type(r_integral.backend()),
                          q_abs = b != 0u ? a_abs % b_abs : a_abs,
                          r = (is_negative(a) == is_negative(b)) ? r_abs : negate_word(r_abs),
                          q = is_negative(a)? negate_word(q_abs) : q_abs;

                word_type q_out = b != 0u ? q : 0; // according to EVM spec a % 0 = 0
                bool t_last = integral_type(q_abs) < integral_type(b_abs);
                word_type v = word_type(integral_type(q_abs) + integral_type(t_last)*zkevm_modulus - integral_type(b_abs));

                word_type result = is_div ? r : q_out;

                const std::vector<value_type> b_input_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b_input);
                const std::vector<value_type> a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b);
                const std::vector<value_type> r_chunks = zkevm_word_to_field_element<BlueprintFieldType>(r);
                const std::vector<value_type> q_chunks = zkevm_word_to_field_element<BlueprintFieldType>(q);
                const std::vector<value_type> b_abs_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b_abs);
                const std::vector<value_type> q_abs_chunks = zkevm_word_to_field_element<BlueprintFieldType>(q_abs);
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

                for(std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row) = b_input_chunks[i];
                }

                value_type a_sum = std::accumulate(a_chunks.begin(), a_chunks.end(), value_type(0)),
                           b_input_sum = std::accumulate(b_input_chunks.begin(), b_input_chunks.end(), value_type(0)),
                           b_lower_sum = b_input_sum - b_input_chunks[chunk_amount - 1]; // all chunks except the last

                assignment.witness(witness_cols[2*chunk_amount], curr_row) = (a_sum == 16*65535) ?
                                                                            0 : (a_sum - 16*65535).inversed();
                assignment.witness(witness_cols[2*chunk_amount+1], curr_row) = (b_lower_sum == 0) ? 0 : b_lower_sum.inversed();
                assignment.witness(witness_cols[2*chunk_amount+2], curr_row) = (b_input_chunks[chunk_amount-1] == 32768) ?
                                                                              0 : (b_input_chunks[chunk_amount-1] - 32768).inversed();
                assignment.witness(witness_cols[2*chunk_amount+3], curr_row) = (a_sum == 16*65535);
                assignment.witness(witness_cols[2*chunk_amount+4], curr_row) = (b_lower_sum == 0);
                assignment.witness(witness_cols[2*chunk_amount+5], curr_row) = (b_input_chunks[chunk_amount-1] == 32768);
                assignment.witness(witness_cols[2*chunk_amount+6], curr_row) = (a_sum == 16*65535) && (b_lower_sum == 0) &&
                                                                                (b_input_chunks[chunk_amount-1] == 32768);

                // TODO: replace with memory access, which would also do range checks!
                // also we can pack slightly more effectively
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 1) = a_chunks[i];
                }
                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 1) = c_1_chunks[i];
                }
                assignment.witness(witness_cols[4 + chunk_amount], curr_row + 1) = c_2;

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 2) = b_chunks[i];
                }
                assignment.witness(witness_cols[2*chunk_amount], curr_row + 2) = b_sum == 0 ? 0 : b_sum.inversed();

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 3) = r_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 3) = q_chunks[i];
                }

                // compute signs of a,b and q
                // x + 2^15 = x_aux + 2^16*x_neg
                integral_type two_15 = 32768,
                              biggest_a_chunk = integral_type(a) >> (256 - 16),
                              biggest_b_chunk = integral_type(b) >> (256 - 16),
                              biggest_q_chunk = integral_type(q) >> (256 - 16);

                assignment.witness(witness_cols[5 + chunk_amount], curr_row + 1) =
                        (biggest_a_chunk > two_15 - 1) ? (biggest_a_chunk - two_15) : biggest_a_chunk + two_15; // a_aux
                assignment.witness(witness_cols[6 + chunk_amount], curr_row + 2) = (biggest_a_chunk > two_15 - 1); // a_neg

                assignment.witness(witness_cols[6 + chunk_amount], curr_row + 1) =
                        (biggest_b_chunk > two_15 - 1) ? (biggest_b_chunk - two_15) : biggest_b_chunk + two_15; // b_aux
                assignment.witness(witness_cols[7 + chunk_amount], curr_row + 2) = (biggest_b_chunk > two_15 - 1); // b_neg

                assignment.witness(witness_cols[7 + chunk_amount], curr_row + 1) =
                        (biggest_q_chunk > two_15 - 1) ? (biggest_q_chunk - two_15) : biggest_q_chunk + two_15; // q_aux
                assignment.witness(witness_cols[8 + chunk_amount], curr_row + 2) = (biggest_q_chunk > two_15 - 1); // q_neg

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 4) = b_abs_chunks[i];
                }

                assignment.witness(witness_cols[chunk_amount], curr_row + 4) = (b != 0u); // b_non_zero
                assignment.witness(witness_cols[chunk_amount + 1], curr_row + 4) = (biggest_b_chunk > two_15 - 1); // b_neg
                assignment.witness(witness_cols[chunk_amount + 2], curr_row + 4) = (biggest_q_chunk > two_15 - 1); // q_neg

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 5) = is_div ? v_chunks[i] : q_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 5) = q_abs_chunks[i];
                }

                bool carry = 0;
                // b + |b| = 2^256 carries
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + b_chunks[3 * i    ] + b_abs_chunks[3 * i    ] +
                                    (b_chunks[3 * i + 1] + b_abs_chunks[3 * i + 1]) * two_16 +
                                    (b_chunks[3 * i + 2] + b_abs_chunks[3 * i + 2]) * two_32 ) >= two_48;
                    assignment.witness(witness_cols[chunk_amount + 9 + i], curr_row + 2) = carry;
                }
                // The last carry, if b + |b| is ever needed, should be 1 anyway, so we don't store it

                // q + |q| = 2^256 carries
                carry = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + q_chunks[3 * i    ] + q_abs_chunks[3 * i    ] +
                                    (q_chunks[3 * i + 1] + q_abs_chunks[3 * i + 1]) * two_16 +
                                    (q_chunks[3 * i + 2] + q_abs_chunks[3 * i + 2]) * two_32 ) >= two_48;
                    assignment.witness(witness_cols[chunk_amount + 3 + i], curr_row + 4) = carry;
                }
                // The last carry, if q + |q| is ever needed, should be 1 anyway, so we don't store it

                // |b| + v carries
                carry = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + b_abs_chunks[3 * i    ] + v_chunks[3 * i    ] +
                                    (b_abs_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                                    (b_abs_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32 ) >= two_48;
                    assignment.witness(witness_cols[chunk_amount + 3 + carry_amount - 1 + i], curr_row + 4) = carry;
                }
                carry = (carry + b_abs_chunks[3 * (carry_amount - 1)] + v_chunks[3 * (carry_amount - 1)]) >= two_16;
                assignment.witness(witness_cols[chunk_amount + 3 + carry_amount - 1 + carry_amount - 1], curr_row + 4) = carry;

                // optional part, for MOD only
                if (!is_div) {
                    for (std::size_t i = 0; i < chunk_amount; i++) {
                        assignment.witness(witness_cols[i], curr_row + 6) = v_chunks[i];
                        assignment.witness(witness_cols[i + chunk_amount], curr_row + 6) = q_out_chunks[i];
                    }
                }
                // stack.push(b_input);
                // stack.push(a);
                stack.push(result);
            }

            std::size_t rows_amount() override {
                return 6 + !is_div; // SMOD has an extra row
            }
        };
    }   // namespace blueprint
}   // namespace nil
