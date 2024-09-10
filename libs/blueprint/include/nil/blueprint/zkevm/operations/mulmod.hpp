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
        class zkevm_mulmod_operation : public zkevm_operation<BlueprintFieldType> {
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
                BOOST_ASSERT(chunk_idx < 8); // corrected to allow 512-bit numbers
                return chunks[4 * chunk_idx] + chunks[4 * chunk_idx + 1] * two_16 +
                       chunks[4 * chunk_idx + 2] * two_32 + chunks[4 * chunk_idx + 3] * two_48;
            }

            // a = b*r, a and r have 8 64-bit chunks, b has 4 64-bit chunks
            template<typename T>
            T first_carryless_construct(
                const std::vector<T> &a_64_chunks, const std::vector<T> &b_64_chunks, const std::vector<T> &r_64_chunks
            ) const {
                return
                    r_64_chunks[0] * b_64_chunks[0] +
                    two_64 * (r_64_chunks[0] * b_64_chunks[1] + r_64_chunks[1] * b_64_chunks[0])
                    - a_64_chunks[0] - two_64 * a_64_chunks[1];
            }

            template<typename T>
            T second_carryless_construct(
                const std::vector<T> &a_64_chunks, const std::vector<T> &b_64_chunks, const std::vector<T> &r_64_chunks
            ) const {
                return
                    (r_64_chunks[0] * b_64_chunks[2] + r_64_chunks[1] * b_64_chunks[1] + r_64_chunks[2] * b_64_chunks[0]) +
                    two_64 * (r_64_chunks[0] * b_64_chunks[3] + r_64_chunks[1] * b_64_chunks[2] +
                              r_64_chunks[2] * b_64_chunks[1] + r_64_chunks[3] * b_64_chunks[0])
                       - a_64_chunks[2] - two_64 * a_64_chunks[3];
            }

            template<typename T>
            T third_carryless_construct(
                const std::vector<T> &a_64_chunks, const std::vector<T> &b_64_chunks, const std::vector<T> &r_64_chunks
            ) const {
                return
                    (r_64_chunks[1] * b_64_chunks[3] + r_64_chunks[2] * b_64_chunks[2] +
                     r_64_chunks[3] * b_64_chunks[1] + r_64_chunks[4] * b_64_chunks[0]) +
                    two_64 * (r_64_chunks[2] * b_64_chunks[3] + r_64_chunks[3] * b_64_chunks[2] + r_64_chunks[4] * b_64_chunks[1] +
                              r_64_chunks[5] * b_64_chunks[0])
                      - a_64_chunks[4] - two_64 * a_64_chunks[5];
            }

            template<typename T>
            T forth_carryless_construct(
                const std::vector<T> &a_64_chunks, const std::vector<T> &b_64_chunks, const std::vector<T> &r_64_chunks
            ) const {
                return (r_64_chunks[3] * b_64_chunks[3] + r_64_chunks[4] * b_64_chunks[2] +
                        r_64_chunks[5] * b_64_chunks[1] + r_64_chunks[6] * b_64_chunks[0]) +
                       two_64 * (r_64_chunks[4] * b_64_chunks[3] + r_64_chunks[5] * b_64_chunks[2] +
                                 r_64_chunks[6] * b_64_chunks[1] + r_64_chunks[7] * b_64_chunks[0])
                        - a_64_chunks[6] - two_64 * a_64_chunks[7];
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

                // The central relation is a * b = s = Nr + q, q < N.
                // For N = 0 we should have q = 0, so we set a = 0 in that case
                //
                // Table layout:                                                     Internal row #:  | External #:
                // +--------------------------------+--------------------------------+---+-------+
                // |             input_a            |                 v              |1/N|   t   |  7 |    0
                // +--------------------------------+--------------------------------+---+-------+
                // |                N               |                 q              |           |  6 |    1
                // +--------------------------------+--------------------------------+-----------+
                // |                a               |                 b              |           |  5 |    2
                // +------+--+------+--+------+--+--+--------------------------------+-----------+
                // |  c1  |c2|  c3  |c4|  c5  |c6|  |                 q              |           |  4 |    3
                // +------+--+------+--+------+--+--+--------------------------------+------+----+
                // |                s'              |                 s"             | tNr' |tNr"|  3 |    4
                // +--------------------------------+--------------------------------+------+----+
                // |              (Nr)'             |               (Nr)"            |           |  2 |    5
                // +--------------------------------+--------------------------------+-----------+
                // |                r'              |                r"              |           |  1 |    6
                // +--------------------------------+------+--+------+--+------+--+--+-----------+
                // |                N               |  c1  |c2|  c3  |c4|  c5  |c6|  |           |  0 |    7
                // +--------------------------------+------+--+------+--+------+--+--+-----------+

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

                // choose a between input_a and 0 according to N = 0
                std::size_t position_0 = 6;
                std::vector<var> input_a_chunks;
                std::vector<var> N_chunks_0;
                std::vector<var> a_chunks_0;
                var N_sum_inverse_0 = var_gen(2*chunk_amount, -1);
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    input_a_chunks.push_back(var_gen(i, -1));
                    N_chunks_0.push_back(var_gen(i, 0));
                    a_chunks_0.push_back(var_gen(i, +1));
                }

                constraint_type N_sum_0;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    N_sum_0 += N_chunks_0[i];
                }
                constraint_type N_nonzero_0 = N_sum_0 * N_sum_inverse_0;

                for(std::size_t i = 0; i < chunk_amount; i++) {
                    constraints.push_back({position_0, (a_chunks_0[i] - N_nonzero_0 * input_a_chunks[i])}); // a = 0 if N = 0
                }
                // end of choosing a

                // prove that (q < N) or (N = 0)
                // note that in the latter case we have q = a = 0, so a*b = Nr + q is satisfied
                std::size_t position_1 = 7;
                std::vector<var> N_chunks_1;
                std::vector<var> q_chunks_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    N_chunks_1.push_back(var_gen(i, +1));
                    q_chunks_1.push_back(var_gen(chunk_amount + i, +1));
                }
                constraint_type N_sum_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    N_sum_1 += N_chunks_1[i];
                }

                std::vector<var> v_chunks_1;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    v_chunks_1.push_back(var_gen(chunk_amount + i, 0));
                }

                var N_sum_inverse_1 = var_gen(2*chunk_amount, 0);
                // inverse for N_sum_inverse unless N_sum = 0
                constraints.push_back({position_1, N_sum_1 * (N_sum_inverse_1 * N_sum_1 - 1)});
                constraint_type N_nonzero_1 = N_sum_inverse_1 * N_sum_1;

                std::vector<var> t;
                for (std::size_t i = 0; i < carry_amount; i++) {
                    t.push_back(var_gen(2*chunk_amount + 1 + i, 0));
                }

                // q < N <=> N + v = q + 2^T, i.e. the last carry is 1.
                // We use t to store the addition carries and enforce the above constraint
                // if N != 0
                constraints.push_back({position_1, carry_on_addition_constraint(N_chunks_1[0], N_chunks_1[1], N_chunks_1[2],
                                                                                v_chunks_1[0], v_chunks_1[1], v_chunks_1[2],
                                                                                q_chunks_1[0], q_chunks_1[1], q_chunks_1[2],
                                                                                t[0],t[0],true)});
                constraints.push_back({position_1, t[0] * (1 - t[0])}); // t[0] is 0 or 1
                for (std::size_t i = 1; i < carry_amount - 1; i++) {
                     constraints.push_back({position_1, carry_on_addition_constraint(
                                                                   N_chunks_1[3*i], N_chunks_1[3*i + 1], N_chunks_1[3*i + 2],
                                                                   v_chunks_1[3*i], v_chunks_1[3*i + 1], v_chunks_1[3*i + 2],
                                                                   q_chunks_1[3*i], q_chunks_1[3*i + 1], q_chunks_1[3*i + 2],
                                                                   t[i-1],t[i])});
                     constraints.push_back({position_1, t[i] * (1 - t[i])}); // t[i] is 0 or 1
                }
                constraints.push_back({position_1, last_carry_on_addition_constraint(
                                                                        N_chunks_1[3*(carry_amount-1)],
                                                                        v_chunks_1[3*(carry_amount-1)],
                                                                        q_chunks_1[3*(carry_amount-1)],
                                                                        t[carry_amount - 2], t[carry_amount - 1])});
                // t[carry_amount-1] is 0 or 1, but should be 1 if N_nonzero = 1
                constraints.push_back({position_1, (N_nonzero_1  + (1 - N_nonzero_1)* t[carry_amount-1]) * (1 - t[carry_amount-1])});
                // end of q < N constraints

                // s = a * b constraints
                std::size_t position_2 = 4;
                std::vector<var> a_chunks;
                std::vector<var> b_chunks;
                std::vector<var> s_chunks_2;

                for(std::size_t i = 0; i < chunk_amount; i++) {
                    a_chunks.push_back(var_gen(i, -1));
                    b_chunks.push_back(var_gen(chunk_amount + i, -1));
                    s_chunks_2.push_back(var_gen(i, +1));
                }
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    s_chunks_2.push_back(var_gen(chunk_amount + i, +1));
                }

                std::vector<var> s_c_1_chunks;
                std::vector<var> s_c_3_chunks;
                std::vector<var> s_c_5_chunks;
                for(std::size_t i = 0; i < 4; i++) {
                    s_c_1_chunks.push_back(var_gen(i, 0));
                    s_c_3_chunks.push_back(var_gen(5 + i, 0));
                    s_c_5_chunks.push_back(var_gen(10 + i, 0));
                }

                var s_c_2 = var_gen(4, 0);
                var s_c_4 = var_gen(9, 0);
                var s_c_6 = var_gen(14, 0);

                std::vector<constraint_type> s_64_chunks;
                std::vector<constraint_type> a_64_chunks;
                std::vector<constraint_type> b_64_chunks;

                for(std::size_t i = 0; i < 8; i++) {
                    s_64_chunks.push_back(chunk_sum_64<constraint_type, var>(s_chunks_2,i));
                    if (i < 4) {
                        a_64_chunks.push_back(chunk_sum_64<constraint_type, var>(a_chunks,i));
                        b_64_chunks.push_back(chunk_sum_64<constraint_type, var>(b_chunks,i));
                    } else {
                        a_64_chunks.push_back(c_zero);
                    }
                }

                constraint_type s_c_1_64 = chunk_sum_64<constraint_type, var>(s_c_1_chunks, 0);
                constraint_type s_c_3_64 = chunk_sum_64<constraint_type, var>(s_c_3_chunks, 0);
                constraint_type s_c_5_64 = chunk_sum_64<constraint_type, var>(s_c_5_chunks, 0);
                // prove that multiplication a * b = s is correct
                constraint_type s_first_carryless = first_carryless_construct<constraint_type>(s_64_chunks, b_64_chunks, a_64_chunks);
                constraints.push_back({position_2, (s_first_carryless - s_c_1_64 * two128 - s_c_2 * two192)});

                constraint_type s_second_carryless = second_carryless_construct<constraint_type>(s_64_chunks, b_64_chunks, a_64_chunks);
                constraints.push_back({position_2, (s_second_carryless + s_c_1_64 + s_c_2 * two_64 - s_c_3_64 * two128 - s_c_4 * two192)});

                // add constraints for s_c_2/s_c_4/s_c_6: s_c_2 is 0/1, s_c_4 is 0/1/2/3, s_c_6 is 0/1
                constraints.push_back({position_2, s_c_2 * (s_c_2 - 1)});
                constraints.push_back({position_2, s_c_4 * (s_c_4 - 1) * (s_c_4 - 2) * (s_c_4 - 3)});
                constraints.push_back({position_2, s_c_6 * (s_c_6 - 1)});

                constraint_type s_third_carryless = third_carryless_construct<constraint_type>(s_64_chunks, b_64_chunks, a_64_chunks);
                constraints.push_back({position_2, (s_third_carryless + s_c_3_64 + s_c_4 * two_64 - s_c_5_64 * two128 - s_c_6 * two192)});

                constraint_type s_forth_carryless = forth_carryless_construct<constraint_type>(s_64_chunks, b_64_chunks, a_64_chunks);
                constraints.push_back({position_2, (s_forth_carryless + s_c_5_64 + s_c_6 * two_64)});
                // end of s = a * b constraints

                // assure copies of q are equal
                std::size_t position_3 = 5;
                std::vector<var> q_upper_copy;
                std::vector<var> q_lower_copy;
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    q_upper_copy.push_back(var_gen(chunk_amount + i, -1));
                    q_lower_copy.push_back(var_gen(chunk_amount + i, +1));
                }
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    constraints.push_back({position_3, (q_upper_copy[i] - q_lower_copy[i])});
                }
                // end of copy constraints for q

                // s = Nr + q constraints
                std::size_t position_4 = 3;
                std::vector<var> sp_chunks_4;
                std::vector<var> spp_chunks_4;
                std::vector<var> tNrp;
                std::vector<var> tNrpp;
                std::vector<var> q_chunks_4;
                std::vector<var> Nr_p_chunks_4;
                std::vector<var> Nr_pp_chunks_4;

                for(std::size_t i = 0; i < chunk_amount; i++) {
                    sp_chunks_4.push_back(var_gen(i, 0));
                    spp_chunks_4.push_back(var_gen(chunk_amount + i, 0));
                    q_chunks_4.push_back(var_gen(chunk_amount + i, -1));
                    Nr_p_chunks_4.push_back(var_gen(i, +1));
                    Nr_pp_chunks_4.push_back(var_gen(chunk_amount + i, +1));
                }
                for(std::size_t i = 0; i < carry_amount - 1; i++) {
                    tNrp.push_back(var_gen(2*chunk_amount + i, 0));
                    tNrpp.push_back(var_gen(2*chunk_amount + carry_amount + i, 0));
                }
                tNrp.push_back(var_gen(2*chunk_amount + carry_amount - 1, 0)); // only the first part has the overflow carry

                constraints.push_back({position_4, carry_on_addition_constraint(Nr_p_chunks_4[0], Nr_p_chunks_4[1], Nr_p_chunks_4[2],
                                                                                q_chunks_4[0], q_chunks_4[1], q_chunks_4[2],
                                                                                sp_chunks_4[0], sp_chunks_4[1], sp_chunks_4[2],
                                                                                tNrp[0],tNrp[0],true)});
                constraints.push_back({position_4, tNrp[0] * (1 - tNrp[0])}); // tNrp[0] is 0 or 1
                for (std::size_t i = 1; i < carry_amount - 1; i++) {
                     constraints.push_back({position_4, carry_on_addition_constraint(
                                                                   Nr_p_chunks_4[3*i], Nr_p_chunks_4[3*i + 1], Nr_p_chunks_4[3*i + 2],
                                                                   q_chunks_4[3*i], q_chunks_4[3*i + 1], q_chunks_4[3*i + 2],
                                                                   sp_chunks_4[3*i], sp_chunks_4[3*i + 1], sp_chunks_4[3*i + 2],
                                                                   tNrp[i-1],tNrp[i])});
                     constraints.push_back({position_4, tNrp[i] * (1 - tNrp[i])}); // tNrp[i] is 0 or 1
                }
                constraints.push_back({position_4, last_carry_on_addition_constraint(
                                                                        Nr_p_chunks_4[3*(carry_amount-1)],
                                                                        q_chunks_4[3*(carry_amount-1)],
                                                                        sp_chunks_4[3*(carry_amount-1)],
                                                                        tNrp[carry_amount - 2], tNrp[carry_amount - 1])});
                constraints.push_back({position_4, tNrp[carry_amount - 1]*(1 - tNrp[carry_amount - 1])});
                // tNrp[carry_amount - 1] is 0 or 1

                constraints.push_back({position_4, carry_on_addition_constraint(Nr_pp_chunks_4[0], Nr_pp_chunks_4[1], Nr_pp_chunks_4[2],
                                                                                tNrp[carry_amount - 1], c_zero, c_zero,
                                                                                spp_chunks_4[0], spp_chunks_4[1], spp_chunks_4[2],
                                                                                tNrpp[0],tNrpp[0],true)});
                constraints.push_back({position_4, tNrpp[0] * (1 - tNrpp[0])}); // tNrpp[0] is 0 or 1
                for (std::size_t i = 1; i < carry_amount - 1; i++) {
                     constraints.push_back({position_4, carry_on_addition_constraint(
                                                                   Nr_pp_chunks_4[3*i], Nr_pp_chunks_4[3*i + 1], Nr_pp_chunks_4[3*i + 2],
                                                                   c_zero, c_zero, c_zero,
                                                                   spp_chunks_4[3*i], spp_chunks_4[3*i + 1], spp_chunks_4[3*i + 2],
                                                                   tNrpp[i-1],tNrpp[i])});
                     constraints.push_back({position_4, tNrpp[i] * (1 - tNrpp[i])}); // tNrpp[i] is 0 or 1
                }
                constraints.push_back({position_4, last_carry_on_addition_constraint(
                                                                        Nr_pp_chunks_4[3*(carry_amount-1)],
                                                                        c_zero,
                                                                        spp_chunks_4[3*(carry_amount-1)],
                                                                        tNrpp[carry_amount - 2], c_zero)});
                // tNrpp[carry_amount - 1] is always 0, so instead we put c_zero
                // end of s = Nr + q constraints

                // the section where we prove Nr = N * r
                std::size_t position_5 = 1;
                std::vector<var> Nr_chunks_5;
                std::vector<var> r_chunks_5;
                std::vector<var> N_chunks_5;
                for(std::size_t i = 0; i < 2*chunk_amount; i++) {
                    Nr_chunks_5.push_back(var_gen(i, -1));
                    r_chunks_5.push_back(var_gen(i, 0));
                    if (i < chunk_amount) {
                        N_chunks_5.push_back(var_gen(i, +1));
                    }
                }

                std::vector<var> c_1_chunks;
                std::vector<var> c_3_chunks;
                std::vector<var> c_5_chunks;
                for(std::size_t i = 0; i < 4; i++) {
                    c_1_chunks.push_back(var_gen(chunk_amount + i, +1));
                    c_3_chunks.push_back(var_gen(chunk_amount + 5 + i, +1));
                    c_5_chunks.push_back(var_gen(chunk_amount + 10 + i, +1));
                }

                var c_2 = var_gen(chunk_amount + 4, +1);
                var c_4 = var_gen(chunk_amount + 9, +1);
                var c_6 = var_gen(chunk_amount + 14, +1);

                std::vector<constraint_type> Nr_64_chunks;
                std::vector<constraint_type> r_64_chunks;
                std::vector<constraint_type> N_64_chunks;

                for(std::size_t i = 0; i < 8; i++) {
                    Nr_64_chunks.push_back(chunk_sum_64<constraint_type, var>(Nr_chunks_5,i));
                    r_64_chunks.push_back(chunk_sum_64<constraint_type, var>(r_chunks_5,i));
                    if (i < 4) {
                        N_64_chunks.push_back(chunk_sum_64<constraint_type, var>(N_chunks_5,i));
                    }
                }
                constraint_type c_1_64 = chunk_sum_64<constraint_type, var>(c_1_chunks, 0);
                constraint_type c_3_64 = chunk_sum_64<constraint_type, var>(c_3_chunks, 0);
                constraint_type c_5_64 = chunk_sum_64<constraint_type, var>(c_5_chunks, 0);
                // prove that multiplication N * r = Nr is correct
                constraint_type first_carryless = first_carryless_construct<constraint_type>(Nr_64_chunks, N_64_chunks, r_64_chunks);
                constraints.push_back({position_5, (first_carryless - c_1_64 * two128 - c_2 * two192)});

                constraint_type second_carryless = second_carryless_construct<constraint_type>(Nr_64_chunks, N_64_chunks, r_64_chunks);
                constraints.push_back({position_5, (second_carryless + c_1_64 + c_2 * two_64 - c_3_64 * two128 - c_4 * two192)});

                // add constraints for c_2/c_4: c_2 is 0/1, c_4, c_6 is 0/1/2/3
                constraints.push_back({position_5, c_2 * (c_2 - 1)});
                constraints.push_back({position_5, c_4 * (c_4 - 1) * (c_4 - 2) * (c_4 - 3)});
                constraints.push_back({position_5, c_6 * (c_6 - 1) * (c_6 - 2) * (c_6 - 3)});

                constraint_type third_carryless = third_carryless_construct<constraint_type>(Nr_64_chunks, N_64_chunks, r_64_chunks);
                constraints.push_back({position_5, (third_carryless + c_3_64 + c_4 * two_64 - c_5_64 * two128 - c_6 * two192)});

                constraint_type forth_carryless = forth_carryless_construct<constraint_type>(Nr_64_chunks, N_64_chunks, r_64_chunks);
                constraints.push_back({position_5, (forth_carryless + c_5_64 + c_6 * two_64)});
                // end of Nr = N * r constraints

                return {{gate_class::MIDDLE_OP, {constraints, {}}}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                using word_type = typename zkevm_stack::word_type;
                using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;
                using extended_integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<512>>;

                zkevm_stack &stack = machine.stack;

                word_type input_a = stack.pop();
                word_type b = stack.pop();
                word_type N = stack.pop();

                word_type a = N != 0u ? input_a : 0;

                extended_integral_type s_integral = extended_integral_type(integral_type(a)) * extended_integral_type(integral_type(b));

                word_type sp  = word_type(s_integral % extended_integral_type(zkevm_modulus));
                word_type spp = word_type(s_integral / extended_integral_type(zkevm_modulus));

                extended_integral_type r_integral = N != 0u ? s_integral / extended_integral_type(integral_type(N)) : 0u;
                word_type rp  = word_type(r_integral % extended_integral_type(zkevm_modulus));
                word_type rpp = word_type(r_integral / extended_integral_type(zkevm_modulus));

                word_type q = N != 0u ? word_type(s_integral % extended_integral_type(integral_type(N))) : 0u;

                extended_integral_type Nr_integral = s_integral - extended_integral_type(integral_type(q));
                word_type Nr_p  = word_type(Nr_integral % extended_integral_type(zkevm_modulus));
                word_type Nr_pp = word_type(Nr_integral / extended_integral_type(zkevm_modulus));

                bool t_last = integral_type(q) < integral_type(N);
                word_type v = word_type(integral_type(q) + integral_type(t_last)*zkevm_modulus - integral_type(N));

                word_type result = q;

                const std::vector<value_type> v_chunks = zkevm_word_to_field_element<BlueprintFieldType>(v);
                const std::vector<value_type> N_chunks = zkevm_word_to_field_element<BlueprintFieldType>(N);
                const std::vector<value_type> q_chunks = zkevm_word_to_field_element<BlueprintFieldType>(q);
                const std::vector<value_type> a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<value_type> input_a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(input_a);
                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b);
                const std::vector<value_type> sp_chunks = zkevm_word_to_field_element<BlueprintFieldType>(sp);
                const std::vector<value_type> spp_chunks = zkevm_word_to_field_element<BlueprintFieldType>(spp);
                const std::vector<value_type> rp_chunks = zkevm_word_to_field_element<BlueprintFieldType>(rp);
                const std::vector<value_type> rpp_chunks = zkevm_word_to_field_element<BlueprintFieldType>(rpp);
                const std::vector<value_type> Nr_p_chunks = zkevm_word_to_field_element<BlueprintFieldType>(Nr_p);
                const std::vector<value_type> Nr_pp_chunks = zkevm_word_to_field_element<BlueprintFieldType>(Nr_pp);

                const std::size_t chunk_amount = sp_chunks.size();
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                assignment_type &assignment = zkevm_circuit.get_assignment();
                const std::size_t curr_row = zkevm_circuit.get_current_row();

                // note that we don't assign 64-chunks for s/N, as we can build them from 16-chunks with constraints
                // under the same logic we only assign the 16-bit chunks for carries
                std::vector<value_type> a_64_chunks, b_64_chunks, s_64_chunks, N_64_chunks, r_64_chunks, Nr_64_chunks;
                for (std::size_t i = 0; i < 4; i++) {
                    a_64_chunks.push_back(chunk_sum_64<value_type>(a_chunks, i));
                    b_64_chunks.push_back(chunk_sum_64<value_type>(b_chunks, i));
                    s_64_chunks.push_back(chunk_sum_64<value_type>(sp_chunks, i));
                    N_64_chunks.push_back(chunk_sum_64<value_type>(N_chunks, i));
                    r_64_chunks.push_back(chunk_sum_64<value_type>(rp_chunks, i));
                    Nr_64_chunks.push_back(chunk_sum_64<value_type>(Nr_p_chunks, i));
                }
                for (std::size_t i = 0; i < 4; i++) { // for 512-bit integers 64-bit chunks go on
                    a_64_chunks.push_back(0); // artificially extend a_64_chunks to a 512-bit number representation
                    s_64_chunks.push_back(chunk_sum_64<value_type>(spp_chunks, i));
                    r_64_chunks.push_back(chunk_sum_64<value_type>(rpp_chunks, i));
                    Nr_64_chunks.push_back(chunk_sum_64<value_type>(Nr_pp_chunks, i));
                }

                // computation of s = a*b product
                auto s_first_row_carries =
                    first_carryless_construct(s_64_chunks, b_64_chunks, a_64_chunks).data >> 128;
                value_type s_c_1 = static_cast<value_type>(s_first_row_carries & (two_64 - 1).data);
                value_type s_c_2 = static_cast<value_type>(s_first_row_carries >> 64);
                std::vector<value_type> s_c_1_chunks = chunk_64_to_16<BlueprintFieldType>(s_c_1);
                // no need for c_2 chunks as there is only a single chunk
                auto s_second_row_carries =
                    (second_carryless_construct(s_64_chunks, b_64_chunks, a_64_chunks)
                     + s_c_1 + s_c_2 * two_64).data >> 128;
                value_type s_c_3 = static_cast<value_type>(s_second_row_carries & (two_64 - 1).data);
                value_type s_c_4 = static_cast<value_type>(s_second_row_carries >> 64);
                std::vector<value_type> s_c_3_chunks = chunk_64_to_16<BlueprintFieldType>(s_c_3);
                auto s_third_row_carries =
                    (third_carryless_construct(s_64_chunks, b_64_chunks, a_64_chunks)
                     + s_c_3 + s_c_4 * two_64).data >> 128;
                value_type s_c_5 = static_cast<value_type>(s_third_row_carries & (two_64 - 1).data);
                value_type s_c_6 = static_cast<value_type>(s_third_row_carries >> 64);
                std::vector<value_type> s_c_5_chunks = chunk_64_to_16<BlueprintFieldType>(s_c_5);

                // computation of N*r product
                // caluclate first row carries
                auto first_row_carries =
                    first_carryless_construct(Nr_64_chunks, N_64_chunks, r_64_chunks).data >> 128;
                value_type c_1 = static_cast<value_type>(first_row_carries & (two_64 - 1).data);
                value_type c_2 = static_cast<value_type>(first_row_carries >> 64);
                std::vector<value_type> c_1_chunks = chunk_64_to_16<BlueprintFieldType>(c_1);
                // no need for c_2 chunks as there is only a single chunk
                auto second_row_carries =
                    (second_carryless_construct(Nr_64_chunks, N_64_chunks, r_64_chunks)
                     + c_1 + c_2 * two_64).data >> 128;
                value_type c_3 = static_cast<value_type>(second_row_carries & (two_64 - 1).data);
                value_type c_4 = static_cast<value_type>(second_row_carries >> 64);
                std::vector<value_type> c_3_chunks = chunk_64_to_16<BlueprintFieldType>(c_3);
                auto third_row_carries =
                    (third_carryless_construct(Nr_64_chunks, N_64_chunks, r_64_chunks)
                     + c_3 + c_4 * two_64).data >> 128;
                value_type c_5 = static_cast<value_type>(third_row_carries & (two_64 - 1).data);
                value_type c_6 = static_cast<value_type>(third_row_carries >> 64);
                std::vector<value_type> c_5_chunks = chunk_64_to_16<BlueprintFieldType>(c_5);

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[chunk_amount + i], curr_row) = v_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row) = input_a_chunks[i];
                }
                value_type N_sum = std::accumulate(N_chunks.begin(), N_chunks.end(), value_type(0));
                assignment.witness(witness_cols[2*chunk_amount], curr_row) = N_sum == 0 ? 0 : N_sum.inversed();

                bool carry = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + N_chunks[3 * i    ] + v_chunks[3 * i    ] +
                                    (N_chunks[3 * i + 1] + v_chunks[3 * i + 1]) * two_16 +
                                    (N_chunks[3 * i + 2] + v_chunks[3 * i + 2]) * two_32 ) >= two_48;
                    assignment.witness(witness_cols[2*chunk_amount + 1 + i], curr_row) = carry;
                }
                carry = (carry + N_chunks[3 * (carry_amount - 1)] + v_chunks[3 * (carry_amount - 1)]) >= two_16;
                assignment.witness(witness_cols[2*chunk_amount + 1 + carry_amount - 1], curr_row) = carry;

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 1) = N_chunks[i]; //TODO this has to be lookup-constrained with RW-table
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 1) = q_chunks[i];
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 3) = q_chunks[i];
                }

                // TODO: replace with memory access, which would also do range checks!
                // also we can pack slightly more effectively
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 2) = a_chunks[i];
                    assignment.witness(witness_cols[chunk_amount + i], curr_row + 2) = b_chunks[i];
                    assignment.witness(witness_cols[i], curr_row + 4) = sp_chunks[i];
                    assignment.witness(witness_cols[chunk_amount + i], curr_row + 4) = spp_chunks[i];
                }
                // s = a * b carries
                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(witness_cols[i], curr_row + 3) = s_c_1_chunks[i];
                    assignment.witness(witness_cols[5 + i], curr_row + 3) = s_c_3_chunks[i];
                    assignment.witness(witness_cols[10 + i], curr_row + 3) = s_c_5_chunks[i];
                }
                assignment.witness(witness_cols[4], curr_row + 3) = s_c_2;
                assignment.witness(witness_cols[9], curr_row + 3) = s_c_4;
                assignment.witness(witness_cols[14], curr_row + 3) = s_c_6;

                // s = Nr + q carries
                carry = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + Nr_p_chunks[3 * i    ] + q_chunks[3 * i    ] +
                                    (Nr_p_chunks[3 * i + 1] + q_chunks[3 * i + 1]) * two_16 +
                                    (Nr_p_chunks[3 * i + 2] + q_chunks[3 * i + 2]) * two_32 ) >= two_48;
                    assignment.witness(witness_cols[2*chunk_amount + i], curr_row + 4) = carry;
                }
                carry = (carry + Nr_p_chunks[3 * (carry_amount - 1)] + q_chunks[3 * (carry_amount - 1)]) >= two_16;
                assignment.witness(witness_cols[2*chunk_amount + carry_amount - 1], curr_row + 4) = carry;
                bool Nrpp_add = carry;
                carry = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + Nr_pp_chunks[3 * i    ] + (i == 0)*Nrpp_add +
                                     Nr_pp_chunks[3 * i + 1] * two_16 +
                                     Nr_pp_chunks[3 * i + 2] * two_32 ) >= two_48;
                    assignment.witness(witness_cols[2*chunk_amount + carry_amount + i], curr_row + 4) = carry;
                }
                carry = (carry + Nr_pp_chunks[3 * (carry_amount - 1)]) >= two_16;
                // ^^^^ normally should be zero, so we don't store it
                BOOST_ASSERT(carry == 0);
                // end of s = Nr + q carries

                for(std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 5) = Nr_p_chunks[i];
                    assignment.witness(witness_cols[chunk_amount + i], curr_row + 5) = Nr_pp_chunks[i];
                }

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 6) = rp_chunks[i];
                    assignment.witness(witness_cols[chunk_amount + i], curr_row + 6) = rpp_chunks[i];
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 7) = N_chunks[i];
                }

                // N*r carries
                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 7) = c_1_chunks[i];
                    assignment.witness(witness_cols[5 + i + chunk_amount], curr_row + 7) = c_3_chunks[i];
                    assignment.witness(witness_cols[10 + i + chunk_amount], curr_row + 7) = c_5_chunks[i];
                }
                assignment.witness(witness_cols[4 + chunk_amount], curr_row + 7) = c_2;
                assignment.witness(witness_cols[9 + chunk_amount], curr_row + 7) = c_4;
                assignment.witness(witness_cols[14 + chunk_amount], curr_row + 7) = c_6;

                // stack.push(N);
                // stack.push(b);
                // stack.push(input_a);
                stack.push(result);
            }

            std::size_t rows_amount() override {
                return 8;
            }
        };
    }   // namespace blueprint
}   // namespace nil
