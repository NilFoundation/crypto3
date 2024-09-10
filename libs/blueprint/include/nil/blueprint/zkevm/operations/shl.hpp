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
        class zkevm_shl_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_shl_operation() {}

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
                const std::vector<T> &r_64_chunks
            ) const {
                return
                    a_64_chunks[0] * b_64_chunks[0] +
                    two_64 * (a_64_chunks[0] * b_64_chunks[1] + a_64_chunks[1] * b_64_chunks[0])
                    - r_64_chunks[0] - two_64 * r_64_chunks[1];
            }

            template<typename T>
            T second_carryless_construct(
                const std::vector<T> &a_64_chunks, const std::vector<T> &b_64_chunks,
                const std::vector<T> &r_64_chunks
            ) {
                return
                    (a_64_chunks[0] * b_64_chunks[2] + a_64_chunks[1] * b_64_chunks[1] +
                     a_64_chunks[2] * b_64_chunks[0] - r_64_chunks[2]) +
                    two_64 * (a_64_chunks[0] * b_64_chunks[3] + a_64_chunks[1] * b_64_chunks[2] +
                              a_64_chunks[2] * b_64_chunks[1] + a_64_chunks[3] * b_64_chunks[0] - r_64_chunks[3]);
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

                // Table layout
                // (construct b = 1 << input_b, then do multiplication)
                // +-------------+---+---+----+-----+-+--+--+--+----------+
                // |    input_b  |b0'|b0"|b0"'|     |z|tp|I1|I2|          | 3
                // +-------------+---+---+----+-----+-+--+--+--+----------+
                // |       a     |                       | (j - b0')^{-1} | 2
                // +-------------+-----------------------+----------------+
                // |       b     |                       | (j - b0")^{-1} | 1
                // +-------------+----+--+----+--+-------+----------------+
                // |       r     | c1 |c2| c3 |c4|       |                | 0
                // +-------------+----+--+----+--+-------+----------------+
                std::size_t position_0 = 2;
                std::vector<var> input_b_chunks;
                std::vector<var> indic_1;
                std::vector<var> indic_2;
                std::vector<var> b_chunks_0;
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    input_b_chunks.push_back(var_gen(i, -1));
                    indic_1.push_back(var_gen(2*chunk_amount + i, 0));
                    indic_2.push_back(var_gen(2*chunk_amount + i, +1));
                    b_chunks_0.push_back(var_gen(i, +1));
                }
                var b0p_var = var_gen(chunk_amount, -1),
                    b0pp_var = var_gen(chunk_amount + 1, -1),
                    b0ppp_var = var_gen(chunk_amount + 2, -1),
                    I1_var = var_gen(2*chunk_amount, -1),
                    I2_var = var_gen(2*chunk_amount + 1, -1),
                    z_var = var_gen(chunk_amount + 5, -1),
                    tp_var = var_gen(chunk_amount + 5, -1);

                // lookup constrain b0p < 16, b0pp < 16, b0ppp < 256
                lookup_constraints.push_back({position_0, {range_check_table_index, {4096 * b0p_var}}});
                lookup_constraints.push_back({position_0, {range_check_table_index, {4096 * b0pp_var}}});
                lookup_constraints.push_back({position_0, {range_check_table_index, {256 * b0ppp_var}}});
                constraints.push_back({position_0, (input_b_chunks[0] - b0p_var - 16*b0pp_var - 256*b0ppp_var)});
                constraints.push_back({position_0, b0ppp_var * (1 - b0ppp_var * I1_var)});

                constraint_type sum_b;
                for(std::size_t i = 1; i < chunk_amount; i++) {
                    sum_b += input_b_chunks[i];
                }
                constraints.push_back({position_0, sum_b * (1 - sum_b * I2_var)});
                constraints.push_back({position_0, (z_var - (1 - b0ppp_var * I1_var) * (1 - sum_b * I2_var))});

                for(std::size_t j = 0; j < chunk_amount; j++) {
                    constraints.push_back({position_0, (b0p_var - j)*(1 - (b0p_var - j) * indic_1[j])});
                    constraints.push_back({position_0, (b0pp_var - j)*(1 - (b0pp_var - j) * indic_2[j])});
                }

                constraint_type two_powers;
                unsigned int pow = 1;
                for(std::size_t j = 0; j < chunk_amount; j++) {
                    two_powers += (1 - (b0p_var - j)*indic_1[j])*pow;
                    pow *= 2;
                }
                constraints.push_back({position_0, (tp_var - z_var * two_powers)});

                for(std::size_t j = 0; j < chunk_amount; j++) {
                    constraints.push_back({position_0, (b_chunks_0[j] - tp_var * (1 - (b0pp_var - j)*indic_2[j]))});
                }

                std::size_t position = 1;
                std::vector<var> a_chunks;
                std::vector<var> b_chunks;
                std::vector<var> r_chunks;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    a_chunks.push_back(var_gen(i, -1));
                    b_chunks.push_back(var_gen(i, 0));
                    r_chunks.push_back(var_gen(i, +1));
                }

                std::vector<var> c_1_chunks;
                std::vector<var> c_3_chunks;
                for (std::size_t i = 0; i < 4; i++) {
                    c_1_chunks.push_back(var_gen(i + chunk_amount, +1));
                }
                var c_2 = var_gen(chunk_amount + 4, +1);
                for (std::size_t i = 0; i < 4; i++) {
                    c_3_chunks.push_back(var_gen(i + chunk_amount + 5, +1));
                }
                var c_4 = var_gen(chunk_amount + 9, +1);

                std::vector<constraint_type> a_64_chunks = {
                    chunk_sum_64<constraint_type, var>(a_chunks, 0),
                    chunk_sum_64<constraint_type, var>(a_chunks, 1),
                    chunk_sum_64<constraint_type, var>(a_chunks, 2),
                    chunk_sum_64<constraint_type, var>(a_chunks, 3)
                };
                std::vector<constraint_type> b_64_chunks = {
                    chunk_sum_64<constraint_type, var>(b_chunks, 0),
                    chunk_sum_64<constraint_type, var>(b_chunks, 1),
                    chunk_sum_64<constraint_type, var>(b_chunks, 2),
                    chunk_sum_64<constraint_type, var>(b_chunks, 3)
                };
                std::vector<constraint_type> r_64_chunks = {
                    chunk_sum_64<constraint_type, var>(r_chunks, 0),
                    chunk_sum_64<constraint_type, var>(r_chunks, 1),
                    chunk_sum_64<constraint_type, var>(r_chunks, 2),
                    chunk_sum_64<constraint_type, var>(r_chunks, 3)
                };
                constraint_type c_1_64 = chunk_sum_64<constraint_type, var>(c_1_chunks, 0);
                constraint_type c_3_64 = chunk_sum_64<constraint_type, var>(c_3_chunks, 0);
                constraint_type first_carryless = first_carryless_consrtruct<constraint_type>(
                    a_64_chunks, b_64_chunks, r_64_chunks);
                constraints.push_back({position, (first_carryless - c_1_64 * two128 - c_2 * two192)});
                constraint_type second_carryless = second_carryless_construct<constraint_type>(
                    a_64_chunks, b_64_chunks, r_64_chunks);
                constraints.push_back({ position, (second_carryless + c_1_64 + c_2 * two_64 - c_3_64 * two128 - c_4 * two192)});
                // add constraints for c_2/c_4: c_2 is 0/1, c_4 is 0/1/2/3
                constraints.push_back({position, c_2 * (c_2 - 1)});
                constraints.push_back({position, c_4 * (c_4 - 1) * (c_4 - 2) * (c_4 - 3)});

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

                word_type result = word_type(integral_type(a) << shift);

                word_type b = word_type(integral_type(1) << shift);

                const std::vector<value_type> input_b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(input_b);
                const std::vector<value_type> a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b);
                const std::vector<value_type> r_chunks = zkevm_word_to_field_element<BlueprintFieldType>(result);
                const std::size_t chunk_amount = a_chunks.size();

                value_type b0p   = integral_type(input_b) % 16,
                           b0pp  = (integral_type(input_b) / 16) % 16,
                           b0ppp = (integral_type(input_b) % 65536) / 256,
                           I1    = b0ppp.is_zero() ? 0 : b0ppp.inversed();

                value_type sum_b = 0;
                for(std::size_t i = 1; i < chunk_amount; i++) {
                    sum_b += input_b_chunks[i];
                }
                value_type I2 = sum_b.is_zero() ? 0 : sum_b.inversed(),
                           z = (1 - b0ppp * I1) * (1 - sum_b * I2), // z is zero if input_b >= 256, otherwise it is 1
                           tp = z * (static_cast<unsigned int>(1) << int(integral_type(input_b) % 16));

                // note that we don't assign 64-chunks for a/b, as we can build them from 16-chunks with constraints
                // under the same logic we only assign the 16-bit chunks for carries
                std::vector<value_type> a_64_chunks, b_64_chunks, r_64_chunks;
                for (std::size_t i = 0; i < 4; i++) {
                    a_64_chunks.push_back(chunk_sum_64<value_type>(a_chunks, i));
                    b_64_chunks.push_back(chunk_sum_64<value_type>(b_chunks, i));
                    r_64_chunks.push_back(chunk_sum_64<value_type>(r_chunks, i));
                }
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                assignment_type &assignment = zkevm_circuit.get_assignment();
                const std::size_t curr_row = zkevm_circuit.get_current_row();
                // caluclate first row carries
                auto first_row_carries =
                    first_carryless_consrtruct(a_64_chunks, b_64_chunks, r_64_chunks).data >> 128;
                value_type c_1 = static_cast<value_type>(first_row_carries & (two_64 - 1).data);
                value_type c_2 = static_cast<value_type>(first_row_carries >> 64);
                std::vector<value_type> c_1_chunks = chunk_64_to_16<BlueprintFieldType>(c_1);
                // no need for c_2 chunks as there is only a single chunk
                auto second_row_carries =
                    (second_carryless_construct(a_64_chunks, b_64_chunks, r_64_chunks) + c_1 + c_2 * two_64).data >> 128;
                value_type c_3 = static_cast<value_type>(second_row_carries & (two_64 - 1).data);
                value_type c_4 = static_cast<value_type>(second_row_carries >> 64);
                std::vector<value_type> c_3_chunks = chunk_64_to_16<BlueprintFieldType>(c_3);
                // TODO: replace with memory access, which would also do range checks!
                // also we can pack slightly more effectively
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row) = input_b_chunks[i];
                }
                assignment.witness(witness_cols[chunk_amount], curr_row) = b0p;
                assignment.witness(witness_cols[chunk_amount + 1], curr_row) = b0pp;
                assignment.witness(witness_cols[chunk_amount + 2], curr_row) = b0ppp;
                assignment.witness(witness_cols[2*chunk_amount], curr_row) = I1;
                assignment.witness(witness_cols[2*chunk_amount + 1], curr_row) = I2;
                assignment.witness(witness_cols[chunk_amount + 5], curr_row) = z;
                assignment.witness(witness_cols[chunk_amount + 6], curr_row) = tp;

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 1) = a_chunks[i];
                    assignment.witness(witness_cols[2*chunk_amount + i], curr_row + 1) = (b0p - i).is_zero()? 0 : (b0p - i).inversed();
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 2) = b_chunks[i];
                    assignment.witness(witness_cols[2*chunk_amount + i], curr_row + 2) = (b0pp - i).is_zero()? 0 : (b0pp - i).inversed();
                }
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 3) = r_chunks[i];
                }

                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 3) = c_1_chunks[i];
                }
                assignment.witness(witness_cols[chunk_amount + 4], curr_row + 3) = c_2;

                for (std::size_t i = 0; i < 4; i++) {
                    assignment.witness(witness_cols[i + chunk_amount + 5], curr_row + 3) = c_3_chunks[i];
                }
                assignment.witness(witness_cols[chunk_amount + 9], curr_row + 3) = c_4;

                // stack.push(input_b);
                // stack.push(a);
                stack.push(result);
            }

            std::size_t rows_amount() override {
                return 4;
            }
        };
    }   // namespace blueprint
}   // namespace nil
