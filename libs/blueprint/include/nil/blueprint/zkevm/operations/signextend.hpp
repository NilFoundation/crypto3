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
        class zkevm_signextend_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

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
                // b is the number of the most significant byte to include into x, starting from the least significant one
                // b = p + 2n                                                               Row #
                // +-----------------------+-+---+-+-+--+--+--+--+---+----+-+---------------+
                // |            b          | |b0p|p|n|xn|x'|x"|sb|sgn|saux|I|               | 1
                // +-----------------------+-+---+-+-+--+--+--+--+---+----+-+---------------+
                // |            x          |              r               |    (j-n)^{-1}   | 0
                // +-----------------------+------------------------------+-----------------+

                std::size_t position = 0;

                std::vector<var> b_chunks;
                std::vector<var> x_chunks;
                std::vector<var> r_chunks;
                std::vector<var> indic;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    b_chunks.push_back(var_gen(i, -1));
                    x_chunks.push_back(var_gen(i, 0));
                    r_chunks.push_back(var_gen(chunk_amount + i, 0));
                    indic.push_back(var_gen(2*chunk_amount + i, 0));
                }

                var I_var   = var_gen(2*chunk_amount, -1),
                    b0p_var = var_gen(chunk_amount + 1, -1),
                    p_var   = var_gen(chunk_amount + 2, -1),
                    n_var   = var_gen(chunk_amount + 3, -1),
                    xn_var  = var_gen(chunk_amount + 4, -1),
                    xp_var  = var_gen(chunk_amount + 5, -1),
                    xpp_var = var_gen(chunk_amount + 6, -1),
                    sb_var  = var_gen(chunk_amount + 7, -1),
                    sgn_var = var_gen(chunk_amount + 8, -1),
                    saux_var= var_gen(chunk_amount + 9, -1);

                constraint_type b_sum;
                for(std::size_t j = 1; j < chunk_amount; j++) {
                    b_sum += b_chunks[j];
                }
                constraints.push_back({position, b_sum * (1 - I_var * b_sum)});

                constraints.push_back({position, (b0p_var - b_chunks[0]*(1 - b_sum*I_var) - 32*b_sum*I_var)});

                constraints.push_back({position, p_var * (1 - p_var)});
                constraints.push_back({position, (b0p_var - p_var - 2*n_var)});
                // lookup constraint for n_var < 32768
                lookup_constraints.push_back({position, {range_check_table_index, {2 * n_var}}});

                constraint_type x_sum;
                for(std::size_t j = 0; j < chunk_amount; j++) {
                    x_sum += x_chunks[j] * (1 - (j - n_var)*indic[j]);
                }
                constraints.push_back({position, (xn_var - x_sum)});
                constraints.push_back({position, (xn_var - xp_var*256 - xpp_var)});
                // lookup constraints for xp_var, xpp_var < 256
                lookup_constraints.push_back({position, {range_check_table_index, {256 * xp_var}}});
                lookup_constraints.push_back({position, {range_check_table_index, {256 * xpp_var}}});

                constraints.push_back({position, (sb_var - (1-p_var)*xpp_var - p_var*xp_var)});

                constraints.push_back({position, sgn_var * (1-sgn_var)});
                // lookup constraints for saux_var < 256
                lookup_constraints.push_back({position, {range_check_table_index, {256 * saux_var}}});
                constraints.push_back({position, (sb_var + 128 - saux_var - 256*sgn_var)});

                for(std::size_t j = 0; j < chunk_amount; j++) {
                    constraints.push_back({position, ((j - n_var)*(1 - (j - n_var)*indic[j]))});
                }

                constraint_type is_transition[chunk_amount],
                                is_sign[chunk_amount]; // is_sign[i] = is_transition[0] + .... + is_transition[i-1]

                for(std::size_t i = 0; i < chunk_amount; i++) {
                    is_transition[i] = 1 - (i - n_var)*indic[i];
                    for(std::size_t j = i + 1; j < chunk_amount; j++) {
                        is_sign[j] += is_transition[i];
                    }
                }
                for(std::size_t i = 0; i < chunk_amount; i++) {
                    constraints.push_back({position, (r_chunks[i] - is_sign[i]*sgn_var*65535
                                                                  - is_transition[i]*((1-p_var)*(sb_var + 256*255*sgn_var) + p_var*xn_var)
                                                                  - (1 - is_sign[i] - is_transition[i])*x_chunks[i])});
                }

                return {{gate_class::MIDDLE_OP, {constraints, lookup_constraints}}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                zkevm_stack &stack = machine.stack;
                using word_type = typename zkevm_stack::word_type;
                using integral_type = boost::multiprecision::number<
                    boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                word_type b = stack.pop();
                word_type x = stack.pop();
                int len = (integral_type(b) < 32) ? int(integral_type(b)) + 1 : 32;
                integral_type sign = (integral_type(x) << (8*(32-len) + 1)) >> 256;
                word_type result = word_type((((integral_type(1) << 8*(32-len)) - 1) << 8*len)*sign) +
                                   word_type((integral_type(x) << (8*(32-len) + 1)) >> (8*(32-len) + 1));
                                                            // +1 because integral type is 257 bits long

                unsigned int b0 = static_cast<unsigned int>(integral_type(b) % 65536),
                             b0p = (integral_type(b) > 65535) ? 32 : b0;
                int parity = b0p % 2,
                    n = (b0p - parity) / 2;
                unsigned int xn = static_cast<unsigned int>((integral_type(x) << (16*(n > 15 ? 16 : 15 - n) + 1)) >> (16*15 + 1)),
                                                                       // +1 because integral_type is 257 bits long
                             xpp = xn % 256,
                             xp = (xn - xpp) / 256,
                             sb = (parity == 0) ? xpp : xp,
                             sgn = (sb > 128),
                             saux = sb + 128 - sgn*256;

                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b);
                const std::vector<value_type> x_chunks = zkevm_word_to_field_element<BlueprintFieldType>(x);
                const std::vector<value_type> r_chunks = zkevm_word_to_field_element<BlueprintFieldType>(result);

                size_t chunk_amount = 16;
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                assignment_type &assignment = zkevm_circuit.get_assignment();
                const std::size_t curr_row = zkevm_circuit.get_current_row();

                // TODO: replace with memory access, which would also do range checks!
                for(std::size_t j = 0; j < chunk_amount; j++) {
                    assignment.witness(witness_cols[j], curr_row) = b_chunks[j];
                    assignment.witness(witness_cols[j], curr_row + 1) = x_chunks[j];
                    assignment.witness(witness_cols[chunk_amount + j], curr_row + 1) = r_chunks[j];

                    value_type cur_j = j,
                               val_n = n,
                               indic = (cur_j == val_n) ? 0 : (cur_j-val_n).inversed();
                    assignment.witness(witness_cols[2*chunk_amount + j], curr_row + 1) = indic;
                }

                value_type sum_b = 0;
                for(std::size_t j = 1; j < chunk_amount; j++) {
                    sum_b += b_chunks[j];
                }
                assignment.witness(witness_cols[2*chunk_amount], curr_row) = sum_b.is_zero() ? 0 : sum_b.inversed();
                assignment.witness(witness_cols[chunk_amount + 1], curr_row) = b0p;
                assignment.witness(witness_cols[chunk_amount + 2], curr_row) = parity;
                assignment.witness(witness_cols[chunk_amount + 3], curr_row) = n;
                assignment.witness(witness_cols[chunk_amount + 4], curr_row) = xn;
                assignment.witness(witness_cols[chunk_amount + 5], curr_row) = xp;
                assignment.witness(witness_cols[chunk_amount + 6], curr_row) = xpp;
                assignment.witness(witness_cols[chunk_amount + 7], curr_row) = sb;
                assignment.witness(witness_cols[chunk_amount + 8], curr_row) = sgn;
                assignment.witness(witness_cols[chunk_amount + 9], curr_row) = saux;

                //stack.push(x);
                //stack.push(b);
                stack.push(result);
            }

            std::size_t rows_amount() override {
                return 2;
            }
        };
    }   // namespace blueprint
}   // namespace nil
