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
        class zkevm_byte_operation : public zkevm_operation<BlueprintFieldType> {
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
                // i is the offset from the MOST SIGNIFICANT BYTE
                // i0p = p + 2n
                // +-------------------+-+---+-+-+--+--+--+-+-+--------------+
                // |         i         | |i0p|p|n|xn|x'|x"|r|I|              | 1
                // +-------------------+-+---+-+-+--+--+--+-+-+--------------+
                // |         x         |                    |    (j-n)^{-1}  | 0
                // +-------------------+--------------------+----------------+

                std::size_t position = 0;

                std::vector<var> i_chunks;
                std::vector<var> x_chunks;
                std::vector<var> indic;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    i_chunks.push_back(var_gen(i, -1));
                    x_chunks.push_back(var_gen(i, 0));
                    indic.push_back(var_gen(2*chunk_amount + i, 0));
                }
                var I_var   = var_gen(2*chunk_amount, -1),
                    i0p_var = var_gen(chunk_amount + 1, -1),
                    p_var   = var_gen(chunk_amount + 2, -1),
                    n_var   = var_gen(chunk_amount + 3, -1),
                    xn_var  = var_gen(chunk_amount + 4, -1),
                    xp_var  = var_gen(chunk_amount + 5, -1),
                    xpp_var = var_gen(chunk_amount + 6, -1),
                    r_var   = var_gen(chunk_amount + 7, -1);

                constraint_type i_sum;
                for(std::size_t j = 1; j < chunk_amount; j++) {
                    i_sum += i_chunks[j];
                }
                constraints.push_back({position, i_sum * (1 - I_var * i_sum)});

                constraints.push_back({position, (i0p_var - i_chunks[0]*(1 - i_sum*I_var) - 32*i_sum*I_var)});

                constraints.push_back({position, p_var * (1 - p_var)});
                constraints.push_back({position, (i0p_var - p_var - 2*n_var)});
                // lookup constraint to assure n_var < 32768
                lookup_constraints.push_back({position, {range_check_table_index, {2 * n_var}}});

                constraint_type x_sum;
                for(std::size_t j = 0; j < chunk_amount; j++) {
                    x_sum += x_chunks[chunk_amount-1 - j] * (1 - (j - n_var)*indic[j]);
                }
                constraints.push_back({position, (xn_var - x_sum)});
                constraints.push_back({position, (xn_var - xp_var*256 - xpp_var)});
                // lookup constraints for to assure xp_var, xpp_var < 256
                lookup_constraints.push_back({position, {range_check_table_index, {256 * xp_var}}});
                lookup_constraints.push_back({position, {range_check_table_index, {256 * xpp_var}}});

                constraints.push_back({position, (r_var - (1-p_var)*xp_var - p_var*xpp_var)});

                for(std::size_t j = 0; j < chunk_amount; j++) {
                    constraints.push_back({position, ((j - n_var)*(1 - (j - n_var)*indic[j]))});
                }

                return {{gate_class::MIDDLE_OP, {constraints, lookup_constraints}}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                zkevm_stack &stack = machine.stack;
                using word_type = typename zkevm_stack::word_type;
                using integral_type = boost::multiprecision::number<
                    boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                word_type i = stack.pop();
                word_type x = stack.pop();
                int shift = (integral_type(i) < 32) ? int(integral_type(i)) : 32;
                word_type result = word_type((integral_type(x) << ((8*shift) + 1)) >> (31*8 + 1));
                                                            // +1 because integral type is 257 bits long

                unsigned int i0 = static_cast<unsigned int>(integral_type(i) % 65536),
                             i0p = (integral_type(i) > 65535) ? 32 : i0;
                int parity = i0p % 2,
                    n = (i0p - parity) / 2;
                unsigned int xn = static_cast<unsigned int>((integral_type(x) << (16*n + 1)) >> (16*15 + 1)),
                                                           // +1 because integral_type is 257 bits long
                             xpp = xn % 256,
                             xp = (xn - xpp) / 256;

                const std::vector<value_type> i_chunks = zkevm_word_to_field_element<BlueprintFieldType>(i);
                const std::vector<value_type> x_chunks = zkevm_word_to_field_element<BlueprintFieldType>(x);

                size_t chunk_amount = i_chunks.size();
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                assignment_type &assignment = zkevm_circuit.get_assignment();
                const std::size_t curr_row = zkevm_circuit.get_current_row();

                // TODO: replace with memory access, which would also do range checks!
                for(std::size_t j = 0; j < chunk_amount; j++) {
                    assignment.witness(witness_cols[j], curr_row) = i_chunks[j];
                    assignment.witness(witness_cols[j], curr_row + 1) = x_chunks[j];

                    value_type cur_j = j,
                               val_n = n,
                               indic = (cur_j == val_n) ? 0 : (cur_j-val_n).inversed();
                    assignment.witness(witness_cols[2*chunk_amount + j], curr_row + 1) = indic;
                }
                value_type sum_i = 0;
                for(std::size_t j = 1; j < chunk_amount; j++) {
                    sum_i += i_chunks[j];
                }
                assignment.witness(witness_cols[2*chunk_amount], curr_row) = sum_i.is_zero() ? 0 : sum_i.inversed();
                assignment.witness(witness_cols[chunk_amount + 1], curr_row) = i0p;

                assignment.witness(witness_cols[chunk_amount + 2], curr_row) = parity;
                assignment.witness(witness_cols[chunk_amount + 3], curr_row) = n;

                assignment.witness(witness_cols[chunk_amount + 4], curr_row) = xn; // n is the offset from MSW
                assignment.witness(witness_cols[chunk_amount + 5], curr_row) = xp;
                assignment.witness(witness_cols[chunk_amount + 6], curr_row) = xpp;
                assignment.witness(witness_cols[chunk_amount + 7], curr_row) = static_cast<value_type>(integral_type(result));

                // stack.push(x);
                // stack.push(i);
                stack.push(result);
            }

            std::size_t rows_amount() override {
                return 2;
            }
        };
    }   // namespace blueprint
}   // namespace nil
