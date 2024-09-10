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

        enum cmp_type { C_LT, C_EQ, C_GT, C_SLT, C_SGT };

        template<typename BlueprintFieldType>
        class zkevm_cmp_operation : public zkevm_operation<BlueprintFieldType> {
        public:
            using op_type = zkevm_operation<BlueprintFieldType>;
            using gate_class = typename op_type::gate_class;
            using constraint_type = typename op_type::constraint_type;
            using lookup_constraint_type = crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
            using zkevm_circuit_type = typename op_type::zkevm_circuit_type;
            using assignment_type = typename op_type::assignment_type;
            using value_type = typename BlueprintFieldType::value_type;
            using var = typename op_type::var;

            zkevm_cmp_operation(cmp_type _cmp_operation) : cmp_operation(_cmp_operation) {}

            cmp_type cmp_operation;

            constexpr static const std::size_t carry_amount = 16 / 3 + 1;
            constexpr static const value_type two_16 = 65536;
            constexpr static const value_type two_32 = 4294967296;
            constexpr static const value_type two_48 = 281474976710656;

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

                // Table layout
                // +----------------+--------------------------------+----------------+
                // |       a        |                                |                |
                // +----------------+--------------------------------+----------------+
                // |       b        |EQ:res; SGT,SLT: ax,a-,cx,c-,res|1/B| (EQ only)  |
                // +----------------+--------------------------------+----------------+
                // |       c        |carry|                          |                |
                // +----------------+--------------------------------+----------------+

                std::size_t position = 1;
                auto constraint_gen = [&constraints, &position]
                        (var a_0, var a_1, var a_2,
                         var b_0, var b_1, var b_2,
                         var r_0, var r_1, var r_2,
                         var last_carry, var result_carry, bool first_constraint = false) {
                    if (first_constraint) {
                        // no last carry for first constraint
                        constraints.push_back({ position, (
                                (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                                - r_0 - r_1 * two_16 - r_2 * two_32 - result_carry * two_48)});

                    } else {
                        constraints.push_back({ position, (
                                last_carry + (a_0 + b_0) + (a_1 + b_1) * two_16 + (a_2 + b_2) * two_32
                                - r_0 - r_1 * two_16 - r_2 * two_32 - result_carry * two_48)});
                    }
                    constraints.push_back({position, result_carry * (result_carry - 1)});
                };
                auto last_constraint_gen = [&constraints, &position]
                        (var a_0, var b_0, var r_0, var last_carry, var result_carry) {
                    constraints.push_back({ position, (last_carry + a_0 + b_0 - r_0 - result_carry * two_16)});
                    constraints.push_back({ position, result_carry * (result_carry - 1)});
                };
                std::vector<var> a_chunks;
                std::vector<var> b_chunks;
                std::vector<var> r_chunks;
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    a_chunks.push_back(var_gen(i, -1));
                    b_chunks.push_back(var_gen(i, 0));
                    r_chunks.push_back(var_gen(i, +1));
                }
                std::vector<var> r_carry;
                for (std::size_t i = 0; i < carry_amount; i++) {
                    r_carry.push_back(var_gen(i + chunk_amount, +1));
                }

                // special first constraint
                constraint_gen(a_chunks[0], a_chunks[1], a_chunks[2],
                               b_chunks[0], b_chunks[1], b_chunks[2],
                               r_chunks[0], r_chunks[1], r_chunks[2],
                               r_carry[0], r_carry[0], true);
                for (std::size_t i = 1; i < carry_amount - 1; i++) {
                    constraint_gen(a_chunks[3 * i], a_chunks[3 * i + 1], a_chunks[3 * i + 2],
                                   b_chunks[3 * i], b_chunks[3 * i + 1], b_chunks[3 * i + 2],
                                   r_chunks[3 * i], r_chunks[3 * i + 1], r_chunks[3 * i + 2],
                                   r_carry[i - 1], r_carry[i]);
                }
                last_constraint_gen(a_chunks[3 * (carry_amount - 1)], b_chunks[3 * (carry_amount - 1)],
                                    r_chunks[3 * (carry_amount - 1)],
                                    r_carry[carry_amount - 2], r_carry[carry_amount - 1]);
                if (cmp_operation == C_EQ) {
                    // additional constraints for checking if b = 0
                    constraint_type b_chunk_sum = b_chunks[0];
                    for(std::size_t i = 1; i < chunk_amount; i++) {
                        b_chunk_sum += b_chunks[i];
                    }
                    var b_chunk_sum_inverse = var_gen(2*chunk_amount, 0),
                        result = var_gen(chunk_amount + 1,0);

                    constraints.push_back({position, (b_chunk_sum * b_chunk_sum_inverse + result - 1)});
                    constraints.push_back({position, b_chunk_sum * result});
                } else if ((cmp_operation == C_SLT) || (cmp_operation == C_SGT)) {
                    // additional constraints for computing and accounting for the signs of a and r
                    var c = r_carry[carry_amount-1],
                        a_top = a_chunks[chunk_amount-1],
                        a_aux = var_gen(chunk_amount,0),
                        a_neg = var_gen(chunk_amount+1,0),
                        r_top = r_chunks[chunk_amount-1],
                        r_aux = var_gen(chunk_amount+2,0),
                        r_neg = var_gen(chunk_amount+3,0),
                        result = var_gen(chunk_amount+4,0);
                    value_type two_15 = 32768;
                    // a_top + 2^15 = a_aux + 2^16 * a_neg
                    constraints.push_back({position, a_neg * (1 - a_neg)});
                    constraints.push_back({position, (a_top + two_15 - two_16 * a_neg - a_aux)});
                    // r_top + 2^15 = r_aux + 2^16 * r_neg
                    constraints.push_back({position, r_neg * (1 - r_neg)});
                    constraints.push_back({position, (r_top + two_15 - two_16 * r_neg - r_aux)});

                    // result = (r_neg & !a_neg) | ((r_neg&a_neg | !r_neg & !a_neg  )& c) =
                    // = (r_neg & !a_neg) | (c & !a_neg) | (c & r_neg) =
                    // = r_neg(1-a_neg) + c(1-a_neg) + c r_neg - 2*r_neg(1-a_neg)c
                    constraints.push_back({position, (r_neg*(1-a_neg) + c*(1-a_neg) + c*r_neg - 2*c*r_neg*(1-a_neg) - result)});
                }
                return {{gate_class::MIDDLE_OP, {constraints, {}}}};
            }

            void generate_assignments(zkevm_circuit_type &zkevm_circuit, zkevm_machine_interface &machine) override {
                zkevm_stack &stack = machine.stack;
                using word_type = typename zkevm_stack::word_type;
                using integral_type = boost::multiprecision::number<
                    boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                auto is_negative = [](word_type x) {
                     return (integral_type(x) > zkevm_modulus/2 - 1);
                };

                word_type x = stack.pop();
                word_type y = stack.pop();
                word_type r;

                if ((cmp_operation == C_LT) || (cmp_operation == C_SLT)) {
                    r = (integral_type(x) < integral_type(y));
                } else {
                    r = (integral_type(x) > integral_type(y));
                }

                word_type result;
                if (cmp_operation == C_SLT) {
                    result = (is_negative(x) && !is_negative(y)) || ((is_negative(x) == is_negative(y)) && r);
                } else if (cmp_operation == C_SGT) {
                    result = (!is_negative(x) && is_negative(y)) || ((is_negative(x) == is_negative(y)) && r);
                } else if (cmp_operation == C_EQ) {
                    result = (x == y);
                } else {
                    result = r;
                }

                // comparison is done by evaluating r (the carry) in a valid relation a + b = c + r*2^T, T = 256
                // E.g., y + z = x + 2^T <=> x < y; y + z = x <=> x <= y
                word_type a, b, c;
                if ((cmp_operation == C_LT) || (cmp_operation == C_SLT)) {
                    a = y;
                    c = x;
                } else {
                    a = x;
                    c = y;
                }
                b = word_type(integral_type(c) + integral_type(r)*zkevm_modulus - integral_type(a));

                const std::vector<value_type> a_chunks = zkevm_word_to_field_element<BlueprintFieldType>(a);
                const std::vector<value_type> b_chunks = zkevm_word_to_field_element<BlueprintFieldType>(b);
                const std::vector<value_type> r_chunks = zkevm_word_to_field_element<BlueprintFieldType>(c);
                const std::vector<std::size_t> &witness_cols = zkevm_circuit.get_opcode_cols();
                assignment_type &assignment = zkevm_circuit.get_assignment();
                const std::size_t curr_row = zkevm_circuit.get_current_row();
                std:size_t chunk_amount = 16;

                // TODO: replace with memory access, which would also do range checks!
                // NB! we need range checks on b, since it's generated here!
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row) = a_chunks[i];
                }

                value_type b_sum = value_type::zero();
                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 1) = b_chunks[i];
                    b_sum += b_chunks[i];
                }
                if (cmp_operation == C_EQ) {
                    assignment.witness(witness_cols[2*chunk_amount], curr_row + 1) =
                        b_sum.is_zero() ? value_type::zero() : value_type::one() * b_sum.inversed();
                    assignment.witness(witness_cols[chunk_amount + 1], curr_row + 1) = integral_type(result);
                }

                for (std::size_t i = 0; i < chunk_amount; i++) {
                    assignment.witness(witness_cols[i], curr_row + 2) = r_chunks[i];
                }

                if ((cmp_operation == C_SLT) || (cmp_operation == C_SGT)) {
                    integral_type two_15 = 32768,
                                  biggest_a_chunk = integral_type(a) >> (256 - 16),
                                  biggest_r_chunk = integral_type(c) >> (256 - 16);

                    // find the sign bit by adding 2^16/2 to the biggest chunk. The carry-on bit is 1 iff the sign bit is 1
                    assignment.witness(witness_cols[chunk_amount], curr_row + 1) =
                        (biggest_a_chunk > two_15 - 1) ? (biggest_a_chunk - two_15) : biggest_a_chunk + two_15;
                    assignment.witness(witness_cols[chunk_amount + 1], curr_row + 1) = (biggest_a_chunk > two_15 - 1);

                    assignment.witness(witness_cols[chunk_amount + 2], curr_row + 1) =
                        (biggest_r_chunk > two_15 - 1) ? (biggest_r_chunk - two_15) : biggest_r_chunk + two_15;
                    assignment.witness(witness_cols[chunk_amount + 3], curr_row + 1) = (biggest_r_chunk > two_15 - 1);

                    assignment.witness(witness_cols[chunk_amount + 4], curr_row + 1) = integral_type(result);
                }

                // we might want to pack carries more efficiently?
                bool carry = 0;
                for (std::size_t i = 0; i < carry_amount - 1; i++) {
                    carry = (carry + a_chunks[3 * i    ] + b_chunks[3 * i    ] +
                                    (a_chunks[3 * i + 1] + b_chunks[3 * i + 1]) * two_16 +
                                    (a_chunks[3 * i + 2] + b_chunks[3 * i + 2]) * two_32 ) >= two_48;
                    assignment.witness(witness_cols[i + chunk_amount], curr_row + 2) = carry;
                }
                carry = (carry + a_chunks[3 * (carry_amount - 1)] + b_chunks[3 * (carry_amount - 1)]) >= two_16;
                BOOST_ASSERT(carry == r);
                assignment.witness(witness_cols[chunk_amount + carry_amount - 1], curr_row + 2) = carry;

                //stack.push(y);
                //stack.push(x);
                stack.push(result);
            }

            std::size_t rows_amount() override {
                return 3;
            }
        };
    }   // namespace blueprint
}   // namespace nil
