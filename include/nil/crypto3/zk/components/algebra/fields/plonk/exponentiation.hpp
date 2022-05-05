//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_EXPONENTIATION_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_EXPONENTIATION_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                        std::size_t ExponentSize,
                        std::size_t... WireIndexes>
                class exponentiation;

                // res = base.pow(scalar)
                // W0     | W1          | W2                                   | W3  | W4  | W5  | W6  | W7  | W8  | W9  | W10 | W11 | W12 | W13  | W14  |
                // base   | a = base^n  | n = [b_0 ... b_11]                   | b_0 | b_1 | b_2 | b_3 | b_4 | b_5 | b_6 | b_7 | b_8 | b_9 | b_10 | b_11 |
                // ...    | ...         | n = (n_prev << 12) || [b_0 ... b_11] | ... | ... | ... | ... | ...
                // base   | res         | n = scalar                           | ... | ... | ... | ... | ...
                // ....
                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::size_t ExponentSize,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class exponentiation<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    ExponentSize,
                    W0, W1, W2, W3, W4,
                    W5, W6, W7, W8, W9,
                    W10, W11, W12, W13, W14>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t bits_per_row = 12;
                    constexpr static const std::size_t padded_exponent_size = ExponentSize + 
                            ((bits_per_row - ExponentSize % bits_per_row) 
                                % bits_per_row); // for ExponentSize % bits_per_row = 0

                public:
                    constexpr static const std::size_t rows_amount = (ExponentSize % bits_per_row == 0) ?
                        (ExponentSize / bits_per_row) : (ExponentSize / bits_per_row) + 1;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var base;
                        var exponent;
                    };

                    struct result_type {
                        var result = var(0, 0);

                        result_type(const params_type &params,
                            const std::size_t &component_start_row) {
                                result = var(W1, component_start_row + rows_amount - 1, false);
                        }
                    };

                    static result_type generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {

                        generate_gates(bp, assignment, params, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);

                        return result_type(params, component_start_row);
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType>
                                &assignment,
                            const params_type &params,
                            const std::size_t &start_row_index) {

                        typename BlueprintFieldType::value_type base = assignment.var_value(params.base);
                        typename BlueprintFieldType::value_type exponent = assignment.var_value(params.exponent);

                        std::array<bool, padded_exponent_size> bits;
                        typename BlueprintFieldType::integral_type integral_exp = typename BlueprintFieldType::integral_type(exponent.data);
                        for (std::size_t i = 0; i < padded_exponent_size; i++) {
                            bits[padded_exponent_size - i - 1] = multiprecision::bit_test(integral_exp, i);
                        }

                        typename ArithmetizationType::field_type::value_type accumulated_n = 0;

                        std::size_t current_bit = 0;
                        for (std::size_t row = start_row_index; row < start_row_index + rows_amount; row++) {
                            assignment.witness(W0)[row] = base;

                            typename ArithmetizationType::field_type::value_type row_exponent = 0;

                            for (std::size_t bit_column = W3; bit_column < W3 + bits_per_row; bit_column++) {
                                assignment.witness(bit_column)[row] = bits[current_bit];

                                row_exponent = 2 * row_exponent + bits[current_bit];

                                current_bit++;
                            }

                            accumulated_n = (accumulated_n * (1 << bits_per_row)) + row_exponent;
                            assignment.witness(W1)[row] = power(base, accumulated_n.data);
                            assignment.witness(W2)[row] = accumulated_n;
                        }    

                        return result_type(params, start_row_index);
                    }

                    private:
                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {

                    }

                    static void generate_copy_constraints(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t &component_start_row){

                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_EXPONENTIATION_HPP