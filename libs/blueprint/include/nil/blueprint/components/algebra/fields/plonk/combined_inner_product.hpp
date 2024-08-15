//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_COMBINED_INNER_PRODUCT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_COMBINED_INNER_PRODUCT_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<typename ArithmetizationType, std::size_t k, std::size_t... WireIndexes>
                class combined_inner_product;

                template<typename BlueprintFieldType, std::size_t k, std::size_t W0,
                         std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6,
                         std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11,
                         std::size_t W12, std::size_t W13, std::size_t W14>
                class combined_inner_product<snark::plonk_constraint_system<BlueprintFieldType>,
                                             k, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    constexpr static const std::size_t selector_seed = 0xff70;

                    constexpr static const std::size_t witness_per_row = 5;

                    constexpr static const std::size_t main_rows =
                        (k + ((witness_per_row - (k % witness_per_row)) % witness_per_row)) / witness_per_row;

                public:
                    constexpr static const std::size_t rows_amount = 1 + main_rows;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        std::array<var, k> f_zeta1;
                        std::array<var, k> f_zeta2;
                        var xi;
                        var r;
                    };

                    struct result_type {
                        var output;

                        result_type(const params_type &params, std::size_t component_start_row) {
                            output = var(W2, component_start_row + rows_amount - 1, false);
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         std::size_t start_row_index) {

                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, start_row_index,
                                                   start_row_index + rows_amount - 2);

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        return result_type(params, start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        typename BlueprintFieldType::value_type xi = assignment.var_value(params.xi);
                        typename BlueprintFieldType::value_type r = assignment.var_value(params.r);
                        constexpr static const std::size_t rem = k % witness_per_row;
                        constexpr static const std::size_t k_size = k + ((witness_per_row - rem) % witness_per_row);
                        std::array<typename BlueprintFieldType::value_type, k_size> f_zeta1;
                        std::array<typename BlueprintFieldType::value_type, k_size> f_zeta2;
                        for (std::size_t i = 0; i < k_size; i++) {
                            if (i < k) {
                                f_zeta1[i] = assignment.var_value(params.f_zeta1[i]);
                                f_zeta2[i] = assignment.var_value(params.f_zeta2[i]);
                            } else {
                                f_zeta1[i] = 0;
                                f_zeta2[i] = 0;
                            }
                        }
                        typename BlueprintFieldType::value_type s = 0;
                        typename BlueprintFieldType::value_type acc_xi = 1;

                        for (std::size_t i = row; i < row + rows_amount - 1; i++) {
                            assignment.witness(W0)[i] = r;
                            assignment.witness(W1)[i] = acc_xi;
                            assignment.witness(W2)[i] = s;
                            for (std::size_t j = 0; j < witness_per_row; j++) {
                                s += acc_xi * (f_zeta1[(i - row) * witness_per_row + j] +
                                               r * f_zeta2[(i - row) * witness_per_row + j]);
                                acc_xi *= xi;
                                assignment.witness(3 + j * 2)[i] = f_zeta1[(i - row) * witness_per_row + j];
                                assignment.witness(4 + j * 2)[i] = f_zeta2[(i - row) * witness_per_row + j];
                            }
                            assignment.witness(W13)[i] = xi;
                        }
                        assignment.witness(W0)[row + rows_amount - 1] = r;
                        assignment.witness(W1)[row + rows_amount - 1] = acc_xi;
                        assignment.witness(W2)[row + rows_amount - 1] = s;
                        assignment.witness(W13)[row + rows_amount - 1] = xi;

                        return result_type(params, start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                        auto constraint_1 = bp.add_constraint(var(W0, 0) - var(W0, +1));
                        auto constraint_2 = bp.add_constraint(var(W13, 0) - var(W13, +1));
                        snark::plonk_constraint<BlueprintFieldType> xi_deg = var(W13, +1);
                        for (int i = 0; i < witness_per_row - 1; i++) {
                            xi_deg = xi_deg * var(W13, +1);
                        }
                        auto constraint_3 = bp.add_constraint(var(W1, +1) - var(W1, 0) * xi_deg);
                        snark::plonk_constraint<BlueprintFieldType> s = var(W2, 0);
                        snark::plonk_constraint<BlueprintFieldType> acc_xi = var(W1, 0);
                        for (std::size_t j = 0; j < witness_per_row; j++) {
                            s = s + acc_xi * (var(3 + j * 2, 0) + var(W0, 0) * var(4 + j * 2, 0));
                            acc_xi = acc_xi * var(W13, 0);
                        }
                        auto constraint_4 = bp.add_constraint(var(W2, +1) - s);

                        bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3, constraint_4});
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {
                        bp.add_copy_constraint({{W0, static_cast<int>(component_start_row), false}, params.r});
                        bp.add_copy_constraint({{W13, static_cast<int>(component_start_row), false}, params.xi});
                        bp.add_copy_constraint({{W1, static_cast<int>(component_start_row), false},
                                                {0, static_cast<int32_t>(component_start_row + 1), false, var::column_type::constant}});
                        bp.add_copy_constraint({{W2, static_cast<int>(component_start_row), false},
                                                {0, static_cast<int32_t>(component_start_row), false, var::column_type::constant}});

                        for (std::size_t i = 0; i < k; i++) {
                            bp.add_copy_constraint(
                                {{3 + (2 * i) % 10, static_cast<int>(component_start_row + (i / 5)), false},
                                 params.f_zeta1[i]});
                            bp.add_copy_constraint(
                                {{4 + (2 * i) % 10, static_cast<int>(component_start_row + (i / 5)), false},
                                 params.f_zeta2[i]});
                        }
                    }

                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t component_start_row) {
                        std::size_t row = component_start_row;

                        assignment.constant(0)[row] = 0;
                        assignment.constant(0)[row + 1] = 1;
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_COMBINED_INNER_PRODUCT_HPP