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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ALGEBRA_FIELDS_ELEMENT_POWERS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ALGEBRA_FIELDS_ELEMENT_POWERS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // for (base, n) calculates [base^0, base^1, ..., base^n]
                template<typename ArithmetizationType, typename CurveType, std::size_t n, std::size_t... WireIndexes>
                class element_powers;

                template<
                         typename CurveType,
                         std::size_t n,
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
                class element_powers<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type>,
                    CurveType,
                    n,
                    W0,
                    W1,
                    W2,
                    W3,
                    W4,
                    W5,
                    W6,
                    W7,
                    W8,
                    W9,
                    W10,
                    W11,
                    W12,
                    W13,
                    W14> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0fff;

                public:
                    constexpr static const std::size_t rows_amount = n * mul_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var base;
                        var n;
                        var one;
                    };

                    struct result_type {
                        std::array<var, n> output;

                        result_type(std::size_t component_start_row) {
                            if (n > 0) {
                                output[0] = var(W0, component_start_row, false);
                            }
                            if (n > 1) {
                                output[1] = var(W1, component_start_row, false);
                            }
                            for (std::size_t i = 2; i < n; i++) {
                                output[i] = mul_component::result_type(component_start_row + i).output;
                            }
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::cout << "ELEMENT POWERS COMPONENT IS NOT IMPLEMENTED" << std::endl;

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(params, start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::vector<var> res(n);
                        if (n < 2) {
                            res.resize(2);
                        }
                        assignment.witness(W0)[row] = 1;
                        res[0] = var(0, row, false);
                        typename BlueprintFieldType::value_type base_value = assignment.var_value(x);
                        assignment.witness(W0 + 1)[row] = base_value;
                        res[1] = var(W0 + 1, row, false);
                        typename BlueprintFieldType::value_type prev_value = base_value;
                        std::size_t column_idx = 2;

                        for (std::size_t i = 2; i < n; i++) {
                            // we need to copy any power of the element
                            // so we place them only on copy-constrainted columns
                            if (column_idx >= zk::snark::kimchi_constant::PERMUTES) {
                                column_idx = 0;
                                row++;
                            }
                            typename BlueprintFieldType::value_type new_value = prev_value * base_value;
                            assignment.witness(W0 + column_idx)[row] = new_value;
                            res[i] = var(W0 + i, row, false);
                            prev_value = new_value;
                        }

                        return res;
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {
                    }

                    static void
                        generate_copy_constraints(bblueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {

                        bp.add_copy_constraint({{W0, static_cast<int>(component_start_row), false}, params.one});
                        bp.add_copy_constraint({{W1, static_cast<int>(component_start_row), false}, params.base});
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ALGEBRA_FIELDS_ELEMENT_POWERS_HPP