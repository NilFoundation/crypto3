//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ELEMENT_POWERS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ELEMENT_POWERS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // for (base, n) calculates [base^0, base^1, ..., base^n]
                // n >= 0
                // Input: base, n
                // Output: [base^0, base^1, ..., base^n]
                template<typename ArithmetizationType, std::size_t n, std::size_t... WireIndexes>
                class element_powers;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t n, std::size_t W0,
                         std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6,
                         std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11,
                         std::size_t W12, std::size_t W13, std::size_t W14>
                class element_powers<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, n, W0,
                                     W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0f0c;

                public:
                    constexpr static const std::size_t rows_amount =
                        n <= 1 ? 1 : (n - 2) * mul_component::rows_amount + 1;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var base;
                        var one;
                    };

                    struct result_type {
                        std::array<var, n> output;

                        result_type(std::size_t component_start_row) {
                            output[0] = var(W0, component_start_row, false);
                            if (n > 0) {
                                output[1] = var(W1, component_start_row, false);
                            }
                            for (std::size_t i = 2; i < n; i++) {
                                output[i] = typename mul_component::result_type(component_start_row + i - 1).output;
                            }
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        var base(W1, start_row_index, false);
                        var last_result(W1, start_row_index, false);
                        std::size_t row = start_row_index + 1;
                        for (std::size_t i = 2; i < n; i++) {
                            last_result = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                          {base, last_result}, row)
                                              .output;
                            row += mul_component::rows_amount;
                        }

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        assignment.witness(W0)[start_row_index] = 1;
                        assignment.witness(W1)[start_row_index] = assignment.var_value(params.base);
                        var base(W1, start_row_index, false);
                        var last_result(W1, start_row_index, false);
                        row++;

                        for (std::size_t i = 2; i < n; i++) {
                            last_result =
                                mul_component::generate_assignments(assignment, {base, last_result}, row).output;
                            row += mul_component::rows_amount;
                        }

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {

                        bp.add_copy_constraint({{W0, static_cast<int>(start_row_index), false}, params.one});
                        bp.add_copy_constraint({{W1, static_cast<int>(start_row_index), false}, params.base});
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ELEMENT_POWERS_HPP