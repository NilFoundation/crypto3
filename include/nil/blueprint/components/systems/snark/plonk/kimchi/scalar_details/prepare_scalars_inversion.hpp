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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_SCALAR_PREPARE_SCALARS_INVERSION_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_SCALAR_PREPARE_SCALARS_INVERSION_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // inverse function for prepare scalars
                // https://github.com/MinaProtocol/mina/blob/f01d3925a273ded939a80e1de9afcd9f913a7c17/src/lib/pickles_types/shifted_value.ml#L129
                template<typename ArithmetizationType, typename CurveType, std::size_t InputSize, std::size_t... WireIndexes>
                class prepare_scalars_inversion;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t InputSize, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8,
                         std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13,
                         std::size_t W14>
                class prepare_scalars_inversion<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                      CurveType, InputSize, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0f2C;

                    constexpr static bool scalar_larger() {
                        using ScalarField = typename CurveType::scalar_field_type;
                        using BaseField = typename CurveType::base_field_type;

                        auto n1 = ScalarField::modulus;
                        auto n2 = BaseField::modulus;

                        return n1 > n2;
                    }

                public:
                    constexpr static const std::size_t rows_amount =
                        InputSize * (add_component::rows_amount + mul_component::rows_amount);
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<var, InputSize> scalars;
                    };

                    struct result_type {
                        std::array<var, InputSize> output;
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constants(bp, assignment, params, start_row_index);

                        var shift = var(0, start_row_index, false, var::column_type::constant);
                        var coef = var(0, start_row_index + 1, false, var::column_type::constant);

                        std::size_t row = start_row_index;

                        std::array<var, InputSize> shifted;
                        result_type result;

                        for (std::size_t i = 0; i < InputSize; ++i) {
                            shifted[i] = zk::components::generate_circuit<add_component>(
                                             bp, assignment, {params.scalars[i], shift}, row)
                                             .output;
                            row += add_component::rows_amount;
                            result.output[i] =
                                zk::components::generate_circuit<mul_component>(bp, assignment, {shifted[i], coef}, row)
                                    .output;
                            row += mul_component::rows_amount;
                        }

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        return result;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        var shift = var(0, start_row_index, false, var::column_type::constant);
                        var coef = var(0, start_row_index + 1, false, var::column_type::constant);

                        std::size_t row = start_row_index;

                        std::array<var, InputSize> shifted;
                        result_type result;

                        for (std::size_t i = 0; i < InputSize; ++i) {
                            shifted[i] =
                                add_component::generate_assignments(assignment, {params.scalars[i], shift}, row).output;
                            row += add_component::rows_amount;
                            result.output[i] =
                                mul_component::generate_assignments(assignment, {shifted[i], coef}, row).output;
                            row += mul_component::rows_amount;
                        }

                        return result;
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
                    }

                    static void generate_assignments_constants(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        typename BlueprintFieldType::value_type base = 2;
                        if (scalar_larger()) {
                            assignment.constant(0)[row] = -base.pow(255);
                            row++;
                            assignment.constant(0)[row] = 1;
                        } else {
                            assignment.constant(0)[row] = -base.pow(255) - 1;
                            row++;
                            assignment.constant(0)[row] = 1 / base;
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_SCALAR_PREPARE_SCALARS_INVERSION_HPP