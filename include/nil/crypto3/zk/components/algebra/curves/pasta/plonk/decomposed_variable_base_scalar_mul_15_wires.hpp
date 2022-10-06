//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_DECOMPOSED_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_DECOMPOSED_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class curve_element_decomposed_variable_base_scalar_mul;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class curve_element_decomposed_variable_base_scalar_mul<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType, W0, W1, W2,
                    W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using add_component =
                        zk::components::curve_element_unified_addition<ArithmetizationType, CurveType, W0, W1, W2, W3,
                                                                       W4, W5, W6, W7, W8, W9, W10>;
                    using mul_component =
                        zk::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, W0, W1,
                                                                               W2, W3, W4, W5, W6, W7, W8, W9, W10, W11,
                                                                               W12, W13, W14>;
                    using mul_field_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                public:
                    constexpr static const std::size_t selector_seed = 0x0f45;
                    constexpr static const std::size_t rows_amount = 2 * mul_component::rows_amount +
                                                                     add_component::rows_amount +
                                                                     2 * mul_field_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        struct var_ec_point {
                            var x;
                            var y;
                        };

                        var_ec_point T;
                        var b1;
                        var b2;
                    };

                    struct result_type {
                        var X;
                        var Y;
                        result_type(std::size_t start_row_index) {
                            auto res = typename add_component::result_type(
                                typename add_component::params_type {{var(0, 0, false), var(0, 0, false)},
                                                                     {var(0, 0, false), var(0, 0, false)}},
                                start_row_index + 2 * mul_component::rows_amount +
                                    2 * mul_field_component::rows_amount);
                            X = res.X;
                            Y = res.Y;
                        }
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        auto mul_res =
                            mul_component::generate_assignments(assignment, {{params.T.x, params.T.y}, params.b1}, row);
                        row += mul_component::rows_amount;
                        auto const_mul_res = mul_component::generate_assignments(
                            assignment,
                            {{params.T.x, params.T.y}, var(0, start_row_index, false, var::column_type::constant)},
                            row);
                        row += mul_component::rows_amount;

                        auto x =
                            mul_field_component::generate_assignments(assignment, {const_mul_res.X, params.b2}, row)
                                .output;
                        row += mul_field_component::rows_amount;
                        auto y =
                            mul_field_component::generate_assignments(assignment, {const_mul_res.Y, params.b2}, row)
                                .output;
                        row += mul_field_component::rows_amount;

                        add_component::generate_assignments(assignment, {{x, y}, {mul_res.X, mul_res.Y}}, row);

                        return result_type(start_row_index);
                    }

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        auto mul_res =
                            mul_component::generate_circuit(bp, assignment, {{params.T.x, params.T.y}, params.b1}, row);
                        row += mul_component::rows_amount;
                        auto const_mul_res = mul_component::generate_circuit(
                            bp, assignment,
                            {{params.T.x, params.T.y}, var(0, start_row_index, false, var::column_type::constant)},
                            row);
                        row += mul_component::rows_amount;

                        auto x = zk::components::generate_circuit<mul_field_component>(
                                     bp, assignment, {const_mul_res.X, params.b2}, row)
                                     .output;
                        row += mul_field_component::rows_amount;
                        auto y = zk::components::generate_circuit<mul_field_component>(
                                     bp, assignment, {const_mul_res.Y, params.b2}, row)
                                     .output;
                        row += mul_field_component::rows_amount;

                        zk::components::generate_circuit<add_component>(bp, assignment,
                                                                        {{x, y}, {mul_res.X, mul_res.Y}}, row);

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type params,
                                               const std::size_t first_selector_index) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type params,
                                                  const std::size_t start_row_index) {
                    }

                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        typename BlueprintFieldType::integral_type one = 1;
                        assignment.constant(0)[row] = (one << 254);
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
