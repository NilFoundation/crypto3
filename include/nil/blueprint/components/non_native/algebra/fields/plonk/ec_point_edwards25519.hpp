//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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
// @file Declaration of interfaces for component to check if a point is on ed25519 curve.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_EC_POINT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_EC_POINT_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/non_native/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/components/non_native/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/non_native/algebra/fields/plonk/subtraction.hpp>
#include <nil/blueprint/components/non_native/algebra/fields/plonk/variable_base_multiplication_edwards25519.hpp>
#include <nil/blueprint/components/non_native/algebra/fields/plonk/non_native_range.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename CurveType, typename Ed25519Type,
                 std::size_t... WireIndexes>
            class ec_point;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams,
                     typename CurveType,
                      typename Ed25519Type,
                     std::size_t W0,
                     std::size_t W1,
                     std::size_t W2,
                     std::size_t W3,
                     std::size_t W4,
                     std::size_t W5,
                     std::size_t W6,
                     std::size_t W7,
                     std::size_t W8>
            class ec_point<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                   CurveType,
                                                    Ed25519Type,
                                                   W0,
                                                   W1,
                                                   W2,
                                                   W3,
                                                   W4,
                                                   W5,
                                                   W6,
                                                   W7,
                                                   W8> {

                typedef snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> ArithmetizationType;
                
                using variable_base_mult_component = variable_base_multiplication<ArithmetizationType, CurveType, Ed25519Type,
                W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                using mult_component = non_native_field_element_multiplication<ArithmetizationType, CurveType, Ed25519Type,
                W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                using add_component = non_native_field_element_addition<ArithmetizationType, CurveType, Ed25519Type,
                W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                using sub_component = non_native_field_element_subtraction<ArithmetizationType, CurveType, Ed25519Type,
                W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                using non_native_range_component = non_native_range<ArithmetizationType, CurveType,
                W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                using var = snark::plonk_variable<BlueprintFieldType>;
                constexpr static const std::size_t selector_seed = 0xfcd1;

            public:
                constexpr static const std::size_t rows_amount = 2 * non_native_range_component::rows_amount 
                                                                + 5 * mult_component::rows_amount 
                                                                + 2 * add_component::rows_amount;

                constexpr static const std::size_t gates_amount = 0;

                struct params_type {
                    struct var_ec_point {
                        std::array<var, 4> x;
                        std::array<var, 4> y;
                    };
                    var_ec_point pnt;
                };

                struct result_type {
                    result_type(std::size_t component_start_row) {
                    }
                };

                static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        std::size_t component_start_row) {
                    std::size_t row = component_start_row;

                    std::array<typename ArithmetizationType::field_type::value_type, 4> constant_one = {1, 0, 0, 0};

                    typename Ed25519Type::scalar_field_type::integral_type base = 1;
                    typename Ed25519Type::scalar_field_type::integral_type mask = (base << 66) - 1;

                    typename Ed25519Type::base_field_type::integral_type a_coef_val = typename Ed25519Type::base_field_type::integral_type(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec_cppui255);
                    std::array<typename Ed25519Type::base_field_type::integral_type, 4> a_coef = {a_coef_val & mask, (a_coef_val >>66) & mask, (a_coef_val >>132) & mask, (a_coef_val >>198) & mask};

                    typename Ed25519Type::base_field_type::integral_type d_coef_val = typename Ed25519Type::base_field_type::integral_type(0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3_cppui255);
                    std::array<typename Ed25519Type::base_field_type::integral_type, 4> d_coef = {d_coef_val & mask, (d_coef_val >>66) & mask, (d_coef_val >>132) & mask, (d_coef_val >>198) & mask};

                    for (int i = 0; i < 4; i++) {
                        assignment.constant(0)[component_start_row + i] = constant_one[i];
                        assignment.constant(0)[component_start_row + 4 + i] = a_coef[i];
                        assignment.constant(0)[component_start_row + 8 + i] = d_coef[i];
                    }

                    std::array<var, 4> one_var = {var(0, component_start_row, false, var::column_type::constant),
                                                var(0, component_start_row + 1, false, var::column_type::constant),
                                                var(0, component_start_row + 2, false, var::column_type::constant),
                                                var(0, component_start_row + 3, false, var::column_type::constant)};
                    std::array<var, 4> a_var = {var(0, component_start_row + 4, false, var::column_type::constant),
                                                var(0, component_start_row + 5, false, var::column_type::constant),
                                                var(0, component_start_row + 6, false, var::column_type::constant),
                                                var(0, component_start_row + 7, false, var::column_type::constant)};
                    std::array<var, 4> d_var = {var(0, component_start_row + 8, false, var::column_type::constant),
                                                var(0, component_start_row + 9, false, var::column_type::constant),
                                                var(0, component_start_row + 10, false, var::column_type::constant),
                                                var(0, component_start_row + 11, false, var::column_type::constant)};

                    /* a * x^2 + y^2 = 1 + d * x^2 * y^2 */
                    non_native_range_component::generate_assignments(assignment, {params.pnt.x}, row);
                    row += non_native_range_component::rows_amount;
                    non_native_range_component::generate_assignments(assignment, {params.pnt.y}, row);
                    row += non_native_range_component::rows_amount;

                    auto y_2 = mult_component::generate_assignments(assignment, {params.pnt.y, params.pnt.y}, row).output;
                    row += mult_component::rows_amount;
                    auto x_2 = mult_component::generate_assignments(assignment, {params.pnt.x, params.pnt.x}, row).output;
                    row += mult_component::rows_amount;

                    auto t0 = mult_component::generate_assignments(assignment, {x_2, a_var}, row).output;
                    row += mult_component::rows_amount;
                    auto left = add_component::generate_assignments(assignment, {y_2, t0}, row).output;
                    row += add_component::rows_amount;
                    auto t1 = mult_component::generate_assignments(assignment, {y_2, x_2}, row).output;
                    row += mult_component::rows_amount;
                    auto t2 = mult_component::generate_assignments(assignment, {d_var, t1}, row).output;
                    row += mult_component::rows_amount;
                    auto right = add_component::generate_assignments(assignment, {one_var, t2}, row).output;
                    row += add_component::rows_amount;
                    return result_type(component_start_row);
                }

                static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                    const params_type &params,
                                                    const std::size_t start_row_index){
                    std::size_t row = start_row_index;

                    std::array<var, 4> one_var = {var(0, start_row_index, false, var::column_type::constant),
                                                var(0, start_row_index + 1, false, var::column_type::constant),
                                                var(0, start_row_index + 2, false, var::column_type::constant),
                                                var(0, start_row_index + 3, false, var::column_type::constant)};
                    std::array<var, 4> a_var = {var(0, start_row_index + 4, false, var::column_type::constant),
                                                var(0, start_row_index + 5, false, var::column_type::constant),
                                                var(0, start_row_index + 6, false, var::column_type::constant),
                                                var(0, start_row_index + 7, false, var::column_type::constant)};
                    std::array<var, 4> d_var = {var(0, start_row_index + 8, false, var::column_type::constant),
                                                var(0, start_row_index + 9, false, var::column_type::constant),
                                                var(0, start_row_index + 10, false, var::column_type::constant),
                                                var(0, start_row_index + 11, false, var::column_type::constant)};

                    /* a * x^2 + y^2 = 1 + d * x^2 * y^2 */
                    non_native_range_component::generate_circuit(bp, assignment, {params.pnt.x}, row);
                    row += non_native_range_component::rows_amount;
                    non_native_range_component::generate_circuit(bp, assignment, {params.pnt.y}, row);
                    row += non_native_range_component::rows_amount;

                    auto y_2 = mult_component::generate_circuit(bp, assignment, {params.pnt.y, params.pnt.y}, row).output;
                    row += mult_component::rows_amount;
                    auto x_2 = mult_component::generate_circuit(bp, assignment, {params.pnt.x, params.pnt.x}, row).output;
                    row += mult_component::rows_amount;

                    auto t0 = mult_component::generate_circuit(bp, assignment, {x_2, a_var}, row).output;
                    row += mult_component::rows_amount;
                    auto left = add_component::generate_circuit(bp, assignment, {y_2, t0}, row).output;
                    row += add_component::rows_amount;
                    auto t1 = mult_component::generate_circuit(bp, assignment, {y_2, x_2}, row).output;
                    row += mult_component::rows_amount;
                    auto t2 = mult_component::generate_circuit(bp, assignment, {d_var, t1}, row).output;
                    row += mult_component::rows_amount;
                    auto right = add_component::generate_circuit(bp, assignment, {one_var, t2}, row).output;
                    row += add_component::rows_amount;

                    generate_copy_constraints(bp, assignment, params, start_row_index);

                    return result_type(start_row_index);
                }

            private:

                static void generate_gates(
                    blueprint<ArithmetizationType> &bp,
                    blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                    const params_type &params,
                    const std::size_t first_selector_index) {
                    
                }

                static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                      blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                                      const params_type &params,
                                                      std::size_t component_start_row) {
                    std::size_t row = component_start_row + 2 * non_native_range_component::rows_amount + 3 * mult_component::rows_amount;
                    auto left = (typename add_component::result_type(component_start_row + 25)).output;
                    row += 2 * mult_component::rows_amount + add_component::rows_amount;
                    auto right = (typename add_component::result_type(component_start_row + 43)).output;
                    
                    bp.add_copy_constraint({left[0], right[0]});
                    bp.add_copy_constraint({left[1], right[1]});
                    bp.add_copy_constraint({left[2], right[2]});
                    bp.add_copy_constraint({left[3], right[3]});
                }
            };

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP