//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for auxiliary components for the MERKLE_TREE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_COMPLETE_ADDITION_EDWARD25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_COMPLETE_ADDITION_EDWARD25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/multiplication.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/addition.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/subtraction.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         typename Ed25519Type,
                         std::size_t... WireIndexes>
                class complete_addition;

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
                class complete_addition<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using non_native_range_component =
                        zk::components::non_native_range<ArithmetizationType, CurveType, 0, 1, 2, 3, 4, 5, 6, 7, 8>;
                    using multiplication_component = non_native_field_element_multiplication<ArithmetizationType,
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
                                                                                             W8>;

                    using addition_component = non_native_field_element_addition<ArithmetizationType,
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
                                                                                 W8>;

                    using subtraction_component = non_native_field_element_subtraction<ArithmetizationType,
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
                                                                                       W8>;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    constexpr static const std::size_t selector_seed = 0xff87;

                public:
                    constexpr static const std::size_t rows_amount =
                        2 * non_native_range_component::rows_amount + 8 * multiplication_component::rows_amount +
                        3 * addition_component::rows_amount + subtraction_component::rows_amount;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        struct var_ec_point {
                            std::array<var, 4> x;
                            std::array<var, 4> y;
                        };

                        var_ec_point T;
                        var_ec_point R;
                    };

                    struct result_type {
                        struct var_ec_point {
                            std::array<var, 4> x;
                            std::array<var, 4> y;
                        };
                        var_ec_point output;

                        result_type(std::size_t component_start_row) {
                            output.x = {var(W0, component_start_row, false), var(W1, component_start_row, false),
                                        var(W2, component_start_row, false), var(W3, component_start_row, false)};
                            output.y = {var(W0, component_start_row + non_native_range_component::rows_amount, false),
                                        var(W1, component_start_row + non_native_range_component::rows_amount, false),
                                        var(W2, component_start_row + non_native_range_component::rows_amount, false),
                                        var(W3, component_start_row + non_native_range_component::rows_amount, false)};
                        }
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        typename Ed25519Type::base_field_type::integral_type base = 1;
                        std::array<var, 4> T_x = params.T.x;
                        std::array<var, 4> T_y = params.T.y;
                        std::array<typename CurveType::base_field_type::value_type, 4> T_x_array = {
                            assignment.var_value(params.T.x[0]), assignment.var_value(params.T.x[1]),
                            assignment.var_value(params.T.x[2]), assignment.var_value(params.T.x[3])};
                        std::array<typename CurveType::base_field_type::value_type, 4> T_y_array = {
                            assignment.var_value(params.T.y[0]), assignment.var_value(params.T.y[1]),
                            assignment.var_value(params.T.y[2]), assignment.var_value(params.T.y[3])};

                        std::array<var, 4> R_x = params.R.x;
                        std::array<var, 4> R_y = params.R.y;
                        std::array<typename CurveType::base_field_type::value_type, 4> R_x_array = {
                            assignment.var_value(params.R.x[0]), assignment.var_value(params.R.x[1]),
                            assignment.var_value(params.R.x[2]), assignment.var_value(params.R.x[3])};
                        std::array<typename CurveType::base_field_type::value_type, 4> R_y_array = {
                            assignment.var_value(params.R.y[0]), assignment.var_value(params.R.y[1]),
                            assignment.var_value(params.R.y[2]), assignment.var_value(params.R.y[3])};

                        typename Ed25519Type::template g1_type<algebra::curves::coordinates::affine>::value_type T(
                            (typename Ed25519Type::base_field_type::integral_type(T_x_array[0].data) +
                             typename Ed25519Type::base_field_type::integral_type(T_x_array[1].data) * (base << 66) +
                             typename Ed25519Type::base_field_type::integral_type(T_x_array[2].data) * (base << 132) +
                             typename Ed25519Type::base_field_type::integral_type(T_x_array[3].data) * (base << 198)),
                            (typename Ed25519Type::base_field_type::integral_type(T_y_array[0].data) +
                             typename Ed25519Type::base_field_type::integral_type(T_y_array[1].data) * (base << 66) +
                             typename Ed25519Type::base_field_type::integral_type(T_y_array[2].data) * (base << 132) +
                             typename Ed25519Type::base_field_type::integral_type(T_y_array[3].data) * (base << 198)));
                        typename Ed25519Type::template g1_type<algebra::curves::coordinates::affine>::value_type R(
                            (typename Ed25519Type::base_field_type::integral_type(R_x_array[0].data) +
                             typename Ed25519Type::base_field_type::integral_type(R_x_array[1].data) * (base << 66) +
                             typename Ed25519Type::base_field_type::integral_type(R_x_array[2].data) * (base << 132) +
                             typename Ed25519Type::base_field_type::integral_type(R_x_array[3].data) * (base << 198)),
                            (typename Ed25519Type::base_field_type::integral_type(R_y_array[0].data) +
                             typename Ed25519Type::base_field_type::integral_type(R_y_array[1].data) * (base << 66) +
                             typename Ed25519Type::base_field_type::integral_type(R_y_array[2].data) * (base << 132) +
                             typename Ed25519Type::base_field_type::integral_type(R_y_array[3].data) * (base << 198)));

                        typename Ed25519Type::template g1_type<algebra::curves::coordinates::affine>::value_type P =
                            T + R;

                        typename Ed25519Type::base_field_type::integral_type mask = (base << 66) - 1;

                        typename Ed25519Type::base_field_type::integral_type Px_integral =
                            typename Ed25519Type::base_field_type::integral_type(P.X.data);
                        std::array<typename Ed25519Type::base_field_type::integral_type, 4> x3 = {
                            Px_integral & mask, (Px_integral >> 66) & mask, (Px_integral >> 132) & mask,
                            (Px_integral >> 198) & mask};

                        typename Ed25519Type::base_field_type::integral_type Py_integral =
                            typename Ed25519Type::base_field_type::integral_type(P.Y.data);
                        std::array<typename Ed25519Type::base_field_type::integral_type, 4> y3 = {
                            Py_integral & mask, (Py_integral >> 66) & mask, (Py_integral >> 132) & mask,
                            (Py_integral >> 198) & mask};

                        assignment.witness(W0)[row] = x3[0];
                        assignment.witness(W1)[row] = x3[1];
                        assignment.witness(W2)[row] = x3[2];
                        assignment.witness(W3)[row] = x3[3];
                        std::array<var, 4> P_x = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};

                        typename non_native_range_component::params_type range_params_x3 = {P_x};
                        non_native_range_component::generate_assignments(assignment, range_params_x3, row);
                        row += non_native_range_component::rows_amount;

                        assignment.witness(W0)[row] = y3[0];
                        assignment.witness(W1)[row] = y3[1];
                        assignment.witness(W2)[row] = y3[2];
                        assignment.witness(W3)[row] = y3[3];
                        std::array<var, 4> P_y = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};

                        typename non_native_range_component::params_type range_params_y3 = {P_y};
                        non_native_range_component::generate_assignments(assignment, range_params_y3, row);
                        row += non_native_range_component::rows_amount;

                        auto t0 = multiplication_component::generate_assignments(
                            assignment, typename multiplication_component::params_type({T_x, R_y}), row);
                        row += multiplication_component::rows_amount;

                        auto t1 = multiplication_component::generate_assignments(
                            assignment, typename multiplication_component::params_type({T_y, R_x}), row);
                        row += multiplication_component::rows_amount;

                        auto t2 = multiplication_component::generate_assignments(
                            assignment, typename multiplication_component::params_type({T_x, R_x}), row);
                        row += multiplication_component::rows_amount;

                        auto t3 = multiplication_component::generate_assignments(
                            assignment, typename multiplication_component::params_type({T_y, R_y}), row);
                        row += multiplication_component::rows_amount;

                        auto z0 = addition_component::generate_assignments(
                            assignment, typename addition_component::params_type({t0.output, t1.output}), row);
                        row += addition_component::rows_amount;

                        auto z1 = addition_component::generate_assignments(
                            assignment, typename addition_component::params_type({t2.output, t3.output}), row);
                        row += addition_component::rows_amount;

                        auto z2 = multiplication_component::generate_assignments(
                            assignment, typename multiplication_component::params_type({t0.output, t1.output}), row);
                        row += multiplication_component::rows_amount;

                        typename Ed25519Type::base_field_type::integral_type d =
                            typename Ed25519Type::base_field_type::integral_type(
                                0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3_cppui256);
                        assignment.constant(0)[row + 4] = d & mask;
                        assignment.constant(0)[row + 5] = (d >> 66) & mask;
                        assignment.constant(0)[row + 6] = (d >> 132) & mask;
                        assignment.constant(0)[row + 7] = (d >> 198) & mask;
                        std::array<var, 4> d_var_array = {var(0, row + 4, false, var::column_type::constant),
                                                          var(0, row + 5, false, var::column_type::constant),
                                                          var(0, row + 6, false, var::column_type::constant),
                                                          var(0, row + 7, false, var::column_type::constant)};

                        auto k0 = multiplication_component::generate_assignments(
                            assignment, typename multiplication_component::params_type({d_var_array, z2.output}), row);
                        row += multiplication_component::rows_amount;

                        auto k1 = multiplication_component::generate_assignments(
                            assignment, typename multiplication_component::params_type({P_x, k0.output}), row);
                        row += multiplication_component::rows_amount;

                        auto k2 = multiplication_component::generate_assignments(
                            assignment, typename multiplication_component::params_type({P_y, k0.output}), row);
                        row += multiplication_component::rows_amount;

                        auto k3 = addition_component::generate_assignments(
                            assignment, typename addition_component::params_type({P_x, k1.output}), row);
                        row += addition_component::rows_amount;

                        auto k4 = subtraction_component::generate_assignments(
                            assignment, typename subtraction_component::params_type({P_y, k2.output}), row);
                        row += subtraction_component::rows_amount;

                        return result_type(component_start_row);
                    }

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;
                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }
                        std::size_t row = start_row_index;
                        std::array<var, 4> P_x = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};

                        typename non_native_range_component::params_type range_params_x3 = {P_x};
                        non_native_range_component::generate_circuit(bp, assignment, range_params_x3, row);
                        row += non_native_range_component::rows_amount;

                        std::array<var, 4> P_y = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};

                        typename non_native_range_component::params_type range_params_y3 = {P_y};
                        non_native_range_component::generate_circuit(bp, assignment, range_params_y3, row);
                        row += non_native_range_component::rows_amount;

                        std::array<var, 4> R_x = params.R.x;
                        std::array<var, 4> R_y = params.R.y;
                        std::array<var, 4> T_x = params.T.x;
                        std::array<var, 4> T_y = params.T.y;

                        auto t0 = multiplication_component::generate_circuit(
                            bp, assignment, typename multiplication_component::params_type({T_x, R_y}), row);
                        row += multiplication_component::rows_amount;

                        auto t1 = multiplication_component::generate_circuit(
                            bp, assignment, typename multiplication_component::params_type({T_y, R_x}), row);
                        row += multiplication_component::rows_amount;

                        auto t2 = multiplication_component::generate_circuit(
                            bp, assignment, typename multiplication_component::params_type({T_x, R_x}), row);
                        row += multiplication_component::rows_amount;

                        auto t3 = multiplication_component::generate_circuit(
                            bp, assignment, typename multiplication_component::params_type({T_y, R_y}), row);
                        row += multiplication_component::rows_amount;

                        auto z0 = addition_component::generate_circuit(
                            bp, assignment, typename addition_component::params_type({t0.output, t1.output}), row);
                        row += addition_component::rows_amount;

                        auto z1 = addition_component::generate_circuit(
                            bp, assignment, typename addition_component::params_type({t2.output, t3.output}), row);
                        row += addition_component::rows_amount;

                        auto z2 = multiplication_component::generate_circuit(
                            bp,
                            assignment,
                            typename multiplication_component::params_type({t0.output, t1.output}),
                            row);
                        row += multiplication_component::rows_amount;

                        std::array<var, 4> d_var_array = {var(0, row + 4, false, var::column_type::constant),
                                                          var(0, row + 5, false, var::column_type::constant),
                                                          var(0, row + 6, false, var::column_type::constant),
                                                          var(0, row + 7, false, var::column_type::constant)};

                        auto k0 = multiplication_component::generate_circuit(
                            bp,
                            assignment,
                            typename multiplication_component::params_type({d_var_array, z2.output}),
                            row);
                        row += multiplication_component::rows_amount;

                        auto k1 = multiplication_component::generate_circuit(
                            bp, assignment, typename multiplication_component::params_type({P_x, k0.output}), row);
                        row += multiplication_component::rows_amount;

                        auto k2 = multiplication_component::generate_circuit(
                            bp, assignment, typename multiplication_component::params_type({P_y, k0.output}), row);
                        row += multiplication_component::rows_amount;

                        auto k3 = addition_component::generate_circuit(
                            bp, assignment, typename addition_component::params_type({P_x, k1.output}), row);
                        row += addition_component::rows_amount;

                        auto k4 = subtraction_component::generate_circuit(
                            bp, assignment, typename subtraction_component::params_type({P_y, k2.output}), row);
                        row += subtraction_component::rows_amount;

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        return result_type(start_row_index);
                    }

                private:
                    static void
                        generate_gates(blueprint<ArithmetizationType> &bp,
                                       blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                       const params_type &params,
                                       const std::size_t first_selector_index) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        row += non_native_range_component::rows_amount;
                        row += non_native_range_component::rows_amount;
                        row += multiplication_component::rows_amount;
                        row += multiplication_component::rows_amount;
                        row += multiplication_component::rows_amount;
                        row += multiplication_component::rows_amount;

                        for (std::size_t i = 0; i < 4; i++) {
                            bp.add_copy_constraint({{i, (std::int32_t)(row + 2), false},
                                                    {i, (std::int32_t)(start_row_index + rows_amount - 4 - 2), false}});
                        }
                        row += addition_component::rows_amount;

                        for (std::size_t i = 0; i < 4; i++) {
                            bp.add_copy_constraint({{i, (std::int32_t)(row + 2), false},
                                                    {i, (std::int32_t)(start_row_index + rows_amount - 2), false}});
                        }
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP