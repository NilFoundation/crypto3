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
// @file Declaration of interfaces for auxiliary components for the FIXED_BASE_MULTIPLICATION_EDWARD25519 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_FIXED_BASE_MULTIPLICATION_EDWARD25519_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_FIXED_BASE_MULTIPLICATION_EDWARD25519_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/range.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/complete_addition.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename CurveType, typename Ed25519Type, std::size_t... WireIndexes>
            class fixed_base_multiplication;

            template<typename BlueprintFieldType, typename CurveType,
                     typename Ed25519Type, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                     std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8>
            class fixed_base_multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, CurveType,
                Ed25519Type, W0, W1, W2, W3, W4, W5, W6, W7, W8> {

                typedef snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;

                using non_native_range_component =
                    components::non_native_range<ArithmetizationType, CurveType, 0, 1, 2, 3, 4, 5, 6, 7, 8>;
                using scalar_non_native_range_component =
                    components::scalar_non_native_range<ArithmetizationType, CurveType, Ed25519Type, 0, 1, 2, 3, 4, 5,
                                                        6, 7, 8>;

                using complete_addition_component =
                    complete_addition<ArithmetizationType, CurveType, Ed25519Type, W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;
                constexpr static const std::size_t selector_seed = 0xff88;

            public:
                constexpr static const std::size_t rows_amount =
                    scalar_non_native_range_component::rows_amount + 13 + 11 * complete_addition_component::rows_amount;

                constexpr static const std::size_t gates_amount = 0;

                struct params_type {
                    var k;
                };

                struct result_type {
                    componentsar_ec_point {
                        std::array<var, 4> x;
                        std::array<var, 4> y;
                    };
                    var_ec_point output;
                    result_type(std::size_t row) {
                        auto res = (typename complete_addition_component::result_type(row)).output;
                        output.x = res.x;
                        output.y = res.y;
                    }
                };

                static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        std::size_t component_start_row) {
                    std::size_t row = component_start_row;
                    auto k_chunks_vars =
                        scalar_non_native_range_component::generate_assignments(
                            assignment, typename scalar_non_native_range_component::params_type({params.k}), row)
                            .output;
                    row += scalar_non_native_range_component::rows_amount;
                    typename Ed25519Type::scalar_field_type::integral_type base = 1;
                    std::array<typename Ed25519Type::scalar_field_type::integral_type, 12> k_chunks;
                    for (std::size_t i = 0; i < 12; i++) {
                        k_chunks[i] = typename Ed25519Type::scalar_field_type::integral_type(
                            assignment.var_value(k_chunks_vars[i]).data);
                    }

                    typename Ed25519Type::template g1_type<algebra::curves::coordinates::affine>::value_type B =
                        Ed25519Type::template g1_type<algebra::curves::coordinates::affine>::value_type::one();

                    typename Ed25519Type::scalar_field_type::integral_type mask = (base << 66) - 1;

                    typename Ed25519Type::template g1_type<algebra::curves::coordinates::affine>::value_type P =
                        typename Ed25519Type::scalar_field_type::value_type(k_chunks[0]) * B;

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
                    assignment.witness(W4)[row] = y3[0];
                    assignment.witness(W5)[row] = y3[1];
                    assignment.witness(W6)[row] = y3[2];
                    assignment.witness(W7)[row] = y3[3];
                    std::array<var, 4> P_y = {var(W4, row), var(W5, row), var(W6, row), var(W7, row)};
                    assignment.witness(W8)[row] = k_chunks[0];
                    row++;

                    for (std::size_t i = 0; i < 11; i++) {
                        typename Ed25519Type::template g1_type<algebra::curves::coordinates::affine>::value_type Q =
                            typename Ed25519Type::scalar_field_type::value_type(k_chunks[i + 1]) *
                            (base << 22 * (i + 1)) * B;

                        typename Ed25519Type::base_field_type::integral_type Qx_integral =
                            typename Ed25519Type::base_field_type::integral_type(Q.X.data);
                        std::array<typename Ed25519Type::base_field_type::integral_type, 4> x3 = {
                            Qx_integral & mask, (Qx_integral >> 66) & mask, (Qx_integral >> 132) & mask,
                            (Qx_integral >> 198) & mask};

                        typename Ed25519Type::base_field_type::integral_type Qy_integral =
                            typename Ed25519Type::base_field_type::integral_type(Q.Y.data);
                        std::array<typename Ed25519Type::base_field_type::integral_type, 4> y3 = {
                            Qy_integral & mask, (Qy_integral >> 66) & mask, (Qy_integral >> 132) & mask,
                            (Qy_integral >> 198) & mask};

                        assignment.witness(W0)[row] = x3[0];
                        assignment.witness(W1)[row] = x3[1];
                        assignment.witness(W2)[row] = x3[2];
                        assignment.witness(W3)[row] = x3[3];
                        std::array<var, 4> Q_x = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};
                        assignment.witness(W4)[row] = y3[0];
                        assignment.witness(W5)[row] = y3[1];
                        assignment.witness(W6)[row] = y3[2];
                        assignment.witness(W7)[row] = y3[3];
                        std::array<var, 4> Q_y = {var(W4, row), var(W5, row), var(W6, row), var(W7, row)};
                        assignment.witness(W8)[row] = k_chunks[0];
                        row++;
                        auto t = complete_addition_component::generate_assignments(
                            assignment, typename complete_addition_component::params_type({{P_x, P_y}, {Q_x, Q_y}}),
                            row);
                        row += complete_addition_component::rows_amount;
                        if (i != 10) {
                            P_x = t.output.x;
                            P_y = t.output.y;
                            P.X = typename Ed25519Type::base_field_type::value_type(
                                (typename Ed25519Type::base_field_type::integral_type(
                                     assignment.var_value(P_x[0]).data) +
                                 typename Ed25519Type::base_field_type::integral_type(
                                     assignment.var_value(P_x[1]).data) *
                                     (base << 66) +
                                 typename Ed25519Type::base_field_type::integral_type(
                                     assignment.var_value(P_x[2]).data) *
                                     (base << 132) +
                                 typename Ed25519Type::base_field_type::integral_type(
                                     assignment.var_value(P_x[3]).data) *
                                     (base << 198)));
                            P.Y = typename Ed25519Type::base_field_type::value_type(
                                (typename Ed25519Type::base_field_type::integral_type(
                                     assignment.var_value(P_y[0]).data) +
                                 typename Ed25519Type::base_field_type::integral_type(
                                     assignment.var_value(P_y[1]).data) *
                                     (base << 66) +
                                 typename Ed25519Type::base_field_type::integral_type(
                                     assignment.var_value(P_y[2]).data) *
                                     (base << 132) +
                                 typename Ed25519Type::base_field_type::integral_type(
                                     assignment.var_value(P_y[3]).data) *
                                     (base << 198)));
                        } else {

                            typename Ed25519Type::template g1_type<algebra::curves::coordinates::affine>::value_type Q =
                                typename Ed25519Type::scalar_field_type::value_type((k_chunks[i + 1]) * (base << 11)) *
                                P;

                            typename Ed25519Type::base_field_type::integral_type Qx_integral =
                                typename Ed25519Type::base_field_type::integral_type(Q.X.data);
                            std::array<typename Ed25519Type::base_field_type::integral_type, 4> x3 = {
                                Qx_integral & mask, (Qx_integral >> 66) & mask, (Qx_integral >> 132) & mask,
                                (Qx_integral >> 198) & mask};

                            typename Ed25519Type::base_field_type::integral_type Qy_integral =
                                typename Ed25519Type::base_field_type::integral_type(Q.Y.data);
                            std::array<typename Ed25519Type::base_field_type::integral_type, 4> y3 = {
                                Qy_integral & mask, (Qy_integral >> 66) & mask, (Qy_integral >> 132) & mask,
                                (Qy_integral >> 198) & mask};

                            assignment.witness(W0)[row] = x3[0];
                            assignment.witness(W1)[row] = x3[1];
                            assignment.witness(W2)[row] = x3[2];
                            assignment.witness(W3)[row] = x3[3];
                            std::array<var, 4> Q_x = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};
                            assignment.witness(W4)[row] = y3[0];
                            assignment.witness(W5)[row] = y3[1];
                            assignment.witness(W6)[row] = y3[2];
                            assignment.witness(W7)[row] = y3[3];
                            std::array<var, 4> Q_y = {var(W4, row), var(W5, row), var(W6, row), var(W7, row)};
                            assignment.witness(W8)[row] = k_chunks[0];
                            row++;
                        }
                    }
                    return result_type(row - 1 - complete_addition_component::rows_amount);
                }

                static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                    const params_type &params,
                                                    const std::size_t start_row_index) {

                    std::size_t row = start_row_index;
                    auto k_chunks =
                        scalar_non_native_range_component::generate_circuit(
                            bp, assignment, typename scalar_non_native_range_component::params_type({params.k}), row)
                            .output;
                    row += scalar_non_native_range_component::rows_amount;

                    std::array<var, 4> P_x = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};
                    std::array<var, 4> P_y = {var(W4, row), var(W5, row), var(W6, row), var(W7, row)};
                    row++;

                    for (std::size_t i = 0; i < 11; i++) {
                        std::array<var, 4> Q_x = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};
                        std::array<var, 4> Q_y = {var(W4, row), var(W5, row), var(W6, row), var(W7, row)};
                        row++;
                        auto t = complete_addition_component::generate_circuit(
                            bp, assignment, typename complete_addition_component::params_type({{P_x, P_y}, {Q_x, Q_y}}),
                            row);
                        row += complete_addition_component::rows_amount;
                        P_x = t.output.x;
                        P_y = t.output.y;
                    }

                    generate_copy_constraints(bp, assignment, params, start_row_index);

                    return result_type(row - 1 - complete_addition_component::rows_amount);
                }

            private:
                static void generate_gates(blueprint<ArithmetizationType> &bp,
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
                }
            };

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP