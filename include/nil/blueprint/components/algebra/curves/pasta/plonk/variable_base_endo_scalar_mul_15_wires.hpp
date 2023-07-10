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
// @file Declaration of interfaces for auxiliary components for the VARIABLE_BASE_ENDO_SCALAR_MUL component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class curve_element_variable_base_endo_scalar_mul;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
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
                class curve_element_variable_base_endo_scalar_mul<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
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
                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using multiplication_component = zk::components::multiplication<ArithmetizationType, 0, 1, 2>;

                    using unified_addition_component =
                        zk::components::curve_element_unified_addition<ArithmetizationType,
                                                                       CurveType,
                                                                       0,
                                                                       1,
                                                                       2,
                                                                       3,
                                                                       4,
                                                                       5,
                                                                       6,
                                                                       7,
                                                                       8,
                                                                       9,
                                                                       10>;

                public:
                    constexpr static const typename BlueprintFieldType::value_type endo =
                        typename BlueprintFieldType::value_type(
                            algebra::fields::arithmetic_params<BlueprintFieldType>::multiplicative_generator)
                            .pow(typename BlueprintFieldType::integral_type(
                                ((BlueprintFieldType::value_type::zero() - BlueprintFieldType::value_type::one()) *
                                 (typename BlueprintFieldType::value_type(3)).inversed())
                                    .data));
                    constexpr static const std::size_t selector_seed = 0x0f02;
                    constexpr static const std::size_t rows_amount =
                        33 + multiplication_component::rows_amount + unified_addition_component::rows_amount * 2;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        struct var_ec_point {
                            var x;
                            var y;
                        };

                        var_ec_point T;
                        var b;
                    };

                    struct result_type {
                        var X;
                        var Y;
                        result_type(std::size_t start_row_index) {
                            X = var(W4, start_row_index + rows_amount - 1, false);
                            Y = var(W5, start_row_index + rows_amount - 1, false);
                        }
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t j = start_row_index;
                        typename multiplication_component::params_type multiplication_params = {
                            params.T.x, var(W0, j + 1, false, var::column_type::constant)};
                        auto mul_res =
                            multiplication_component::generate_assignments(assignment, multiplication_params, j);
                        j++;

                        typename unified_addition_component::params_type addition_params = {
                            {params.T.x, params.T.y}, {mul_res.output, params.T.y}};
                        auto add_res = unified_addition_component::generate_assignments(assignment, addition_params, j);
                        j++;

                        typename unified_addition_component::params_type double_params = {{add_res.X, add_res.Y},
                                                                                          {add_res.X, add_res.Y}};
                        unified_addition_component::generate_assignments(assignment, double_params, j);
                        j++;

                        typename BlueprintFieldType::value_type b = assignment.var_value(params.b);
                        typename BlueprintFieldType::value_type T_x = assignment.var_value(params.T.x);
                        typename BlueprintFieldType::value_type T_y = assignment.var_value(params.T.y);
                        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type T(T_x,
                                                                                                                 T_y);

                        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type P;

                        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type R;
                        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type Q;
                        typename CurveType::scalar_field_type::integral_type integral_b =
                            typename CurveType::scalar_field_type::integral_type(b.data);

                        std::array<bool, 128> bits = {false};
                        {
                            nil::marshalling::status_type status;
                            std::array<bool, 255> bits_all =
                                nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_b, status);
                            std::copy(bits_all.end() - 128, bits_all.end(), bits.begin());
                        }

                        typename ArithmetizationType::field_type::value_type n = 0;
                        typename ArithmetizationType::field_type::value_type n_next = 0;
                        typename ArithmetizationType::field_type::value_type s1 = 0;
                        typename ArithmetizationType::field_type::value_type s3 = 0;
                        for (std::size_t i = j; i < j + 32; i++) {
                            assignment.witness(W0)[i] = T.X;
                            assignment.witness(W1)[i] = T.Y;
                            if (i == j) {
                                Q.X = endo * T.X;
                                Q.Y = T.Y;
                                P = T + (T + Q) + Q;
                                assignment.witness(W4)[i] = P.X;
                                assignment.witness(W5)[i] = P.Y;
                                assignment.witness(W6)[i] = n;
                            } else {
                                Q.X = (1 + (endo - 1) * bits[(i - j) * 4 - 2]) * T.X;
                                Q.Y = (2 * bits[(i - j) * 4 - 1] - 1) * T.Y;
                                /*s4 = 2 * R.Y * (2*R.X + Q.X - s3 * s3).inversed() - s3;
                                P.X = Q.X + s4*s4 - s3*s3;
                                P.Y = (R.X - P.X)*s4 -R.Y;*/
                                P = 2 * R + Q;
                                assignment.witness(W4)[i] = P.X;
                                assignment.witness(W5)[i] = P.Y;
                                n_next = n * 16 + bits[(i - j) * 4 - 4] * 8 + bits[(i - j) * 4 - 3] * 4 +
                                         bits[(i - j) * 4 - 2] * 2 + bits[(i - j) * 4 - 1];
                                assignment.witness(W6)[i] = n_next;
                                n = n_next;
                            }
                            assignment.witness(W11)[i] = bits[(i - j) * 4];
                            assignment.witness(W12)[i] = bits[(i - j) * 4 + 1];
                            assignment.witness(W13)[i] = bits[(i - j) * 4 + 2];
                            assignment.witness(W14)[i] = bits[(i - j) * 4 + 3];
                            Q.X = (1 + (endo - 1) * bits[(i - j) * 4]) * T.X;
                            Q.Y = (2 * bits[(i - j) * 4 + 1] - 1) * T.Y;
                            s1 = (Q.Y - P.Y) * (Q.X - P.X).inversed();
                            // s2 = 2 * P.Y * (2*P.X + Q.X - s1 * s1).inversed() - s1;

                            assignment.witness(W9)[i] = s1;
                            /*R.X = Q.X + s2*s2 - s1*s1;
                            R.Y = (P.X - R.X)*s2 -P.Y;*/
                            R = 2 * P + Q;
                            s3 = ((2 * bits[(i - j) * 4 + 3] - 1) * T.Y - R.Y) *
                                 ((1 + (endo - 1) * bits[(i - j) * 4 + 2]) * T.X - R.X).inversed();
                            assignment.witness(W10)[i] = s3;
                            assignment.witness(W7)[i] = R.X;
                            assignment.witness(W8)[i] = R.Y;
                        }

                        Q.X = (1 + (endo - 1) * bits[126]) * T.X;
                        Q.Y = (2 * bits[127] - 1) * T.Y;
                        /*s4 = 2 * R.Y * (2*R.X + Q.X - s3 * s3).inversed() - s3;
                        P.X = Q.X + s4*s4 - s3*s3;
                        P.Y = (R.X - P.X)*s4 -R.Y; */
                        P = R + Q + R;
                        assignment.witness(W4)[j + 32] = P.X;
                        assignment.witness(W5)[j + 32] = P.Y;
                        n_next = n * 16 + bits[124] * 8 + bits[125] * 4 + bits[126] * 2 + bits[127];
                        assignment.witness(W6)[j + 32] = n_next;
                    }

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;
                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }
                        std::size_t j = start_row_index;
                        typename multiplication_component::params_type multiplication_params = {
                            params.T.x, var(W0, j + 1, false, var::column_type::constant)};
                        zk::components::generate_circuit<multiplication_component>(
                            bp, assignment, multiplication_params, start_row_index);
                        typename multiplication_component::result_type mul_res(multiplication_params, j);
                        j++;

                        typename unified_addition_component::params_type addition_params = {
                            {params.T.x, params.T.y}, {mul_res.output, params.T.y}};
                        zk::components::generate_circuit<unified_addition_component>(
                            bp, assignment, addition_params, j);
                        typename unified_addition_component::result_type add_res(addition_params, j);
                        j++;

                        typename unified_addition_component::params_type double_params = {{add_res.X, add_res.Y},
                                                                                          {add_res.X, add_res.Y}};
                        zk::components::generate_circuit<unified_addition_component>(bp, assignment, double_params, j);
                        j++;

                        assignment.enable_selector(first_selector_index, j, j + 31);

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                        auto bit_check_1 = bp.add_bit_check(var(W11, 0));
                        auto bit_check_2 = bp.add_bit_check(var(W12, 0));
                        auto bit_check_3 = bp.add_bit_check(var(W13, 0));
                        auto bit_check_4 = bp.add_bit_check(var(W14, 0));

                        auto constraint_1 =
                            bp.add_constraint(((1 + (endo - 1) * var(W11, 0)) * var(W0, 0) - var(W4, 0)) * var(W9, 0) -
                                              2 * var(W12, 0) * var(W1, 0) + var(W1, 0) + var(W5, 0));
                        auto constraint_2 = bp.add_constraint(
                            (2 * var(W4, 0) - var(W9, 0) * var(W9, 0) + (1 + (endo - 1) * var(W11, 0)) * var(W0, 0)) *
                                ((var(W4, 0) - var(W7, 0)) * var(W9, 0) + var(W8, 0) + var(W5, 0)) -
                            ((var(W4, 0) - var(W7, 0)) * 2 * var(W5, 0)));
                        auto constraint_3 = bp.add_constraint(
                            (var(W8, 0) + var(W5, 0)) * (var(W8, 0) + var(W5, 0)) -
                            ((var(W4, 0) - var(W7, 0)) * (var(W4, 0) - var(W7, 0)) *
                             (var(W9, 0) * var(W9, 0) - (1 + (endo - 1) * var(W11, 0)) * var(W0, 0) + var(W7, 0))));
                        auto constraint_4 =
                            bp.add_constraint(((1 + (endo - 1) * var(W13, 0)) * var(W0, 0) - var(W7, 0)) * var(W10, 0) -
                                              2 * var(W14, 0) * var(W1, 0) + var(W1, 0) + var(W8, 0));
                        auto constraint_5 = bp.add_constraint(
                            (2 * var(W7, 0) - var(W10, 0) * var(W10, 0) + (1 + (endo - 1) * var(W13, 0)) * var(W0, 0)) *
                                ((var(W7, 0) - var(W4, +1)) * var(W10, 0) + var(W5, +1) + var(W8, 0)) -
                            ((var(W7, 0) - var(W4, +1)) * 2 * var(W8, 0)));
                        auto constraint_6 = bp.add_constraint(
                            (var(W5, +1) + var(W8, 0)) * (var(W5, +1) + var(W8, 0)) -
                            ((var(W7, 0) - var(W4, +1)) * (var(W7, 0) - var(W4, +1)) *
                             (var(W10, 0) * var(W10, 0) - (1 + (endo - 1) * var(W13, 0)) * var(W0, 0) + var(W4, +1))));
                        auto constraint_7 =
                            bp.add_constraint(var(W6, +1) - (16 * var(W6, 0) + 8 * var(W11, 0) + 4 * var(W12, 0) +
                                                             2 * var(W13, 0) + var(W14, 0)));

                        bp.add_gate(first_selector_index,
                                    {bit_check_1, bit_check_2, bit_check_3, bit_check_4, constraint_1, constraint_2,
                                     constraint_3, constraint_4, constraint_5, constraint_6, constraint_7});
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {

                        std::size_t j = start_row_index;

                        typename multiplication_component::params_type multiplication_params = {
                            params.T.x, var(0, j, false, var::column_type::constant)};
                        typename multiplication_component::result_type mul_res(multiplication_params, start_row_index);
                        j++;

                        typename unified_addition_component::params_type addition_params = {
                            {params.T.x, params.T.y}, {mul_res.output, params.T.y}};
                        typename unified_addition_component::result_type add_res(addition_params, j);
                        j++;

                        typename unified_addition_component::params_type double_params = {{add_res.X, add_res.Y},
                                                                                          {add_res.X, add_res.Y}};
                        typename unified_addition_component::result_type double_res(double_params, j);
                        j++;

                        bp.add_copy_constraint({{W4, (std::int32_t)(j), false}, double_res.X});
                        bp.add_copy_constraint({{W5, (std::int32_t)(j), false}, double_res.Y});

                        for (int z = 0; z < 31; z++) {
                            bp.add_copy_constraint(
                                {{W0, (std::int32_t)(j + z), false}, {W0, (std::int32_t)(j + z + 1), false}});
                            bp.add_copy_constraint(
                                {{W1, (std::int32_t)(j + z), false}, {W1, (std::int32_t)(j + z + 1), false}});
                        }
                        bp.add_copy_constraint(
                            {{W6, (std::int32_t)(j + 0), false},
                             {0, (std::int32_t)(start_row_index + 1), false, var::column_type::constant}});

                        // TODO link to params.b

                        bp.add_copy_constraint({{W6, (std::int32_t)(j + 32), false}, params.b});
                    }

                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t component_start_row) {
                        std::size_t row = component_start_row;

                        assignment.constant(0)[row] = ArithmetizationType::field_type::value_type::zero();
                        assignment.constant(0)[row + 1] = endo;
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
