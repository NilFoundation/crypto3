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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // Using results from https://arxiv.org/pdf/math/0208038.pdf
                // Input: x \in F_p, P \in E(F_p)
                // Output: y * P, where x = (y - 2^255 - 1) / 2
                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class curve_element_variable_base_scalar_mul;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class curve_element_variable_base_scalar_mul<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType, W0, W1, W2,
                    W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using add_component =
                        zk::components::curve_element_unified_addition<ArithmetizationType, CurveType, W0, W1, W2, W3,
                                                                       W4, W5, W6, W7, W8, W9, W10>;

                    constexpr static const std::size_t mul_rows_amount = 102;

                public:
                    constexpr static const std::size_t selector_seed = 0x0f03;
                    constexpr static const std::size_t rows_amount = add_component::rows_amount + mul_rows_amount + 1;
                    constexpr static const std::size_t gates_amount = 2;

                    constexpr static const typename ArithmetizationType::field_type::value_type shifted_minus_one = 0x224698fc0994a8dd8c46eb2100000000_cppui255;
                    constexpr static const typename ArithmetizationType::field_type::value_type shifted_zero = 0x200000000000000000000000000000003369e57a0e5efd4c526a60b180000001_cppui255;
                    constexpr static const typename ArithmetizationType::field_type::value_type shifted_one = 0x224698fc0994a8dd8c46eb2100000001_cppui255;

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
                        result_type(const params_type &params, std::size_t start_row_index) {
                            X = var(W0, start_row_index + rows_amount - 1, false, var::column_type::witness);
                            Y = var(W1, start_row_index + rows_amount - 1, false, var::column_type::witness);
                        }
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type params,
                                                            const std::size_t start_row_index) {
                        typename BlueprintFieldType::value_type b = assignment.var_value(params.b);
                        typename BlueprintFieldType::value_type T_x = assignment.var_value(params.T.x);
                        typename BlueprintFieldType::value_type T_y = assignment.var_value(params.T.y);
                        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type T(T_x,
                                                                                                                 T_y);

                        std::array<
                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type, 6>
                            P;
                        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type Q;

                        typename CurveType::scalar_field_type::integral_type integral_b =
                            typename CurveType::scalar_field_type::integral_type(b.data);
                        const std::size_t scalar_size = 255;
                        nil::marshalling::status_type status;
                        std::array<bool, scalar_size> bits = nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_b, status);

                        typename ArithmetizationType::field_type::value_type n = 0;
                        typename ArithmetizationType::field_type::value_type n_next = 0;

                        auto addition_res = add_component::generate_assignments(
                            assignment, {{params.T.x, params.T.y}, {params.T.x, params.T.y}}, start_row_index);

                        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type
                            T_doubled(assignment.var_value(addition_res.X), assignment.var_value(addition_res.Y));

                        std::size_t j = start_row_index + add_component::rows_amount;

                        for (std::size_t i = j; i < j + mul_rows_amount; i = i + 2) {
                            assignment.witness(W0)[i] = T.X;
                            assignment.witness(W1)[i] = T.Y;
                            if (i == j) {
                                P[0] = T_doubled;
                            } else {
                                P[0] = P[5];
                                n = n_next;
                            }
                            assignment.witness(W2)[i] = P[0].X;
                            assignment.witness(W3)[i] = P[0].Y;
                            assignment.witness(W4)[i] = n;
                            n_next = 32 * n + 16 * bits[((i - j) / 2) * 5] + 8 * bits[((i - j) / 2) * 5 + 1] +
                                     4 * bits[((i - j) / 2) * 5 + 2] + 2 * bits[((i - j) / 2) * 5 + 3] +
                                     bits[((i - j) / 2) * 5 + 4];
                            assignment.witness(W5)[i] = n_next;
                            Q.X = T.X;
                            Q.Y = (2 * bits[((i - j) / 2) * 5] - 1) * T.Y;
                            P[1] = (P[0] + Q) + P[0];
                            assignment.witness(W7)[i] = P[1].X;
                            assignment.witness(W8)[i] = P[1].Y;
                            assignment.witness(W7)[i + 1] = (P[0].Y - Q.Y) * (P[0].X - Q.X).inversed();
                            Q.Y = (2 * bits[((i - j) / 2) * 5 + 1] - 1) * T.Y;
                            P[2] = (P[1] + Q) + P[1];
                            assignment.witness(W9)[i] = P[2].X;
                            assignment.witness(W10)[i] = P[2].Y;
                            assignment.witness(W8)[i + 1] = (P[1].Y - Q.Y) * (P[1].X - Q.X).inversed();
                            Q.Y = (2 * bits[((i - j) / 2) * 5 + 2] - 1) * T.Y;
                            P[3] = (P[2] + Q) + P[2];
                            assignment.witness(W11)[i] = P[3].X;
                            assignment.witness(W12)[i] = P[3].Y;
                            assignment.witness(W9)[i + 1] = (P[2].Y - Q.Y) * (P[2].X - Q.X).inversed();
                            Q.Y = (2 * bits[((i - j) / 2) * 5 + 3] - 1) * T.Y;
                            P[4] = (P[3] + Q) + P[3];
                            assignment.witness(W13)[i] = P[4].X;
                            assignment.witness(W14)[i] = P[4].Y;
                            assignment.witness(W10)[i + 1] = (P[3].Y - Q.Y) * (P[3].X - Q.X).inversed();
                            Q.Y = (2 * bits[((i - j) / 2) * 5 + 4] - 1) * T.Y;
                            P[5] = (P[4] + Q) + P[4];
                            assignment.witness(W0)[i + 1] = P[5].X;
                            assignment.witness(W1)[i + 1] = P[5].Y;
                            assignment.witness(W11)[i + 1] = (P[4].Y - Q.Y) * (P[4].X - Q.X).inversed();
                            assignment.witness(W2)[i + 1] = bits[((i - j) / 2) * 5];
                            assignment.witness(W3)[i + 1] = bits[((i - j) / 2) * 5 + 1];
                            assignment.witness(W4)[i + 1] = bits[((i - j) / 2) * 5 + 2];
                            assignment.witness(W5)[i + 1] = bits[((i - j) / 2) * 5 + 3];
                            assignment.witness(W6)[i + 1] = bits[((i - j) / 2) * 5 + 4];
                        }
                        typename ArithmetizationType::field_type::value_type m = ((n_next - shifted_minus_one)*
                        (n_next - shifted_zero)*(n_next - shifted_one));
                        typename ArithmetizationType::field_type::value_type t0 = ( m == 0 ? 0 : m.inversed());
                        typename ArithmetizationType::field_type::value_type t1 = ((n_next - shifted_minus_one) == 0) ? 0 : (n_next - shifted_minus_one).inversed();
                        typename ArithmetizationType::field_type::value_type t2 = ((n_next - shifted_one)       == 0) ? 0 : (n_next - shifted_one).inversed();
                        typename ArithmetizationType::field_type::value_type x;
                        typename ArithmetizationType::field_type::value_type y;
                        if (n_next == shifted_minus_one) {
                            x = T.X;
                            y = -T.Y;
                        } else  {
                            if (n_next == shifted_zero) {
                                x = 0;
                                y = 0;
                            } else {
                                if (n_next == shifted_one) {
                                    x = T.X;
                                    y = T.Y;
                                } else {
                                    x = P[5].X;
                                    y = P[5].Y;
                                }
                            }
                        }
                        assignment.witness(W2)[start_row_index + rows_amount - 1] = t0;
                        assignment.witness(W3)[start_row_index + rows_amount - 1] = t1;
                        assignment.witness(W4)[start_row_index + rows_amount - 1] = t2;
                        assignment.witness(W5)[start_row_index + rows_amount - 1] = n_next;
                        assignment.witness(W6)[start_row_index + rows_amount - 1] = T.X;
                        assignment.witness(W7)[start_row_index + rows_amount - 1] = T.Y;
                        assignment.witness(W8)[start_row_index + rows_amount - 1] = m;
                        assignment.witness(W0)[start_row_index + rows_amount - 1] = x;
                        assignment.witness(W1)[start_row_index + rows_amount - 1] = y;

                        return result_type(params, start_row_index);
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

                        assignment.enable_selector(first_selector_index, start_row_index + add_component::rows_amount,
                                                   start_row_index + rows_amount - 3, 2);
                        assignment.enable_selector(first_selector_index + 1, start_row_index + rows_amount - 2);

                        typename add_component::params_type addition_params = {{params.T.x, params.T.y},
                                                                               {params.T.x, params.T.y}};
                        zk::components::generate_circuit<add_component>(bp, assignment, addition_params,
                                                                        start_row_index);

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(params, start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type params,
                                               const std::size_t first_selector_index) {

                        auto bit_check_1 = bp.add_bit_check(var(W2, +1));
                        auto bit_check_2 = bp.add_bit_check(var(W3, +1));
                        auto bit_check_3 = bp.add_bit_check(var(W4, +1));
                        auto bit_check_4 = bp.add_bit_check(var(W5, +1));
                        auto bit_check_5 = bp.add_bit_check(var(W6, +1));

                        auto constraint_1 = bp.add_constraint((var(W2, 0) - var(W0, 0)) * var(W7, +1) -
                                                              (var(W3, 0) - (2 * var(W2, +1) - 1) * var(W1, 0)));
                        auto constraint_2 = bp.add_constraint((var(W7, 0) - var(W0, 0)) * var(W8, +1) -
                                                              (var(W8, 0) - (2 * var(W3, +1) - 1) * var(W1, 0)));
                        auto constraint_3 = bp.add_constraint((var(W9, 0) - var(W0, 0)) * var(W9, +1) -
                                                              (var(W10, 0) - (2 * var(W4, +1) - 1) * var(W1, 0)));
                        auto constraint_4 = bp.add_constraint((var(W11, 0) - var(W0, 0)) * var(W10, +1) -
                                                              (var(W12, 0) - (2 * var(W5, +1) - 1) * var(W1, 0)));
                        auto constraint_5 = bp.add_constraint((var(W13, 0) - var(W0, 0)) * var(W11, +1) -
                                                              (var(W14, 0) - (2 * var(W6, +1) - 1) * var(W1, 0)));

                        auto constraint_6 = bp.add_constraint(
                            (2 * var(W3, 0) - var(W7, 1) * (2 * var(W2, 0) - var(W7, 1).pow(2) + var(W0, 0))) *
                                (2 * var(W3, 0) - var(W7, 1) * (2 * var(W2, 0) - var(W7, 1).pow(2) + var(W0, 0))) -
                            ((2 * var(W2, 0) - var(W7, 1).pow(2) + var(W0, 0)) *
                             (2 * var(W2, 0) - var(W7, 1).pow(2) + var(W0, 0)) *
                             (var(W7, 0) - var(W0, 0) + var(W7, 1).pow(2))));
                        auto constraint_7 = bp.add_constraint(
                            (2 * var(W8, 0) - var(W8, 1) * (2 * var(W7, 0) - var(W8, 1).pow(2) + var(W0, 0))) *
                                (2 * var(W8, 0) - var(W8, 1) * (2 * var(W7, 0) - var(W8, 1).pow(2) + var(W0, 0))) -
                            ((2 * var(W7, 0) - var(W8, 1).pow(2) + var(W0, 0)) *
                             (2 * var(W7, 0) - var(W8, 1).pow(2) + var(W0, 0)) *
                             (var(W9, 0) - var(W0, 0) + var(W8, 1).pow(2))));
                        auto constraint_8 = bp.add_constraint(
                            (2 * var(W10, 0) - var(W9, 1) * (2 * var(W9, 0) - var(W9, 1).pow(2) + var(W0, 0))) *
                                (2 * var(W10, 0) - var(W9, 1) * (2 * var(W9, 0) - var(W9, 1).pow(2) + var(W0, 0))) -
                            ((2 * var(W9, 0) - var(W9, 1).pow(2) + var(W0, 0)) *
                             (2 * var(W9, 0) - var(W9, 1).pow(2) + var(W0, 0)) *
                             (var(W11, 0) - var(W0, 0) + var(W9, 1).pow(2))));
                        auto constraint_9 = bp.add_constraint(
                            (2 * var(W12, 0) - var(W10, +1) * (2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0))) *
                                (2 * var(W12, 0) -
                                 var(W10, +1) * (2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0))) -
                            ((2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0)) *
                             (2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0)) *
                             (var(W13, 0) - var(W0, 0) + var(W10, +1).pow(2))));
                        auto constraint_10 = bp.add_constraint(
                            (2 * var(W14, 0) - var(W11, +1) * (2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0))) *
                                (2 * var(W14, 0) -
                                 var(W11, +1) * (2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0))) -
                            ((2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0)) *
                             (2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0)) *
                             (var(W0, 1) - var(W0, 0) + var(W11, +1).pow(2))));

                        auto constraint_11 = bp.add_constraint(
                            (var(W8, 0) + var(W3, 0)) * (2 * var(W2, 0) - var(W7, +1).pow(2) + var(W0, 0)) -
                            ((var(W2, 0) - var(W7, 0)) *
                             (2 * var(W3, 0) - var(W7, +1) * (2 * var(W2, 0) - var(W7, +1).pow(2) + var(W0, 0)))));
                        auto constraint_12 = bp.add_constraint(
                            (var(W10, 0) + var(W8, 0)) * (2 * var(W7, 0) - var(W8, +1).pow(2) + var(W0, 0)) -
                            ((var(W7, 0) - var(W9, 0)) *
                             (2 * var(W8, 0) - var(W8, +1) * (2 * var(W7, 0) - var(W8, +1).pow(2) + var(W0, 0)))));
                        auto constraint_13 = bp.add_constraint(
                            (var(W12, 0) + var(W10, 0)) * (2 * var(W9, 0) - var(W9, +1).pow(2) + var(W0, 0)) -
                            ((var(W9, 0) - var(W11, 0)) *
                             (2 * var(W10, 0) - var(W9, +1) * (2 * var(W9, 0) - var(W9, +1).pow(2) + var(W0, 0)))));
                        auto constraint_14 = bp.add_constraint(
                            (var(W14, 0) + var(W12, 0)) * (2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0)) -
                            ((var(W11, 0) - var(W13, 0)) *
                             (2 * var(W12, 0) - var(W10, +1) * (2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0)))));
                        auto constraint_15 = bp.add_constraint(
                            (var(W1, +1) + var(W14, 0)) * (2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0)) -
                            ((var(W13, 0) - var(W0, +1)) *
                             (2 * var(W14, 0) - var(W11, +1) * (2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0)))));

                        auto constraint_16 =
                            bp.add_constraint(var(W5, 0) - (32 * (var(W4, 0)) + 16 * var(W2, +1) + 8 * var(W3, +1) +
                                                            4 * var(W4, +1) + 2 * var(W5, +1) + var(W6, +1)));

                        bp.add_gate(first_selector_index,
                                    {bit_check_1,   bit_check_2,   bit_check_3,   bit_check_4,   bit_check_5,
                                     constraint_1,  constraint_2,  constraint_3,  constraint_4,  constraint_5,
                                     constraint_6,  constraint_7,  constraint_8,  constraint_9,  constraint_10,
                                     constraint_11, constraint_12, constraint_13, constraint_14, constraint_15,
                                     constraint_16});
                        std::size_t selector_index_2 = first_selector_index + 1;
                        bit_check_1 = bp.add_bit_check(var(W2, 0));
                        bit_check_2 = bp.add_bit_check(var(W3, 0));
                        bit_check_3 = bp.add_bit_check(var(W4, 0));
                        bit_check_4 = bp.add_bit_check(var(W5, 0));
                        bit_check_5 = bp.add_bit_check(var(W6, 0));

                        constraint_1 = bp.add_constraint((var(W2, -1) - var(W0, -1)) * var(W7, 0) -
                                                              (var(W3, -1) - (2 * var(W2, 0) - 1) * var(W1, -1)));
                        constraint_2 = bp.add_constraint((var(W7, -1) - var(W0, -1)) * var(W8, 0) -
                                                              (var(W8, -1) - (2 * var(W3, 0) - 1) * var(W1, -1)));
                        constraint_3 = bp.add_constraint((var(W9, -1) - var(W0, -1)) * var(W9, 0) -
                                                              (var(W10, -1) - (2 * var(W4, 0) - 1) * var(W1, -1)));
                        constraint_4 = bp.add_constraint((var(W11, -1) - var(W0, -1)) * var(W10, 0) -
                                                              (var(W12, -1) - (2 * var(W5, 0) - 1) * var(W1, -1)));
                        constraint_5 = bp.add_constraint((var(W13, -1) - var(W0, -1)) * var(W11, 0) -
                                                              (var(W14, -1) - (2 * var(W6, 0) - 1) * var(W1, -1)));

                        constraint_6 = bp.add_constraint(
                            (2 * var(W3, -1) - var(W7, 0) * (2 * var(W2, -1) - var(W7, 0).pow(2) + var(W0, -1))) *
                                (2 * var(W3, -1) - var(W7, 0) * (2 * var(W2, -1) - var(W7, 0).pow(2) + var(W0, -1))) -
                            ((2 * var(W2, -1) - var(W7, 0).pow(2) + var(W0, -1)) *
                             (2 * var(W2, -1) - var(W7, 0).pow(2) + var(W0, -1)) *
                             (var(W7, -1) - var(W0, -1) + var(W7, 0).pow(2))));
                        constraint_7 = bp.add_constraint(
                            (2 * var(W8, -1) - var(W8, 0) * (2 * var(W7, -1) - var(W8, 0).pow(2) + var(W0, -1))) *
                                (2 * var(W8, -1) - var(W8, 0) * (2 * var(W7, -1) - var(W8, 0).pow(2) + var(W0, -1))) -
                            ((2 * var(W7, -1) - var(W8, 0).pow(2) + var(W0, -1)) *
                             (2 * var(W7, -1) - var(W8, 0).pow(2) + var(W0, -1)) *
                             (var(W9, -1) - var(W0, -1) + var(W8, 0).pow(2))));
                        constraint_8 = bp.add_constraint(
                            (2 * var(W10, -1) - var(W9, 0) * (2 * var(W9, -1) - var(W9, 0).pow(2) + var(W0, -1))) *
                                (2 * var(W10, -1) - var(W9, 0) * (2 * var(W9, -1) - var(W9, 0).pow(2) + var(W0, -1))) -
                            ((2 * var(W9, -1) - var(W9, 0).pow(2) + var(W0, -1)) *
                             (2 * var(W9, -1) - var(W9, 0).pow(2) + var(W0, -1)) *
                             (var(W11, -1) - var(W0, -1) + var(W9, 0).pow(2))));
                        constraint_9 = bp.add_constraint(
                            ((2 * var(W12, -1) - var(W10, 0) * (2 * var(W11, -1) - var(W10, 0).pow(2) + var(W0, -1))) *
                                (2 * var(W12, -1) -
                                 var(W10, 0) * (2 * var(W11, -1) - var(W10, 0).pow(2) + var(W0, -1))) -
                            ((2 * var(W11, -1) - var(W10, 0).pow(2) + var(W0, -1)) *
                             (2 * var(W11, -1) - var(W10, 0).pow(2) + var(W0, -1)) *
                             (var(W13, -1) - var(W0, -1) + var(W10, 0).pow(2))))*
                             var(W8, +1)*var(W2, +1));
                        constraint_10 = bp.add_constraint(
                            ((2 * var(W14, -1) - var(W11, 0) * (2 * var(W13, -1) - var(W11, 0).pow(2) + var(W0, -1))) *
                                (2 * var(W14, -1) -
                                 var(W11, 0) * (2 * var(W13, -1) - var(W11, 0).pow(2) + var(W0, -1))) -
                            ((2 * var(W13, -1) - var(W11, 0).pow(2) + var(W0, -1)) *
                             (2 * var(W13, -1) - var(W11, 0).pow(2) + var(W0, -1)) *
                             (var(W0, 0) - var(W0, -1) + var(W11, 0).pow(2))))*var(W8, + 1)*var(W2, +1));

                        constraint_11 = bp.add_constraint(
                            (var(W8, -1) + var(W3, -1)) * (2 * var(W2, -1) - var(W7, 0).pow(2) + var(W0, -1)) -
                            ((var(W2, -1) - var(W7, -1)) *
                             (2 * var(W3, -1) - var(W7, 0) * (2 * var(W2, -1) - var(W7, 0).pow(2) + var(W0, -1)))));
                        constraint_12 = bp.add_constraint(
                            (var(W10, -1) + var(W8, -1)) * (2 * var(W7, -1) - var(W8, 0).pow(2) + var(W0, -1)) -
                            ((var(W7, -1) - var(W9, -1)) *
                             (2 * var(W8, -1) - var(W8, 0) * (2 * var(W7, -1) - var(W8, 0).pow(2) + var(W0, -1)))));
                        constraint_13 = bp.add_constraint(
                                                         (var(W12, -1) + var(W10, -1)) * (2 * var(W9, -1) - var(W9, 0).pow(2) + var(W0, -1)) -
                            ((var(W9, -1) - var(W11, -1)) *
                             (2 * var(W10, -1) - var(W9, 0) * (2 * var(W9, -1) - var(W9, 0).pow(2) + var(W0, -1)))));
                        constraint_14 = bp.add_constraint(
                            ((var(W14, -1) + var(W12, -1)) * (2 * var(W11, -1) - var(W10, 0).pow(2) + var(W0, -1)) -
                            ((var(W11, -1) - var(W13, -1)) *
                             (2 * var(W12, -1) - var(W10, 0) * (2 * var(W11, -1) - var(W10, 0).pow(2) + var(W0, -1)))))*
                             var(W8, +1)*var(W2, +1));
                        constraint_15 = bp.add_constraint(
                            ((var(W1, 0) + var(W14, -1)) * (2 * var(W13, -1) - var(W11, 0).pow(2) + var(W0, -1)) -
                            ((var(W13, -1) - var(W0, 0)) *
                             (2 * var(W14, -1) - var(W11, 0) * (2 * var(W13, -1) - var(W11, 0).pow(2) + var(W0, -1)))))*
                             var(W8, +1)*var(W2, +1));

                        constraint_16 =
                            bp.add_constraint(var(W5, -1) - (32 * (var(W4, -1)) + 16 * var(W2, 0) + 8 * var(W3, 0) +
                                                            4 * var(W4, 0) + 2 * var(W5, 0) + var(W6, 0)));

                        auto constraint_17 = bp.add_constraint((var(W8, +1)*var(W2, +1) - 1) * var(W8, +1));
                        auto constraint_18 = bp.add_constraint(((var(W5, +1) - shifted_minus_one)
                        *var(W3, +1) - 1) * (var(W5, +1) - shifted_minus_one));
                        auto constraint_19 = bp.add_constraint(((var(W5, +1) - shifted_one)
                        *var(W4, +1) - 1) * (var(W5, +1) - shifted_one));
                        auto constraint_20 = bp.add_constraint((var(W8, +1)*var(W2, +1)*var(W0, 0)) + 
                        ((var(W5, +1) - shifted_minus_one)
                        *var(W3, +1) - (var(W5, +1) - shifted_one)
                        *var(W4, +1))* ((var(W5, +1) - shifted_minus_one)
                        *var(W3, +1) - (var(W5, +1) - shifted_one)
                        *var(W4, +1)) * var(W6, +1) - var(W0, +1));
                        auto constraint_21 = bp.add_constraint((var(W8, +1)*var(W2, +1)*var(W1, 0)) + 
                        ((var(W5, +1) - shifted_minus_one)
                        *var(W3, +1) - (var(W5, +1) - shifted_one)
                        *var(W4, +1)) * var(W7, +1) - var(W1, +1));
                        auto constraint_22 = bp.add_constraint(var(W8, +1) - ((var(W5, +1) - shifted_minus_one)
                        *(var(W5, +1) - shifted_zero)*
                        (var(W5, +1) - shifted_one)));
                        bp.add_gate(selector_index_2,
                                    {bit_check_1,   bit_check_2,   bit_check_3,   bit_check_4,   bit_check_5,
                                     constraint_1,  constraint_2,  constraint_3,  constraint_4,  constraint_5,
                                     constraint_6,  constraint_7,  constraint_8,  constraint_9,  constraint_10,
                                     constraint_11, constraint_12, constraint_13, constraint_14, constraint_15,
                                     constraint_16, constraint_17, constraint_18, constraint_19, constraint_20,
                                     constraint_21, constraint_22});
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type params,
                                                  const std::size_t start_row_index) {

                        std::size_t j = start_row_index + add_component::rows_amount;

                        typename add_component::params_type addition_params = {{params.T.x, params.T.y},
                                                                               {params.T.x, params.T.y}};
                        typename add_component::result_type addition_res(addition_params, start_row_index);

                        bp.add_copy_constraint({{W2, (std::int32_t)(j), false}, addition_res.X});
                        bp.add_copy_constraint({{W3, (std::int32_t)(j), false}, addition_res.Y});

                        // main algorithm

                        for (int z = 0; z < mul_rows_amount - 2; z += 2) {
                            bp.add_copy_constraint(
                                {{W0, (std::int32_t)(j + z), false}, {W0, (std::int32_t)(j + z + 2), false}});
                            bp.add_copy_constraint(
                                {{W1, (std::int32_t)(j + z), false}, {W1, (std::int32_t)(j + z + 2), false}});
                        }

                        for (int z = 2; z < mul_rows_amount; z += 2) {
                            bp.add_copy_constraint(
                                {{W2, (std::int32_t)(j + z), false}, {W0, (std::int32_t)(j + z - 1), false}});
                            bp.add_copy_constraint(
                                {{W3, (std::int32_t)(j + z), false}, {W1, (std::int32_t)(j + z - 1), false}});
                        }

                        for (int z = 2; z < mul_rows_amount; z += 2) {
                            bp.add_copy_constraint(
                                {{W4, (std::int32_t)(j + z), false}, {W5, (std::int32_t)(j + z - 2), false}});
                        }
                        bp.add_copy_constraint(
                                {{W5, (std::int32_t)(start_row_index + rows_amount - 1), false},
                                 {W5, (std::int32_t)(start_row_index + rows_amount - 3), false}});
                        bp.add_copy_constraint(
                                {{W6, (std::int32_t)(start_row_index + rows_amount - 1), false},
                                 {W0, (std::int32_t)(start_row_index + rows_amount - 3), false}});
                        bp.add_copy_constraint(
                                {{W7, (std::int32_t)(start_row_index + rows_amount - 1), false},
                                 {W1, (std::int32_t)(start_row_index + rows_amount - 3), false}});

                        bp.add_copy_constraint(
                            {{W4, (std::int32_t)(j), false},
                             {0, (std::int32_t)(j), false, var::column_type::constant}});

                        bp.add_copy_constraint(
                            {params.b, {W5, (std::int32_t)(j + rows_amount - 4), false}});    // scalar value check
                    }

                    static void
                    generate_assignments_constant(blueprint<ArithmetizationType> &bp,
                                                blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                const params_type &params,
                                                std::size_t component_start_row) {
                        std::size_t row = component_start_row + add_component::rows_amount;

                        assignment.constant(0)[row] = ArithmetizationType::field_type::value_type::zero();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
