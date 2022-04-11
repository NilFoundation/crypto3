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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class curve_element_variable_base_scalar_mul;

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
                class curve_element_variable_base_scalar_mul<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    CurveType,
                    W0, W1, W2, W3, W4,
                    W5, W6, W7, W8, W9,
                    W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;
                    
                    using var = snark::plonk_variable<BlueprintFieldType>;

                public:

                    constexpr static const std::size_t required_rows_amount = 102;
                    
                    struct public_params_type {
                    };

                    struct private_params_type {
                        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type T;
                        typename CurveType::scalar_field_type::value_type b;
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(required_rows_amount);
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const std::size_t &component_start_row) {

                        const std::size_t &j = component_start_row;

                        std::size_t vbsm_selector_index =
                            public_assignment.add_selector(j, j + required_rows_amount - 1, 2);

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
                            (2 * var(W3, 0) - var(W7, 1) * (2 * var(W2, 0) - var(W7, 1).pow(2) + var(W0, 0)))
                            *(2 * var(W3, 0) - var(W7, 1) * (2 * var(W2, 0) - var(W7, 1).pow(2) + var(W0, 0)))
                            - ((2 * var(W2, 0) - var(W7, 1).pow(2) + var(W0, 0))*(2 * var(W2, 0) - var(W7, 1).pow(2) + var(W0, 0))
                                 * (var(W7, 0) - var(W0, 0) + var(W7, 1).pow(2))));
                        auto constraint_7 = bp.add_constraint(
                            (2 * var(W8, 0) - var(W8, 1) * (2 * var(W7, 0) - var(W8, 1).pow(2) + var(W0, 0)))
                            * (2 * var(W8, 0) - var(W8, 1) * (2 * var(W7, 0) - var(W8, 1).pow(2) + var(W0, 0)))
                            - ((2 * var(W7, 0) - var(W8, 1).pow(2) + var(W0, 0))* (2 * var(W7, 0) - var(W8, 1).pow(2) + var(W0, 0))
                                 * (var(W9, 0) - var(W0, 0) + var(W8, 1).pow(2))));
                        auto constraint_8 = bp.add_constraint(
                            (2 * var(W10, 0) - var(W9, 1) * (2 * var(W9, 0) - var(W9, 1).pow(2) + var(W0, 0)))
                            *(2 * var(W10, 0) - var(W9, 1) * (2 * var(W9, 0) - var(W9, 1).pow(2) + var(W0, 0)))
                            - ((2 * var(W9, 0) - var(W9, 1).pow(2) + var(W0, 0))*(2 * var(W9, 0) - var(W9, 1).pow(2) + var(W0, 0))
                                 * (var(W11, 0) - var(W0, 0) + var(W9, 1).pow(2))));
                        auto constraint_9 = bp.add_constraint(
                            (2 * var(W12, 0) - var(W10, +1) * (2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0)))
                            *(2 * var(W12, 0) - var(W10, +1) * (2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0)))
                            - ((2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0))*(2 * var(W11, 0) - var(W10, +1).pow(2) + var(W0, 0))
                                 * (var(W13, 0) - var(W0, 0) + var(W10, +1).pow(2))));
                        auto constraint_10 = bp.add_constraint(
                            (2 * var(W14, 0) - var(W11, +1) * (2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0)))
                            *(2 * var(W14, 0) - var(W11, +1) * (2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0)))
                            - ((2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0))*(2 * var(W13, 0) - var(W11, +1).pow(2) + var(W0, 0))
                            * (var(W0, 1) - var(W0, 0) + var(W11, +1).pow(2))));

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

                        auto constraint_16 = bp.add_constraint(
                            var(W5, 0) - (32 * (var(W4, 0)) + 16 * var(W2, +1) + 8 * var(W3, +1) + 4 * var(W4, +1) +
                                          2 * var(W5, +1) + var(W6, +1)));
                        bp.add_gate(vbsm_selector_index,
                                          {bit_check_1,   bit_check_2,   bit_check_3,   bit_check_4,   bit_check_5,
                                           constraint_1,  constraint_2,  constraint_3,  constraint_4,  constraint_5,
                                           constraint_6,  constraint_7,  constraint_8,  constraint_9,  constraint_10,
                                           constraint_11, constraint_12, constraint_13, constraint_14, constraint_15,
                                           constraint_16});
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const std::size_t &component_start_row) {
                        const std::size_t &j = component_start_row;

                        for (int z = 0; z < required_rows_amount - 2; z += 2) {
                            bp.add_copy_constraint({{W0, j + z, false}, {W0, j + z + 2, false}});
                            bp.add_copy_constraint({{W1, j + z, false}, {W1, j + z + 2, false}});
                        }

                        //TODO link to params.b

                        // TODO: (x0, y0) in row i are copy constrained with values from the first doubling circuit

                        for (int z = 2; z < required_rows_amount; z += 2) {
                            bp.add_copy_constraint({{W2, j + z, false}, {W0, j + z - 1, false}});
                            bp.add_copy_constraint({{W3, j + z, false}, {W1, j + z - 1, false}});
                        }

                         for (int z = 2; z < required_rows_amount; z += 2) {
                            bp.add_copy_constraint({{W4, j + z, false}, {W5, j + z - 2, false}});
                        }

                        std::size_t public_input_column_index = 0;
                        bp.add_copy_constraint(
                            {{W4, j, false}, {public_input_column_index, j, false, var::column_type::public_input}});
                    }

                    static void generate_assignments(
                        blueprint_private_assignment_table<ArithmetizationType>
                            &private_assignment,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const private_params_type &params,
                        const std::size_t &component_start_row) {

                            const std::size_t &j = component_start_row;
                            public_assignment.public_input(0)[j] = ArithmetizationType::field_type::value_type::zero();

                            const typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type &T = params.T;

                            std::array<typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type, 6> P;
                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type Q;

                            std::array<bool, CurveType::scalar_field_type::modulus_bits + 1> b = {false};
                            typename CurveType::scalar_field_type::integral_type integral_b = typename CurveType::scalar_field_type::integral_type(params.b.data);
                            for (std::size_t i = 0; i < CurveType::scalar_field_type::modulus_bits; i++) {
                                b[CurveType::scalar_field_type::modulus_bits - i - 1] = multiprecision::bit_test(integral_b, i);
                            }
                            typename ArithmetizationType::field_type::value_type n = 0;
                            typename ArithmetizationType::field_type::value_type n_next = 0;
                            for (std::size_t i = j; i < j + required_rows_amount; i= i + 2) {
                                private_assignment.witness(W0)[i] = T.X;
                                private_assignment.witness(W1)[i] = T.Y;
                                if (i == j) {
                                    P[0] = 2*T;
                                }
                                else {
                                    P[0] = P[5];
                                    n = n_next;
                                }
                                private_assignment.witness(W2)[i] = P[0].X;
                                private_assignment.witness(W3)[i] = P[0].Y;
                                private_assignment.witness(W4)[i] = n;
                                n_next = 32*n + 16*b[((i - j) / 2)*5] + 8*b[((i - j) / 2)*5 + 1] + 4* b[((i - j) / 2)*5 + 2] +
                                2*b[((i - j) / 2)*5 + 3] + b[((i - j) / 2)*5 + 4];
                                private_assignment.witness(W5)[i] = n_next;
                                Q.X = T.X;
                                Q.Y = (2 * b[((i - j) / 2)*5] -1)*T.Y;
                                P[1] = 2 * P[0] + Q;
                                private_assignment.witness(W7)[i] =P[1].X;
                                private_assignment.witness(W8)[i] =P[1].Y;
                                private_assignment.witness(W7)[i + 1] = (P[0].Y - Q.Y) * (P[0].X - Q.X).inversed();
                                Q.Y = (2 * b[((i - j) / 2)*5 + 1] -1)*T.Y;
                                P[2] = 2 * P[1] + Q;
                                private_assignment.witness(W9)[i] =P[2].X;
                                private_assignment.witness(W10)[i] = P[2].Y;
                                private_assignment.witness(W8)[i + 1] = (P[1].Y - Q.Y) * (P[1].X - Q.X).inversed();
                                Q.Y = (2 * b[((i - j) / 2)*5 + 2] -1)*T.Y;
                                P[3] = 2 * P[2] + Q;
                                private_assignment.witness(W11)[i] =P[3].X;
                                private_assignment.witness(W12)[i] = P[3].Y;
                                private_assignment.witness(W9)[i + 1] = (P[2].Y - Q.Y) * (P[2].X - Q.X).inversed();
                                Q.Y = (2 * b[((i - j) / 2)*5 + 3] -1)*T.Y;
                                P[4] = 2 * P[3] + Q;
                                private_assignment.witness(W13)[i] =P[4].X;
                                private_assignment.witness(W14)[i] = P[4].Y;
                                private_assignment.witness(W10)[i + 1] = (P[3].Y - Q.Y) * (P[3].X - Q.X).inversed();
                                Q.Y = (2 * b[((i - j) / 2)*5 + 4] -1)*T.Y;
                                P[5] = 2 * P[4] + Q;
                                private_assignment.witness(W0)[i + 1] = P[5].X;
                                private_assignment.witness(W1)[i + 1] = P[5].Y;  
                                private_assignment.witness(W11)[i + 1] = (P[4].Y - Q.Y) * (P[4].X - Q.X).inversed();

                                private_assignment.witness(W2)[i + 1] = b[((i - j) / 2)*5];
                                private_assignment.witness(W3)[i + 1] = b[((i - j) / 2)*5 + 1];
                                private_assignment.witness(W4)[i + 1] = b[((i - j) / 2)*5 + 2];
                                private_assignment.witness(W5)[i + 1] = b[((i - j) / 2)*5 + 3];
                                private_assignment.witness(W6)[i + 1] = b[((i - j) / 2)*5 + 4];
                            }
                                std::cout<<"circuit result "<< P[5].X.data<< " "<< P[5].Y.data<<std::endl;

                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
