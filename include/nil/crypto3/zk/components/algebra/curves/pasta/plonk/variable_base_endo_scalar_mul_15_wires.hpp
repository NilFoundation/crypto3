//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
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
                class curve_element_variable_base_endo_scalar_mul<snark::plonk_constraint_system<BlueprintFieldType,
                            ArithmetizationParams>,
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
                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const typename BlueprintFieldType::value_type endo = typename BlueprintFieldType::value_type(algebra::fields::arithmetic_params<BlueprintFieldType>::multiplicative_generator).pow(typename BlueprintFieldType::integral_type( ( (BlueprintFieldType::value_type::zero() - BlueprintFieldType::value_type::one()) * ( typename BlueprintFieldType::value_type(3) ).inversed() ).data));
                public:

                    constexpr static const std::size_t required_rows_amount = 65;
                    struct init_params { };

                    struct assignment_params_type {
                        typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type T;
                        typename CurveType::scalar_field_type::value_type b;
                    };

                        static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(required_rows_amount);
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const std::size_t &component_start_row) {

                        const std::size_t &j = component_start_row;

                        std::size_t selector_index = public_assignment.add_selector(j, j + required_rows_amount - 2);

                        auto bit_check_1 = this->bp.add_bit_check(var(W11, 0));
                        auto bit_check_2 = this->bp.add_bit_check(var(W12, 0));
                        auto bit_check_3 = this->bp.add_bit_check(var(W13, 0));
                        auto bit_check_4 = this->bp.add_bit_check(var(W14, 0));

                        auto constraint_1 = this->bp.add_constraint(
                            ((1 + (endo - 1) * var(W12, 0)) * var(W0, 0) - var(W4, 0)) * var(W9, 0) -
                            2 * var(W11, 0)* var(W1, 0) + var(W1, 0) + var(W5, 0));
                        auto constraint_2 = this->bp.add_constraint(
                            (2 * var(W4, 0) - var(W9, 0) * var(W9, 0) + (1 + (endo - 1) * var(W12, 0)) * var(W0, 0)) *
                                ((var(W4, 0) - var(W7, 0)) * var(W9, 0) + var(W8, 0) + var(W5, 0)) -
                            ((var(W4, 0) - var(W7, 0)) * 2 * var(W5, 0)));
                        auto constraint_3 = this->bp.add_constraint(
                            (var(W8, 0) + var(W5, 0)) * (var(W8, 0) + var(W5, 0))
                            - ((var(W4, 0) - var(W7, 0)) * (var(W4, 0) - var(W7, 0)) * (var(W9, 0) * (var(W9, 0) - (1 + (endo - 1) * var(W12, 0)) * var(W0, 0) + var(W7, 0)))));
                        auto constraint_4 = this->bp.add_constraint(
                            ((1 + (endo - 1) * var(W12, 0)) * var(W0, 0) - var(W7, 0)) * var(W10, 0) -
                            2 * var(W13, 0)* var(W1, 0) + var(W1, 0) + var(W8, 0));
                        auto constraint_5 = this->bp.add_constraint(
                            (2 * var(W7, 0) - var(W10, 0) * var(W10, 0) + (1 + (endo - 1) * var(W14, 0)) * var(W0, 0)) *
                                ((var(W7, 0) - var(W4, +1)) * var(W10, 0) + var(W5, +1) + var(W8, 0)) -
                            ((var(W7, 0) - var(W4, +1)) * 2 * var(W8, 0)));
                        auto constraint_6 = this->bp.add_constraint(
                            (var(W4, +1) + var(W8, 0)) * (var(W4, +1) + var(W8, 0))
                            - ((var(W7, 0) - var(W4, +1)) * (var(W7, 0) - var(W4, +1))
                                * (var(W10, 0) * (var(W10, 0)  - (1 + (endo - 1) * var(W14, 0)) * var(W0, 0) + var(W4, +1)))));
                        auto constraint_7 =
                            this->bp.add_constraint(var(W6, +1) - (16 * var(W6, 0) + 8 * var(W11, 0) + 4 * var(W12, 0) +
                                                                   2 * var(W13, 0) + var(W14, 0)));
                        this->bp.add_gate(selector_index,
                                          {bit_check_1, bit_check_2, bit_check_3, bit_check_4, constraint_1, constraint_2});
                        /*this->bp.add_gate(selector_index,
                                          {bit_check_1, bit_check_2, bit_check_3, bit_check_4, constraint_1,
                                           constraint_4});*/
                    }


                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const std::size_t &component_start_row) {
                        const std::size_t &j = component_start_row;

                        for (int z = 0; z < required_rows_amount - 2; z++) {
                            this->bp.add_copy_constraint({{W0, j + z, false}, {W0, j + z + 1, false}});
                            this->bp.add_copy_constraint({{W1, j + z, false}, {W1, j + z + 1, false}});
                        }

                        // TODO: (xP , yP ) in row i are copy constrained with values from the first doubling circuit
                    }

                    template<std::size_t WitnessColumns,
                             std::size_t SelectorColumns,
                             std::size_t PublicInputColumns,
                             std::size_t ConstantColumns>
                    static void generate_assignments(
                        blueprint_private_assignment_table<ArithmetizationType>
                            &private_assignment,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const assignment_params_type &params,
                        const std::size_t &component_start_row) {
                            const std::size_t &j = component_start_row;
                            private_assignment.allocate_rows(j + required_rows_amount);
                            public_assignment.allocate_rows(j + required_rows_amount);
                            public_assignment.public_input(0)[0] = arithmetization_type::field_type::value_type::zero();
                            //public_assignment.public_input(0)[1] = params.b;

                            const typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type &T = params.T;

                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type P;

                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type R;
                            typename CurveType::template g1_type<algebra::curves::coordinates::affine>::value_type Q;

                            std::array<bool, CurveType::scalar_field_type::modulus_bits> b = {false};

                            typename CurveType::scalar_field_type::integral_type integral_b = typename CurveType::scalar_field_type::integral_type(params.b.data);
                            for (std::size_t i = 0; i < CurveType::scalar_field_type::modulus_bits; ++i) {
                                b[i]= multiprecision::bit_test(integral_b, i);
                            }

                            for (std::size_t i = j; i < j + required_rows_amount - 1; i++) {
                                private_assignment.witness(W0)[i] = T.X;
                                private_assignment.witness(W1)[i] = T.Y;
                                if (i == j) {
                                    Q.X = endo * T.X;
                                    Q.Y = T.Y;
                                    P = 2 * (T + Q);
                                    private_assignment.witness(W4)[i] = P.X;
                                    private_assignment.witness(W5)[i] = P.Y;
                                    private_assignment.witness(W6)[i] = 0;
                                }
                                else {
                                    Q.X = (1 + (endo - 1) * b[(i - j)*4 - 1]) * T.X;
                                    Q.Y = (2* b[(i - j)*4 - 2] - 1) * T.Y;
                                    P = 2 * R + Q;
                                    private_assignment.witness(W4)[i] = P.X;
                                    private_assignment.witness(W5)[i] = P.Y;
                                    private_assignment.witness(W6)[i] = private_assignment.witness(W6)[i - 1] * 16 + private_assignment.witness(W11)[i - 1] * 8 
                                    + private_assignment.witness(W12)[i - 1] * 4 + private_assignment.witness(W13)[i - 1] * 2 + private_assignment.witness(W14)[i - 1];
                                }
                                Q.X = (1 + (endo - 1) * b[(i - j)*4 + 1]) * T.X;
                                Q.Y = (2* b[(i - j)*4] - 1) * T.Y;
                                R = 2 * P + Q;
                                private_assignment.witness(W7)[i] = R.X;
                                private_assignment.witness(W8)[i] = R.Y;
                                private_assignment.witness(W11)[i] = b[(i - j)*4];
                                private_assignment.witness(W12)[i] = b[(i - j)*4 + 1];
                                private_assignment.witness(W13)[i] = b[(i - j)*4 + 2];
                                private_assignment.witness(W14)[i] = b[(i - j)*4 + 3];
                                private_assignment.witness(W9)[i] = ((2 * b[(i - j)*4] - 1) * T.Y - P.Y) * ((1 + (endo - 1)*
                                b[(i - j)*4 + 1]) * T.X - P.X).inversed();

                                private_assignment.witness(W10)[i] = ((2 * b[(i - j)*4 + 2] - 1) * T.Y - R.Y) * ((1 + (endo - 1)*
                                b[(i - j)*4 + 3]) * T.X - R.X).inversed();
                            }

                            Q.X = (1 + (endo - 1) * b[255]) * T.X;
                            Q.Y = (2* b[254] - 1) * T.Y;
                            P = 2 * R + Q;
                            private_assignment.witness(W4)[j + 64] = P.X;
                            private_assignment.witness(W5)[j + 64] = P.Y;
                            private_assignment.witness(W6)[j + 64] = private_assignment.witness(W6)[j + 63] * 16 + private_assignment.witness(W11)[j + 63] * 8 
                            + private_assignment.witness(W12)[j + 63] * 4 + private_assignment.witness(W13)[j + 63] * 2 + private_assignment.witness(W14)[j + 63];


                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
