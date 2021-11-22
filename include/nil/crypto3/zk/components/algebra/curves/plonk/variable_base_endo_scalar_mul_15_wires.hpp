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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_ENDO_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_ENDO_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/crypto3/zk/components/blueprint.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TBlueprintField, typename CurveType, 
                    std::size_t W0 = 0, std::size_t W1 = 1, std::size_t W2 = 2, std::size_t W3 = 3, 
                    std::size_t W4 = 4, std::size_t W5 = 5, std::size_t W6 = 6, std::size_t W7 = 7,
                    std::size_t W8 = 8, std::size_t W9 = 9, std::size_t W10 = 10, std::size_t W11 = 11,
                    std::size_t W12 = 12, std::size_t W13 = 13, std::size_t W14 = 14>
                class element_g1_variable_base_endo_scalar_mul_plonk : public component<TBlueprintField> {
                    typedef snark::plonk_constraint_system<TBlueprintField> arithmetization_type;

                    typedef blueprint<arithmetization_type, TBlueprintField> blueprint_type;

                    typename blueprint_type::row_index_type j;

                    constexpr static const std::size_t endo = 3;
                public:

                    element_g1_variable_base_endo_scalar_mul_plonk(blueprint_type &bp) :
                        component<FieldType>(bp){

                        j = bp.allocate_rows(64);
                    }

                    void generate_gates() {

                        constexpr static const typename blueprint_type::variable_type x_T(W0, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type y_T(W1, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type x_S(W2, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type y_S(W3, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type x_P(W4, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type y_P(W5, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type n(W6, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type x_R(W7, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type y_R(W8, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type s_1(W9, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type s_3(W10, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type b_1(W11, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type b_2(W12, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type b_3(W13, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type b_4(W14, 
                            blueprint_type::variable_type::rotation_type::current);

                        constexpr static const typename blueprint_type::variable_type s_5(W0, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type b_3(W1, 
                            blueprint_type::variable_type::rotation_type::current);

                        constexpr static const typename blueprint_type::variable_type next_n(W6, 
                            blueprint_type::variable_type::rotation_type::next);

                        bp.add_gate(j, b_1 * (b_1 - 1));
                        bp.add_gate(j, b_2 * (b_2 - 1));
                        bp.add_gate(j, b_3 * (b_3 - 1));
                        bp.add_gate(j, b_4 * (b_4 - 1));

                        bp.add_gate(j, ((1 + (endo - 1) * b_2) * x_T - x_P) * s_1 - (2 * b_1 - 1) * y_T + y_P);
                        bp.add_gate(j, (2 * x_P - s_1^2 + (1 + (endo - 1) * b_2) * x_T) * ((x_P - x_R) * s_1 + y_R + y_P) - (x_P - x_R) * 2 * y_P);
                        bp.add_gate(j, (y_R + yP)^2 - ((xP - x_R)^2 * (s_1^2 - (1 + (endo - 1) * b_2) * x_T + x_R)));
                        bp.add_gate(j, ((1 + (endo - 1) * b_2) * x_T - x_R) * s_3 - (2 * b_3-1) * y_T + y_R);
                        bp.add_gate(j, (2 * x_R - s_3^2 + (1 + (endo - 1) * b_4) * x_T) * ((x_R - x_S) * s_3 + y_S + y_R) - (x_R - x_S) * 2 * y_R);
                        bp.add_gate(j, (y_S + y_R)^2 - ((x_R - x_S)^2 * (s_3^2 - (1 + (endo - 1) * b_4) * x_T + x_S)));
                        bp.add_gate(j, n - (16 * next_n + 8 * b_1 + 4 * b_2 + 2 * b_3 + b_4));

                    }

                    void generate_assignments(typename CurveType::scalar_field_type::value_type &r, 
                                              typename CurveType::g1_type<>::value_type &T) {

                        typename CurveType::g1_type<>::value_type Q = ...;
                        typename CurveType::g1_type<>::value_type S = ...;
                        typename CurveType::g1_type<>::value_type R = S + Q;
                        
                        std::array<bool, 4> b = marshalling::unpack(r);

                        bp.val(W0, j) = T.X;
                        bp.val(W1, j) = T.Y;
                        bp.val(W2, j) = S.X;
                        bp.val(W3, j) = S.Y;
                        bp.val(W4, j) = ...;
                        bp.val(W5, j) = ...;
                        bp.val(W6, j) = ...;
                        bp.val(W7, j) = R.X;
                        bp.val(W8, j) = R.Y;
                        bp.val(W9, j) = ...;
                        bp.val(W10, j) = ...;
                        bp.val(W11, j) = b[0];
                        bp.val(W12, j) = b[1];
                        bp.val(W13, j) = b[2];
                        bp.val(W14, j) = b[3];

                        bp.val(W0, j+1) = ...;
                        bp.val(W1, j+1) = b[3];
                        bp.val(W2, j+1) = S.X;
                        bp.val(W3, j+1) = S.Y;
                        bp.val(W4, j+1) = ...;
                        bp.val(W5, j+1) = ...;
                        bp.val(W6, j+1) = ...;
                        bp.val(W7, j+1) = R.X;
                        bp.val(W8, j+1) = R.Y;
                        bp.val(W9, j+1) = ...;
                        bp.val(W10, j+1) = ...;
                        bp.val(W11, j+1) = b[0];
                        bp.val(W12, j+1) = b[1];
                        bp.val(W13, j+1) = b[2];
                        bp.val(W14, j+1) = b[3];

                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_ENDO_SCALAR_MUL_COMPONENT_15_WIRES_HPP
