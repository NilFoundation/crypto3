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

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/component.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TArithmetization,
                         typename CurveType,
                         std::size_t W0 = 0,
                         std::size_t W1 = 1,
                         std::size_t W2 = 2,
                         std::size_t W3 = 3,
                         std::size_t W4 = 4,
                         std::size_t W5 = 5,
                         std::size_t W6 = 6,
                         std::size_t W7 = 7,
                         std::size_t W8 = 8,
                         std::size_t W9 = 9,
                         std::size_t W10 = 10,
                         std::size_t W11 = 11,
                         std::size_t W12 = 12,
                         std::size_t W13 = 13,
                         std::size_t W14 = 14>
                class element_g1_variable_base_endo_scalar_mul_plonk;

                template<typename TBlueprintField,
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
                class element_g1_variable_base_endo_scalar_mul_plonk<
                    snark::plonk_constraint_system<TBlueprintField, 15>,
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
                    W14> : public component<snark::plonk_constraint_system<TBlueprintField, 15>> {
                    typedef snark::plonk_constraint_system<TBlueprintField, 15> arithmetization_type;

                    typedef blueprint<arithmetization_type> blueprint_type;

                    std::size_t j;

                    constexpr static const std::size_t endo = 3;

                public:
                    element_g1_variable_base_endo_scalar_mul_plonk(blueprint_type &bp) :
                        component<arithmetization_type>(bp) {

                        // the last row is only for the n
                        j = this->bp.allocate_rows(64 + 1);
                    }

                    void generate_gates() {

                        constexpr static const typename blueprint_type::value_type x_T(
                            W0, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type y_T(
                            W1, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type x_S(
                            W2, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type y_S(
                            W3, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type x_P(
                            W4, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type y_P(
                            W5, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type n(
                            W6, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type x_R(
                            W7, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type y_R(
                            W8, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type s_1(
                            W9, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type s_3(
                            W10, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type b_1(
                            W11, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type b_2(
                            W12, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type b_3(
                            W13, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type b_4(
                            W14, blueprint_type::value_type::rotation_type::current);

                        constexpr static const typename blueprint_type::value_type next_n(
                            W6, blueprint_type::value_type::rotation_type::next);

                        for (std::size_t z = 0; z <= 63; z++) {
                            this->bp.add_gate(j + z, b_1 * (b_1 - 1));
                            this->bp.add_gate(j + z, b_2 * (b_2 - 1));
                            this->bp.add_gate(j + z, b_3 * (b_3 - 1));
                            this->bp.add_gate(j + z, b_4 * (b_4 - 1));

                            this->bp.add_gate(j + z,
                                              ((1 + (endo - 1) * b_2) * x_T - x_P) * s_1 - (2 * b_1 - 1) * y_T + y_P);
                            this->bp.add_gate(j + z,
                                              (2 * x_P - s_1 ^ 2 + (1 + (endo - 1) * b_2) * x_T) *
                                                      ((x_P - x_R) * s_1 + y_R + y_P) -
                                                  (x_P - x_R) * 2 * y_P);
                            this->bp.add_gate(
                                j + z,
                                (y_R + y_P) ^ 2 - ((x_P - x_R) ^ 2 * (s_1 ^ 2 - (1 + (endo - 1) * b_2) * x_T + x_R)));
                            this->bp.add_gate(j + z,
                                              ((1 + (endo - 1) * b_2) * x_T - x_R) * s_3 - (2 * b_3 - 1) * y_T + y_R);
                            this->bp.add_gate(j + z,
                                              (2 * x_R - s_3 ^ 2 + (1 + (endo - 1) * b_4) * x_T) *
                                                      ((x_R - x_S) * s_3 + y_S + y_R) -
                                                  (x_R - x_S) * 2 * y_R);
                            this->bp.add_gate(
                                j + z,
                                (y_S + y_R) ^ 2 - ((x_R - x_S) ^ 2 * (s_3 ^ 2 - (1 + (endo - 1) * b_4) * x_T + x_S)));
                            this->bp.add_gate(j + z, n - (16 * next_n + 8 * b_1 + 4 * b_2 + 2 * b_3 + b_4));
                        }
                    }

                private:
                    static typename CurveType::scalar_field_type::value_type
                        lambda(typename CurveType::template g1_type<>::value_type P1,
                               typename CurveType::template g1_type<>::value_type P2) {
                        return (P1.Y - P2.Y) * (P1.X - P2.X);
                    }

                public:
                    void generate_assignments(typename CurveType::scalar_field_type::value_type &r,
                                              typename CurveType::template g1_type<>::value_type &T) {

                        typename CurveType::template g1_type<>::value_type Q = ...;
                        typename CurveType::template g1_type<>::value_type S = ...;
                        typename CurveType::template g1_type<>::value_type R = S + Q;

                        std::array<bool, 4> b = marshalling::pack(r);

                        for (std::size_t z = 0; z <= 63; z++) {
                            this->bp.assignment(W0, j + z) = T.X;
                            this->bp.assignment(W1, j + z) = T.Y;
                            this->bp.assignment(W2, j + z) = S.X;
                            this->bp.assignment(W3, j + z) = S.Y;
                            this->bp.assignment(W4, j + z) = Q.X;
                            this->bp.assignment(W5, j + z) = Q.Y;
                            this->bp.assignment(W6, j + z) = r;
                            this->bp.assignment(W7, j + z) = R.X;
                            this->bp.assignment(W8, j + z) = R.Y;
                            this->bp.assignment(W9, j + z) = lambda(S, Q);
                            this->bp.assignment(W10, j + z) = lambda(R, S);
                            this->bp.assignment(W11, j + z) = b[0];
                            this->bp.assignment(W12, j + z) = b[1];
                            this->bp.assignment(W13, j + z) = b[2];
                            this->bp.assignment(W14, j + z) = b[3];
                        }

                        this->bp.assignment(W6, j + 64) = 0;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_ENDO_SCALAR_MUL_COMPONENT_15_WIRES_HPP
