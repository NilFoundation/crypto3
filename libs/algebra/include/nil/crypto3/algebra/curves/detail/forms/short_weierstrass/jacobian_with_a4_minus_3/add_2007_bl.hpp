//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_MINUS_3_ADD_2007_BL_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_MINUS_3_ADD_2007_BL_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element addition from the group G1 of short Weierstrass curve
                     *  for jacobian_with_a4_minus_3 coordinates representation.
                     *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
                     */

                    struct short_weierstrass_element_g1_jacobian_with_a4_minus_3_add_2007_bl {

                        template<typename ElementType>
                        constexpr static inline void process(ElementType &first,
                                                                    const ElementType &second) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            field_value_type Z1Z1 = (first.Z).squared();            // Z1Z1 = Z1^2
                            field_value_type Z2Z2 = (second.Z).squared();           // Z2Z2 = Z2^2
                            field_value_type U1 = (first.X) * Z2Z2;                 // U1 = X1 * Z2Z2
                            field_value_type U2 = (second.X) * Z1Z1;                // U2 = X2 * Z1Z1
                            field_value_type S1 = (first.Y) * (second.Z) * Z2Z2;    // S1 = Y1 * Z2 * Z2Z2
                            field_value_type S2 = (second.Y) * (first.Z) * Z1Z1;    // S2 = Y2 * Z1 * Z1Z1
                            field_value_type H = U2 - U1;                           // H = U2-U1
                            field_value_type S2_minus_S1 = S2 - S1;
                            field_value_type I = (H + H).squared();             // I = (2 * H)^2
                            field_value_type J = H * I;                         // J = H * I
                            field_value_type r = S2_minus_S1 + S2_minus_S1;     // r = 2 * (S2-S1)
                            field_value_type V = U1 * I;                        // V = U1 * I
                            field_value_type S1_J = S1 * J;

                            first.X = r.squared() - J - (V + V);    // X3 = r^2 - J - 2 * V
                            first.Y = r * (V - first.X) - (S1_J + S1_J);    // Y3 = r * (V-X3)-2 S1 J
                            first.Z =
                                ((first.Z + second.Z).squared() - Z1Z1 - Z2Z2) * H;    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2) * H

                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_MINUS_3_ADD_2007_BL_HPP
