//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_WITH_A4_MINUS_3_ADD_1998_CMO_2_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_WITH_A4_MINUS_3_ADD_1998_CMO_2_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element addition from the group G1 of short Weierstrass curve
                     *  for projective_with_a4_minus_3 coordinates representation.
                     *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective-3.html#addition-add-1998-cmo-2
                     */

                    struct short_weierstrass_element_g1_projective_with_a4_minus_3_add_1998_cmo_2 {

                        template<typename ElementType>
                        constexpr static inline void process(ElementType &first,
                                                                    const ElementType &second) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            const field_value_type Y1Z2 = (first.Y) * (second.Z);        // Y1Z2 = Y1*Z2
                            const field_value_type X1Z2 = (first.X) * (second.Z);        // X1Z2 = X1*Z2
                            const field_value_type Z1Z2 = (first.Z) * (second.Z);        // Z1Z2 = Z1*Z2
                            const field_value_type u = (second.Y) * (first.Z) - Y1Z2;    // u    = Y2*Z1-Y1Z2
                            const field_value_type uu = u.squared();                     // uu   = u^2
                            const field_value_type v = (second.X) * (first.Z) - X1Z2;    // v    = X2*Z1-X1Z2
                            const field_value_type vv = v.squared();                     // vv   = v^2
                            const field_value_type vvv = v * vv;                         // vvv  = v*vv
                            const field_value_type R = vv * X1Z2;                        // R    = vv*X1Z2
                            const field_value_type A = uu * Z1Z2 - (vvv + R + R);        // A    = uu*Z1Z2 - vvv - 2*R

                            first.X = v * A;                           // X3   = v*A
                            first.Y = u * (R - A) - vvv * Y1Z2;        // Y3   = u*(R-A) - vvv*Y1Z2
                            first.Z = vvv * Z1Z2;                      // Z3   = vvv*Z1Z2

                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_WITH_A4_MINUS_3_ADD_1998_CMO_2_HPP
