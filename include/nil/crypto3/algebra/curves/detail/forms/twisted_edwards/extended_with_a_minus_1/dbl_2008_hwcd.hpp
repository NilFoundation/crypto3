//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_DBL_2008_HWCD_HPP
#define CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_DBL_2008_HWCD_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element doubling from the group G1 of twisted Edwards curve
                     *  for extended coordinates with a=-1 representation.
                     *  https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
                     *  https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.4
                     */

                    struct twisted_edwards_element_g1_extended_with_a_minus_1_dbl_2008_hwcd {

                        template<typename ElementType>
                        constexpr static inline ElementType process(const ElementType &first) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            if (first.is_zero()) {
                                return (first);
                            } else {

                                field_value_type A = (first.X).squared();                        // A = X1^2
                                field_value_type B = (first.Y).squared();                        // B = Y1^2
                                field_value_type C = field_value_type(2) * first.Z.squared();    // C = 2*Z1^2
                                field_value_type D = ElementType::params_type::a * A;            // D = a*A
                                field_value_type E = (first.X + first.Y).squared() - A - B;      // E = (X1+Y1)^2-A-B
                                field_value_type G = D + B;                                      // G = D+B
                                field_value_type F = G - C;                                      // F = G-C
                                field_value_type H = D - B;                                      // H = D-B
                                field_value_type X3 = E * F;                                     // X3 = E*F
                                field_value_type Y3 = G * H;                                     // Y3 = G*H
                                field_value_type T3 = E * H;                                     // T3 = E*H
                                field_value_type Z3 = F * G;                                     // Z3 = F*G

                                return ElementType(X3, Y3, T3, Z3);
                            }
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_DBL_2008_HWCD_HPP
