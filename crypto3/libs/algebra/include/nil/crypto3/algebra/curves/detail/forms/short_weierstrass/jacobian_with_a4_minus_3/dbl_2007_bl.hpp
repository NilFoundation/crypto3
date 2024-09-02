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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_MINUS_3_DBL_2007_BL_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_MINUS_3_DBL_2007_BL_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element doubling from the group G1 of short Weierstrass curve
                     *  for jacobian_with_a4_minus_3 coordinates representation.
                     *  http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd-2007-bl
                     */
                    struct short_weierstrass_element_g1_jacobian_with_a4_minus_3_dbl_2007_bl {

                        template<typename ElementType>
                        constexpr static inline void process(ElementType &first ) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            if (! first.is_zero()) {

                                field_value_type XX = (first.X).squared();    // XX = X1^2
                                field_value_type YY = (first.Y).squared();    // YY = Y1^2
                                field_value_type YYYY = YY.squared();         // YYYY = YY^2
                                field_value_type ZZ = (first.Z).squared();    // ZZ = Z1^2 
                                field_value_type S = ((first.X + YY).squared() - XX - YYYY).doubled();          // S = 2*((X1 + YY)^2 -XX - YYYY)
                                field_value_type M = XX.doubled() + XX - ZZ.squared().doubled()- ZZ.squared();  // M = 3*XX + a*ZZ^2
                                field_value_type T = M.squared() - S.doubled(); // T = M^2 - 2S

                                first.X = T;                        //X3 = T
                                first.Z = (first.Y + first.Z).squared() - YY - ZZ;          // Z3 = (Y1 + Z1)^2 - YY - ZZ
                                first.Y = M * (S - T) - YYYY.doubled().doubled().doubled(); // Y3 = M(S - T) - 8Y
                            }
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_MINUS_3_DBL_2007_BL_HPP
