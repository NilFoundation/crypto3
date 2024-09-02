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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_WITH_A4_MINUS_3_DBL_2007_BL_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_WITH_A4_MINUS_3_DBL_2007_BL_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element doubling from the group G1 of short Weierstrass curve
                     *  for projective_with_a4_minus_3 coordinates representation.
                     *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective-3.html#doubling-dbl-2007-bl
                     */
                    struct short_weierstrass_element_g1_projective_with_a4_minus_3_dbl_2007_bl {

                        template<typename ElementType>
                        constexpr static inline void process(ElementType &first) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            if (! first.is_zero()) {

                                const field_value_type XX = (first.X).squared();    // XX  = X1^2
                                const field_value_type ZZ = (first.Z).squared();    // ZZ  = Z1^2
                                const field_value_type w =
                                    ElementType::params_type::a * ZZ + (XX + XX + XX);    // w   = a*ZZ + 3*XX
                                const field_value_type Y1Z1 = (first.Y) * (first.Z);
                                const field_value_type s = Y1Z1 + Y1Z1;      // s   = 2*Y1*Z1
                                const field_value_type ss = s.squared();     // ss  = s^2
                                const field_value_type sss = s * ss;         // sss = s*ss
                                const field_value_type R = (first.Y) * s;    // R   = Y1*s
                                const field_value_type RR = R.squared();     // RR  = R^2
                                const field_value_type B =
                                    ((first.X) + R).squared() - XX - RR;                   // B   = (X1+R)^2 - XX - RR
                                const field_value_type h = w.squared() - B.doubled();      // h   = w^2 - 2*B

                                first.X = h * s;                         // X3  = h*s
                                first.Y = w * (B - h) - RR.doubled();    // Y3  = w*(B-h) - 2*RR
                                first.Z = sss;                           // Z3  = sss
                            }
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_WITH_A4_MINUS_3_DBL_2007_BL_HPP
