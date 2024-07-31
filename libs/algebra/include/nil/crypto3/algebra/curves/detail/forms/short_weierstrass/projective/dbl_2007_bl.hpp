//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_DBL_2007_BL_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_DBL_2007_BL_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element doubling from the group G1 of short Weierstrass curve
                     *  for projective coordinates representation.
                     *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl
                     */
                    struct short_weierstrass_element_g1_projective_dbl_2007_bl {

                        template<typename ElementType>
                        constexpr static inline void process(ElementType &first) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            if (!first.is_zero()) {

                                // XX  = X1^2
                                field_value_type XX (first.X);
                                XX.square_inplace();

                                // ZZ  = Z1^2
                                field_value_type ZZ (first.Z);
                                ZZ.square_inplace();

                                // w   = a*ZZ + 3*XX
                                field_value_type w (ZZ);
                                w *= field_value_type(ElementType::params_type::a);
                                w += XX;
                                w += XX;
                                w += XX;

                                // s   = 2*Y1*Z1
                                field_value_type s (first.Y);
                                s *= first.Z;
                                s.double_inplace();

                                // ss  = s^2
                                // sss = s*ss
                                // Z3 = sss
                                first.Z = s;
                                first.Z.square_inplace();
                                first.Z *= s;

                                // R   = Y1*s
                                field_value_type R (first.Y);
                                R *= s;

                                // RR  = R^2
                                field_value_type RR(R);
                                RR.square_inplace();

                                // B   = (X1+R)^2 - XX - RR
                                field_value_type B (first.X);
                                B += R;
                                B.square_inplace();
                                B -= XX;
                                B -= RR;

                                // h   = w^2 - 2*B
                                field_value_type h (w);
                                h.square_inplace();
                                h -= B;
                                h -= B;

                                // X3  = h*s
                                first.X = h;
                                first.X *= s;

                                // Y3  = w*(B-h) - 2*RR
                                first.Y = B;
                                first.Y -= h;
                                first.Y *= w;
                                first.Y -= RR;
                                first.Y -= RR;

                                // Z3  = sss, see above
                            }
                        }
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_DBL_2007_BL_HPP
