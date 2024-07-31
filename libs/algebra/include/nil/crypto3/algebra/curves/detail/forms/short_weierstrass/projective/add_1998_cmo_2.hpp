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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_ADD_1998_CMO_2_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_ADD_1998_CMO_2_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element addition from the group G1 of short Weierstrass curve
                     *  for projective coordinates representation.
                     *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
                     */

                    struct short_weierstrass_element_g1_projective_add_1998_cmo_2 {

                        template<typename ElementType>
                        constexpr static inline void process(ElementType &first,
                                                                    const ElementType &second) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            // Y1Z2 = Y1*Z2
                            field_value_type Y1Z2 (first.Y);
                            Y1Z2 *= second.Z;

                            // X1Z2 = X1*Z2
                            field_value_type X1Z2 (first.X);
                            X1Z2 *= second.Z;

                            // Z1Z2 = Z1*Z2
                            field_value_type Z1Z2 (first.Z);
                            Z1Z2 *= second.Z;

                            // u    = Y2*Z1-Y1Z2
                            field_value_type u (second.Y);
                            u *= first.Z;
                            u -= Y1Z2;

                            // uu   = u^2
                            field_value_type uu (u);
                            uu.square_inplace();

                            // v    = X2*Z1-X1Z2
                            field_value_type v (second.X);
                            v *= first.Z;
                            v -= X1Z2;

                            // vv   = v^2
                            field_value_type vv (v);
                            vv.square_inplace();

                            // vvv  = v*vv
                            field_value_type vvv (vv);
                            vvv *= v;

                            // R    = vv*X1Z2
                            field_value_type R (vv);
                            R *= X1Z2;

                            // A    = uu*Z1Z2 - vvv - 2*R
                            field_value_type A (uu);
                            A *= Z1Z2;
                            A -= vvv;
                            A -= R;
                            A -= R;

                            // X3   = v*A
                            first.X = v;
                            first.X *= A;

                            // Y3   = u*(R-A) - vvv*Y1Z2
                            first.Y = R;
                            first.Y -= A;
                            first.Y *= u;
                            Y1Z2 *= vvv;
                            first.Y -= Y1Z2;

                            // Z3   = vvv*Z1Z2
                            vvv *= Z1Z2;
                            first.Z = vvv;
                        }
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_ADD_1998_CMO_2_HPP
