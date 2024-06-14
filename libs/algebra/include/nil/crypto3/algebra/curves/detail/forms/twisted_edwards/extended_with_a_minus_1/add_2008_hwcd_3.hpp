//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_ADD_2008_HWCD_3_HPP
#define CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_ADD_2008_HWCD_3_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /** @brief A struct representing element addition from the group G1 of twisted Edwards curve
                     *  for extended coordinates with a=-1 representation.
                     *  https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-3
                     *  https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.4
                     */
                    struct twisted_edwards_element_g1_extended_with_a_minus_1_add_2008_hwcd_3 {

                        template<typename ElementType>
                        constexpr static inline void process(ElementType &first,
                                                                    const ElementType &second) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            // A = (Y1-X1)*(Y2-X2)
                            field_value_type t0 (first.Y);
                            t0 -= first.X;
                            field_value_type A (second.Y);
                            A -= second.X;
                            A *= t0;

                            // B = (Y1+X1)*(Y2+X2)
                            field_value_type t1 (first.Y);
                            t1 += first.X;
                            field_value_type B (second.Y);
                            B += second.X;
                            B *= t1;

                            // C = T1*k*T2 // k = 2d?
                            field_value_type C (first.T);
                            C *= field_value_type(ElementType::params_type::d);
                            C *= second.T;
                            C.double_inplace();

                            // D = Z1*2*Z2
                            field_value_type D (first.Z);
                            D *= second.Z;
                            D.double_inplace();

                            // E = B-A
                            field_value_type E (B);
                            E -= A;

                            // F = D-C
                            field_value_type F (D);
                            F -= C;

                            // G = D+C
                            field_value_type G (D);
                            G += C;

                            // H = B+A
                            field_value_type H (B);
                            H += A;

                            // X3 = E*F
                            first.X = E;
                            first.X *= F;

                            // Y3 = G*H
                            first.Y = G;
                            first.Y *= H;

                            // T3 = E*H
                            first.T = E;
                            first.T *= H;

                            // Z3 = F*G
                            first.Z = F;
                            first.Z *= G;
                        }
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_ADD_2008_HWCD_3_HPP
