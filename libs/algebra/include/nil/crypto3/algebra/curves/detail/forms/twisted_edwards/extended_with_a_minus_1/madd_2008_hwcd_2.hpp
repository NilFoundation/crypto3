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

#ifndef CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_MADD_2008_HWCD_2_HPP
#define CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_MADD_2008_HWCD_2_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element addition from the group G1 of twisted Edwards curve
                     *  for extended coordinates with a=-1 representation.
                     *  https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-madd-2008-hwcd-2
                     */

                    struct twisted_edwards_element_g1_extended_with_a_minus_1_madd_2008_hwcd_2 {

                        template<typename ElementType>
                        constexpr static inline void process(ElementType &first,
                                                                    const ElementType &second) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            // assert(second.Z == field_value_type::one());

                            // A = X1*X2
                            field_value_type A (first.X);
                            A *= second.X;

                            // B = Y1*Y2
                            field_value_type B (first.Y);
                            B *= second.Y;

                            // C = Z1*T2
                            field_value_type C (first.Z);
                            C *= second.T;

                            // D = T1
                            field_value_type D (first.T);

                            // E = D+C
                            field_value_type E (D);
                            E += C;

                            // F = (X1-Y1)*(X2+Y2)+B-A
                            field_value_type t0 (first.X);
                            t0 -= first.Y;
                            field_value_type F (second.X);
                            F += second.Y;
                            F *= t0;
                            F += B;
                            F -= A;

                            // G = B+a*A
                            field_value_type G (A);
                            G *= field_value_type(ElementType::params_type::a);
                            G += B;

                            // H = D-C
                            field_value_type H (D);
                            H -= C;

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
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_MADD_2008_HWCD_2_HPP
