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
                        constexpr static inline void process(ElementType &first) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            if (!first.is_zero()) {

                                // A = X1^2
                                field_value_type A (first.X);
                                A.square_inplace();

                                // B = Y1^2
                                field_value_type B (first.Y);
                                B.square_inplace();

                                // C = 2*Z1^2
                                field_value_type C (first.Z);
                                C.square_inplace();
                                C.double_inplace();

                                // D = a*A
                                field_value_type D (A);
                                D *= field_value_type(ElementType::params_type::a);

                                // E = (X1+Y1)^2-A-B
                                field_value_type E (first.X);
                                E += first.Y;
                                E.square_inplace();
                                E -= A;
                                E -= B;

                                // G = D+B
                                field_value_type G (D);
                                G += B;

                                // F = G-C
                                field_value_type F (G);
                                F -= C;

                                // H = D-B
                                field_value_type H (D);
                                H -= B;

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
                        }
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_DBL_2008_HWCD_HPP
