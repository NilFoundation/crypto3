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
                        constexpr static inline ElementType process(const ElementType &first,
                                                                    const ElementType &second) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            field_value_type A = (first.Y - first.X) * (second.Y - second.X);    // A = (Y1-X1)*(Y2-X2)
                            field_value_type B = (first.Y + first.X) * (second.Y + second.X);    // B = (Y1+X1)*(Y2+X2)
                            field_value_type C = first.T * field_value_type(2) * ElementType::params_type::d *
                                                 second.T;                                    // C = T1*k*T2
                            field_value_type D = first.Z * field_value_type(2) * second.Z;    // D = Z1*2*Z2
                            field_value_type E = B - A;                                       // E = B-A
                            field_value_type F = D - C;                                       // F = D-C
                            field_value_type G = D + C;                                       // G = D+C
                            field_value_type H = B + A;                                       // H = B+A
                            field_value_type X3 = E * F;                                      // X3 = E*F
                            field_value_type Y3 = G * H;                                      // Y3 = G*H
                            field_value_type T3 = E * H;                                      // T3 = E*H
                            field_value_type Z3 = F * G;                                      // Z3 = F*G

                            return ElementType(X3, Y3, T3, Z3);
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_ADD_2008_HWCD_3_HPP
