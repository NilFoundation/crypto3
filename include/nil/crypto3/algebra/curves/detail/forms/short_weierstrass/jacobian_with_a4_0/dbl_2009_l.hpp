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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_0_DBL_2009_L_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_0_DBL_2009_L_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element doubling from the group G1 of short Weierstrass curve
                     *  for jacobian_with_a4_0 coordinates representation.
                     *  NOTE: does not handle O and pts of order 2,4
                     *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
                     */
                    struct short_weierstrass_element_g1_jacobian_with_a4_0_dbl_2009_l {

                        template<typename ElementType>
                        constexpr static inline ElementType process(const ElementType &first) {

                            using field_value_type = typename ElementType::field_type::value_type;

                            // handle point at infinity
                            if (first.is_zero()) {
                                return (first);
                            }

                            field_value_type A = (first.X).squared();    // A = X1^2
                            field_value_type B = (first.Y).squared();    // B = Y1^2
                            field_value_type C = B.squared();            // C = B^2
                            field_value_type D = (first.X + B).squared() - A - C;
                            D = D + D;                            // D = 2 * ((X1 + B)^2 - A - C)
                            field_value_type E = A + A + A;       // E = 3 * A
                            field_value_type F = E.squared();     // F = E^2
                            field_value_type X3 = F - (D + D);    // X3 = F - 2 D
                            field_value_type eightC = C + C;
                            eightC = eightC + eightC;
                            eightC = eightC + eightC;
                            field_value_type Y3 = E * (D - X3) - eightC;    // Y3 = E * (D - X3) - 8 * C
                            field_value_type Y1Z1 = (first.Y) * (first.Z);
                            field_value_type Z3 = Y1Z1 + Y1Z1;    // Z3 = 2 * Y1 * Z1

                            return ElementType(X3, Y3, Z3);
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_0_DBL_2009_L_HPP
