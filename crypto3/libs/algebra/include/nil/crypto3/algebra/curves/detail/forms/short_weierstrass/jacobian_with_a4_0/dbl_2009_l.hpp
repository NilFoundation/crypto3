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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_0_DBL_2009_L_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_0_DBL_2009_L_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing element doubling from the group G1 of short Weierstrass curve
                     *  for jacobian_with_a4_0 coordinates representation.
                     *  http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
                     */
                    struct short_weierstrass_element_g1_jacobian_with_a4_0_dbl_2009_l {

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

                                // C = B^2
                                field_value_type C (B);
                                C.square_inplace();

                                // D = 2 * ((X1 + B)^2 - A - C)
                                field_value_type D (first.X);
                                D += B;
                                D.square_inplace();
                                D -= A;
                                D -= C;
                                D.double_inplace();

                                // E = 3 * A
                                field_value_type E(A);
                                E += A;
                                E += A;

                                // F = E^2
                                field_value_type F(E);
                                F.square_inplace();

                                field_value_type Y1Z1 (first.Y);
                                Y1Z1 *= first.Z;

                                // X3 = F - 2 D
                                first.X = F;
                                first.X -= D;
                                first.X -= D;

                                // Y3 = E * (D - X3) - 8 * C
                                C.double_inplace();
                                C.double_inplace();
                                C.double_inplace();
                                first.Y = D;
                                first.Y -= first.X;
                                first.Y *= E;
                                first.Y -= C;

                                // Z3 = 2 * Y1 * Z1
                                first.Z = Y1Z1;
                                first.Z += Y1Z1;
                            }
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_0_DBL_2009_L_HPP
