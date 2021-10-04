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

#ifndef CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_ATE_PRECOMPUTE_G2_HPP
#define CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_ATE_PRECOMPUTE_G2_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/pairing/detail/forms/short_weierstrass/jacobian_with_a4_0/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<typename CurveType>
                class short_weierstrass_jacobian_with_a4_0_ate_precompute_g2 {
                    using curve_type = CurveType;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::short_weierstrass_jacobian_with_a4_0_types_policy<curve_type> policy_type;

                    using base_field_type = typename curve_type::base_field_type;
                    using g2_type = typename curve_type::template g2_type<>;
                    using g2_affine_type = typename curve_type::template g2_type<curves::coordinates::affine>;

                    using g2_field_type_value = typename g2_type::field_type::value_type;

                    static void doubling_step_for_miller_loop(const typename base_field_type::value_type &two_inv,
                                                              typename g2_type::value_type &current,
                                                              typename policy_type::ate_ell_coeffs &c) {

                        const g2_field_type_value X = current.X, Y = current.Y, Z = current.Z;

                        const g2_field_type_value A = two_inv * (X * Y);                 // A = X1 * Y1 / 2
                        const g2_field_type_value B = Y.squared();                       // B = Y1^2
                        const g2_field_type_value C = Z.squared();                       // C = Z1^2
                        const g2_field_type_value D = 0x03 * C;                          // D = 3 * C
                        const g2_field_type_value E = params_type::twist_coeff_b * D;    // E = twist_b * D

                        const g2_field_type_value F = 0x03 * E;                       // F = 3 * E
                        const g2_field_type_value G = two_inv * (B + F);              // G = (B+F)/2
                        const g2_field_type_value H = (Y + Z).squared() - (B + C);    // H = (Y1+Z1)^2-(B+C)
                        const g2_field_type_value I = E - B;                          // I = E-B
                        const g2_field_type_value J = X.squared();                    // J = X1^2
                        const g2_field_type_value E_squared = E.squared();            // E_squared = E^2

                        current.X = A * (B - F);                         // X3 = A * (B-F)
                        current.Y = G.squared() - (0x03 * E_squared);    // Y3 = G^2 - 3*E^2
                        current.Z = B * H;                               // Z3 = B * H
                        c.ell_0 = I;                                     // ell_0 = xi * I
                        c.ell_VW = -params_type::twist * H;              // ell_VW = - H (later: * yP)
                        c.ell_VV = 0x03 * J;                             // ell_VV = 3*J (later: * xP)
                    }

                    static void mixed_addition_step_for_miller_loop(const typename g2_affine_type::value_type base,
                                                                    typename g2_type::value_type &current,
                                                                    typename policy_type::ate_ell_coeffs &c) {

                        const g2_field_type_value X1 = current.X, Y1 = current.Y, Z1 = current.Z;
                        const g2_field_type_value &x2 = base.X, &y2 = base.Y;

                        const g2_field_type_value D = X1 - x2 * Z1;            // D = X1 - X2*Z1
                        const g2_field_type_value E = Y1 - y2 * Z1;            // E = Y1 - Y2*Z1
                        const g2_field_type_value F = D.squared();             // F = D^2
                        const g2_field_type_value G = E.squared();             // G = E^2
                        const g2_field_type_value H = D * F;                   // H = D*F
                        const g2_field_type_value I = X1 * F;                  // I = X1 * F
                        const g2_field_type_value J = H + Z1 * G - (I + I);    // J = H + Z1*G - (I+I)

                        current.X = D * J;                     // X3 = D*J
                        current.Y = E * (I - J) - (H * Y1);    // Y3 = E*(I-J)-(H*Y1)
                        current.Z = Z1 * H;                    // Z3 = Z1*H
                        c.ell_0 = E * x2 - D * y2;             // ell_0 = xi * (E * X2 - D * Y2)
                        c.ell_VV = -E;                         // ell_VV = - E (later: * xP)
                        c.ell_VW = params_type::twist * D;     // ell_VW = D (later: * yP    )
                    }

                public:
                    using g2_precomputed_type = typename policy_type::ate_g2_precomputed_type;

                    static g2_precomputed_type process(const typename g2_type::value_type &Q) {

                        typename g2_affine_type::value_type Qcopy = Q.to_affine();

                        typename base_field_type::value_type two_inv =
                            (typename base_field_type::value_type(0x02).inversed());

                        g2_precomputed_type result;
                        result.QX = Qcopy.X;
                        result.QY = Qcopy.Y;

                        typename g2_type::value_type R;
                        R.X = Qcopy.X;
                        R.Y = Qcopy.Y;
                        R.Z = g2_type::field_type::value_type::one();

                        const typename policy_type::integral_type &loop_count = params_type::ate_loop_count;

                        bool found_one = false;
                        typename policy_type::ate_ell_coeffs c;

                        for (long i = params_type::integral_type_max_bits; i >= 0; --i) {
                            const bool bit = multiprecision::bit_test(loop_count, i);
                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            doubling_step_for_miller_loop(two_inv, R, c);
                            result.coeffs.push_back(c);

                            if (bit) {
                                mixed_addition_step_for_miller_loop(Qcopy, R, c);
                                result.coeffs.push_back(c);
                            }
                        }

                        return result;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_ATE_PRECOMPUTE_G2_HPP
