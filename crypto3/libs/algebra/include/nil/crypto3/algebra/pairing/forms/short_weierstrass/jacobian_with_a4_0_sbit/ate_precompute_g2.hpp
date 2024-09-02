//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2024  Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_SBIT_ATE_PRECOMPUTE_G2_HPP
#define CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_SBIT_ATE_PRECOMPUTE_G2_HPP

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>

#include <nil/crypto3/algebra/pairing/pairing_policy.hpp>

#include <nil/crypto3/algebra/pairing/detail/forms/short_weierstrass/jacobian_with_a4_0/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<typename CurveType>
                class short_weierstrass_jacobian_with_a4_0_sbit_ate_precompute_g2 {
                    using curve_type = CurveType;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::short_weierstrass_jacobian_with_a4_0_types_policy<curve_type> policy_type;

                    using base_field_type = typename curve_type::base_field_type;
                    using g2_type = typename curve_type::template g2_type<>;
                    using g2_affine_type = typename curve_type::template g2_type<curves::coordinates::affine>;

                    using g2_field_type_value = typename g2_type::field_type::value_type;


                    /* https://eprint.iacr.org/2013/722.pdf
                     * Equations (11) at p.13
                     * current *= 2, output ell coefficients in c
                     */
                    static void doubling_step_for_miller_loop(
                            const typename base_field_type::value_type &two_inv,
                            typename g2_type::value_type &current,
                            typename policy_type::ate_ell_coeffs &c)
                    {

                        const g2_field_type_value X = current.X, Y = current.Y, Z = current.Z;

                        const g2_field_type_value A = two_inv * (X * Y);                 // A = X1 * Y1 / 2
                        const g2_field_type_value B = Y.squared();                       // B = Y1^2
                        const g2_field_type_value C = Z.squared();                       // C = Z1^2
                        const g2_field_type_value D = C.doubled() + C;                   // D = 3 * C
                        const g2_field_type_value E = params_type::twist_coeff_b * D;    // E = twist_b * D

                        const g2_field_type_value F = E.doubled() + E;                       // F = 3 * E
                        const g2_field_type_value G = two_inv * (B + F);              // G = (B+F)/2
                        const g2_field_type_value H = (Y + Z).squared() - (B + C);    // H = (Y1+Z1)^2-(B+C)
                        const g2_field_type_value I = E - B;                          // I = E-B
                        const g2_field_type_value J = X.squared();                    // J = X1^2
                        const g2_field_type_value E_squared = E.squared();            // E_squared = E^2

                        current.X = A * (B - F);                         // X3 = A * (B-F)
                        current.Y = G.squared() - (E_squared.doubled() + E_squared);    // Y3 = G^2 - 3*E^2
                        current.Z = B * H;                               // Z3 = B * H

                        if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                            c.ell_0 = I;
                            c.ell_VW = J.doubled()+J;
                            c.ell_VV = -H;
                        } else {
                            c.ell_0 = -H;
                            c.ell_VW = J.doubled()+J;
                            c.ell_VV = I;
                        }
                    }

                    /* https://eprint.iacr.org/2013/722.pdf
                     * Equations (14?) at p.14
                     */
                    /* current += base, output ell coefficients in c */
                    static void mixed_addition_step_for_miller_loop(
                            const typename g2_affine_type::value_type base,
                            typename g2_type::value_type &current,
                            typename policy_type::ate_ell_coeffs &c)
                    {

                        const g2_field_type_value X1 = current.X, Y1 = current.Y, Z1 = current.Z;
                        const g2_field_type_value &x2 = base.X, &y2 = base.Y;

                        const g2_field_type_value theta = Y1 - y2 * Z1;
                        const g2_field_type_value lambda = X1 - x2 * Z1;
                        const g2_field_type_value C = theta.squared();
                        const g2_field_type_value D = lambda.squared();
                        const g2_field_type_value E = lambda * D;
                        const g2_field_type_value F = Z1 * C;
                        const g2_field_type_value G = X1 * D;
                        const g2_field_type_value H = E + F - G.doubled();

                        current.X = lambda * H;
                        current.Y = theta * (G - H) - (E * Y1);
                        current.Z *= E;

                        const g2_field_type_value J = theta * x2 - lambda * y2;

                        if (params_type::twist_type == curve_twist_type::TWIST_TYPE_M) {
                            c.ell_0 = J;
                            c.ell_VW = -theta;
                            c.ell_VV = lambda;
                        } else {
                            c.ell_0 = lambda;
                            c.ell_VW = -theta;
                            c.ell_VV = J;
                        }
                    }

                    static typename g2_affine_type::value_type mul_by_char(
                            typename g2_affine_type::value_type const& Q) {

                        typename g2_affine_type::value_type result;

                        result.X = Q.X.Frobenius_map(1);
                        result.X *= params_type::TWIST_MUL_BY_Q_X;
                        result.Y = Q.Y.Frobenius_map(1);
                        result.Y *= params_type::TWIST_MUL_BY_Q_Y;

                        return result;
                    }

                public:
                    using g2_precomputed_type = typename policy_type::ate_g2_precomputed_type;

                    static g2_precomputed_type process(const typename g2_type::value_type &Q) {

                        g2_precomputed_type result;

                        if (Q.is_zero()) {
                            result.is_zero = true;
                            return result;
                        }

                        result.is_zero = false;

                        typename g2_affine_type::value_type Qcopy = Q.to_affine();

                        typename base_field_type::value_type two_inv =
                            (typename base_field_type::value_type(0x02).inversed());

                        result.QX = Qcopy.X;
                        result.QY = Qcopy.Y;

                        auto negQ = -Qcopy;

                        typename g2_type::value_type R;
                        R.X = Qcopy.X;
                        R.Y = Qcopy.Y;
                        R.Z = g2_type::field_type::value_type::one();

                        typename policy_type::ate_ell_coeffs c;

                        for(auto bit = params_type::ate_loop_count_sbit.rbegin()+1; /* skip first bit */
                                bit != params_type::ate_loop_count_sbit.rend();
                                ++bit) {

                            doubling_step_for_miller_loop(two_inv, R, c);
                            result.coeffs.push_back(c);

                            switch(*bit) {
                                case 1:
                                    mixed_addition_step_for_miller_loop(Qcopy, R, c);
                                    result.coeffs.push_back(c);
                                    break;
                                case -1:
                                    mixed_addition_step_for_miller_loop(negQ, R, c);
                                    result.coeffs.push_back(c);
                                    break;
                                default: /* case 0: */
                                    continue;
                            }
                        }

                        auto q1 = mul_by_char(Qcopy);
                        auto q2 = mul_by_char(q1);

                        if (params_type::final_exponent_is_z_neg) {
                            R.Y = -R.Y;
                        }
                        q2.Y = -q2.Y;

                        mixed_addition_step_for_miller_loop(q1, R, c);
                        result.coeffs.push_back(c);
                        mixed_addition_step_for_miller_loop(q2, R, c);
                        result.coeffs.push_back(c);

                        return result;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_SHORT_WEIERSTRASS_JACOBIAN_WITH_A4_0_SBIT_ATE_PRECOMPUTE_G2_HPP
