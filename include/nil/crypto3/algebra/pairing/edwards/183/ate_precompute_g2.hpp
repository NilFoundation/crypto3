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

#ifndef CRYPTO3_ALGEBRA_PAIRING_BLS12_ATE_PRECOMPUTE_G2_HPP
#define CRYPTO3_ALGEBRA_PAIRING_BLS12_ATE_PRECOMPUTE_G2_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 183>
                class edwards_ate_precompute_g2;

                template<>
                class edwards_ate_precompute_g2<183> {
                    using curve_type = curves::edwards<183>;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::types_policy<curve_type> policy_type;

                    using base_field_type = typename curve_type::base_field_type;
                    using g2_type = typename curve_type::template g2_type<>;
                    using g2_affine_type = typename curve_type::template g2_type<curves::coordinates::affine>;

                    using g2_field_type_value = typename g2_type::field_type::value_type;

                    struct extended_g2_projective {
                        g2_field_type_value X;
                        g2_field_type_value Y;
                        g2_field_type_value Z;
                        g2_field_type_value T;
                    };

                    static void
                        doubling_step_for_flipped_miller_loop(extended_g2_projective &current,
                                                              typename policy_type::Fq3_conic_coefficients &cc) {

                        const g2_field_type_value &X = current.X, &Y = current.Y, &Z = current.Z, &T = current.T;
                        const g2_field_type_value A = X.squared();          // A    = X1^2
                        const g2_field_type_value B = Y.squared();          // B    = Y1^2
                        const g2_field_type_value C = Z.squared();          // C    = Z1^2
                        const g2_field_type_value D = (X + Y).squared();    // D    = (X1+Y1)^2
                        const g2_field_type_value E = (Y + Z).squared();    // E    = (Y1+Z1)^2
                        const g2_field_type_value F = D - (A + B);          // F    = D-(A+B)
                        const g2_field_type_value G = E - (B + C);          // G    = E-(B+C)
                        const g2_field_type_value H =
                            g2_type::value_type::mul_by_a(A);    // param_twist_coeff_a is 1 * X for us
                        // H    = twisted_a * A
                        const g2_field_type_value I = H + B;    // I    = H+B
                        const g2_field_type_value J = C - I;    // J    = C-I
                        const g2_field_type_value K = J + C;    // K    = J+C

                        cc.c_ZZ = Y * (T - X);    // c_ZZ = 2*Y1*(T1-X1)
                        cc.c_ZZ = cc.c_ZZ + cc.c_ZZ;
                        // c_XY = 2*(C-a * A * delta_3-B)+G (a = 1 for us)
                        cc.c_XY = C - g2_type::value_type::mul_by_a(A) - B;    // param_twist_coeff_a is 1 * X for us
                        cc.c_XY = cc.c_XY + cc.c_XY + G;
                        // c_XZ = 2*(a*X1*T1*delta_3-B) (a = 1 for us)
                        cc.c_XZ = g2_type::value_type::mul_by_a(X * T) - B;    // param_twist_coeff_a is 1 * X for us
                        cc.c_XZ = cc.c_XZ + cc.c_XZ;

                        current.X = F * K;          // X3 = F*K
                        current.Y = I * (B - H);    // Y3 = I*(B-H)
                        current.Z = I * K;          // Z3 = I*K
                        current.T = F * (B - H);    // T3 = F*(B-H)
                    }

                    static void
                        full_addition_step_for_flipped_miller_loop(const extended_g2_projective &base,
                                                                   extended_g2_projective &current,
                                                                   typename policy_type::Fq3_conic_coefficients &cc) {

                        const g2_field_type_value &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z, &T1 = current.T;
                        const g2_field_type_value &X2 = base.X, &Y2 = base.Y, &Z2 = base.Z, &T2 = base.T;

                        const g2_field_type_value A = X1 * X2;                          // A    = X1*X2
                        const g2_field_type_value B = Y1 * Y2;                          // B    = Y1*Y2
                        const g2_field_type_value C = Z1 * T2;                          // C    = Z1*T2
                        const g2_field_type_value D = T1 * Z2;                          // D    = T1*Z2
                        const g2_field_type_value E = D + C;                            // E    = D+C
                        const g2_field_type_value F = (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                        // G = B + twisted_a * A
                        const g2_field_type_value G =
                            B + g2_type::value_type::mul_by_a(A);    // param_twist_coeff_a is 1*X for us

                        const g2_field_type_value H = D - C;      // H    = D-C
                        const g2_field_type_value I = T1 * T2;    // I    = T1*T2

                        // c_ZZ = delta_3* ((T1-X1)*(T2+X2)-I+A)
                        cc.c_ZZ = g2_type::value_type::mul_by_a((T1 - X1) * (T2 + X2) - I +
                                                                A);    // param_twist_coeff_a is 1*X for us

                        cc.c_XY = X1 * Z2 - X2 * Z1 + F;                // c_XY = X1*Z2-X2*Z1+F
                        cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                        current.X = E * F;                              // X3   = E*F
                        current.Y = G * H;                              // Y3   = G*H
                        current.Z = F * G;                              // Z3   = F*G
                        current.T = E * H;                              // T3   = E*H
                    }

                    static void
                        mixed_addition_step_for_flipped_miller_loop(const extended_g2_projective &base,
                                                                    extended_g2_projective &current,
                                                                    typename policy_type::Fq3_conic_coefficients &cc) {

                        const g2_field_type_value &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z, &T1 = current.T;
                        const g2_field_type_value &X2 = base.X, &Y2 = base.Y, &T2 = base.T;

                        const g2_field_type_value A = X1 * X2;                          // A    = X1*X2
                        const g2_field_type_value B = Y1 * Y2;                          // B    = Y1*Y2
                        const g2_field_type_value C = Z1 * T2;                          // C    = Z1*T2
                        const g2_field_type_value E = T1 + C;                           // E    = T1+C
                        const g2_field_type_value F = (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                        // G = B + twisted_a * A
                        const g2_field_type_value G =
                            B + g2_type::value_type::mul_by_a(A);    // param_twist_coeff_a is 1*X for us
                        const g2_field_type_value H = T1 - C;        // H    = T1-C
                        const g2_field_type_value I = T1 * T2;       // I    = T1*T2

                        // c_ZZ = delta_3* ((T1-X1)*(T2+X2)-I+A)
                        cc.c_ZZ = g2_type::value_type::mul_by_a((T1 - X1) * (T2 + X2) - I +
                                                                A);    // param_twist_coeff_a is 1*X for us

                        cc.c_XY = X1 - X2 * Z1 + F;                     // c_XY = X1*Z2-X2*Z1+F
                        cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                        current.X = E * F;                              // X3   = E*F
                        current.Y = G * H;                              // Y3   = G*H
                        current.Z = F * G;                              // Z3   = F*G
                        current.T = E * H;                              // T3   = E*H
                    }

                public:
                    using g2_precomputed_type = typename policy_type::ate_g2_precomputed_type;

                    static g2_precomputed_type process(const typename g2_type::value_type &Q) {

                        g2_precomputed_type result;
                        typename g2_affine_type::value_type Qcopy = Q.to_affine();
                        extended_g2_projective Q_ext;
                        Q_ext.X = Qcopy.X;
                        Q_ext.Y = Qcopy.Y;
                        Q_ext.Z = Qcopy.Z;
                        Q_ext.T = Qcopy.X * Qcopy.Y;

                        extended_g2_projective R = Q_ext;

                        const typename policy_type::integral_type &loop_count = params_type::ate_loop_count;

                        bool found_one = false;
                        for (long i = params_type::integral_type_max_bits - 1; i >= 0; --i) {
                            const bool bit = nil::crypto3::multiprecision::bit_test(loop_count, i);
                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            typename policy_type::Fq3_conic_coefficients cc;
                            doubling_step_for_flipped_miller_loop(R, cc);
                            result.push_back(cc);
                            if (bit) {
                                mixed_addition_step_for_flipped_miller_loop(Q_ext, R, cc);
                                result.push_back(cc);
                            }
                        }

                        return result;
                    }
                };
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_BLS12_ATE_PRECOMPUTE_G2_HPP
