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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TATE_PRECOMPUTE_G1_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TATE_PRECOMPUTE_G1_HPP

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/detail/bls12/381/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 183>
                class edwards_ate_precompute_g1;

                template<>
                class edwards_ate_precompute_g1<183> {
                    using curve_type = curves::edwards<183>;

                    using params_type = detail::pairing_params<curve_type>;
                    typedef detail::types_policy<curve_type> policy_type;

                    using base_field_type = typename curve_type::base_field_type;
                    using g1_type = typename curve_type::template g1_type<>;
                    using g1_affine_type = typename curve_type::template g1_type<curves::coordinates::affine>;

                    using g1_field_type_value = typename g1_type::field_type::value_type;

                    struct extended_g1_projective {
                        g1_field_type_value X;
                        g1_field_type_value Y;
                        g1_field_type_value Z;
                        g1_field_type_value T;
                    };

                    static void doubling_step_for_miller_loop(extended_g1_projective &current,
                                                              typename policy_type::Fq_conic_coefficients &cc) {

                        const g1_field_type_value &X = current.X, &Y = current.Y, &Z = current.Z, &T = current.T;
                        const g1_field_type_value A = X.squared();          // A    = X1^2
                        const g1_field_type_value B = Y.squared();          // B    = Y1^2
                        const g1_field_type_value C = Z.squared();          // C    = Z1^2
                        const g1_field_type_value D = (X + Y).squared();    // D    = (X1+Y1)^2
                        const g1_field_type_value E = (Y + Z).squared();    // E    = (Y1+Z1)^2
                        const g1_field_type_value F = D - (A + B);          // F    = D-(A+B)
                        const g1_field_type_value G = E - (B + C);          // G    = E-(B+C)
                        const g1_field_type_value &H = A;                   // H    = A (a=1)
                        const g1_field_type_value I = H + B;                // I    = H+B
                        const g1_field_type_value J = C - I;                // J    = C-I
                        const g1_field_type_value K = J + C;                // K    = J+C

                        cc.c_ZZ = Y * (T - X);    // c_ZZ = 2*Y1*(T1-X1)
                        cc.c_ZZ = cc.c_ZZ + cc.c_ZZ;

                        cc.c_XY = J + J + G;    // c_XY = 2*J+G
                        cc.c_XZ = X * T - B;    // c_XZ = 2*(X1*T1-B) (a=1)
                        cc.c_XZ = cc.c_XZ + cc.c_XZ;

                        current.X = F * K;          // X3 = F*K
                        current.Y = I * (B - H);    // Y3 = I*(B-H)
                        current.Z = I * K;          // Z3 = I*K
                        current.T = F * (B - H);    // T3 = F*(B-H)
                    }

                    static void full_addition_step_for_miller_loop(const extended_g1_projective &base,
                                                                   extended_g1_projective &current,
                                                                   typename policy_type::Fq_conic_coefficients &cc) {

                        const g1_field_type_value &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z, &T1 = current.T;
                        const g1_field_type_value &X2 = base.X, &Y2 = base.Y, &Z2 = base.Z, &T2 = base.T;

                        const g1_field_type_value A = X1 * X2;                          // A    = X1*X2
                        const g1_field_type_value B = Y1 * Y2;                          // B    = Y1*Y2
                        const g1_field_type_value C = Z1 * T2;                          // C    = Z1*T2
                        const g1_field_type_value D = T1 * Z2;                          // D    = T1*Z2
                        const g1_field_type_value E = D + C;                            // E    = D+C
                        const g1_field_type_value F = (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                        const g1_field_type_value G = B + A;                            // G    = B + A (a=1)
                        const g1_field_type_value H = D - C;                            // H    = D-C
                        const g1_field_type_value I = T1 * T2;                          // I    = T1*T2

                        cc.c_ZZ = (T1 - X1) * (T2 + X2) - I + A;        // c_ZZ = (T1-X1)*(T2+X2)-I+A
                        cc.c_XY = X1 * Z2 - X2 * Z1 + F;                // c_XY = X1*Z2-X2*Z1+F
                        cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                        current.X = E * F;                              // X3   = E*F
                        current.Y = G * H;                              // Y3   = G*H
                        current.Z = F * G;                              // Z3   = F*G
                        current.T = E * H;                              // T3   = E*H
                    }

                    static void mixed_addition_step_for_miller_loop(const extended_g1_projective &base,
                                                                    extended_g1_projective &current,
                                                                    typename policy_type::Fq_conic_coefficients &cc) {

                        const g1_field_type_value &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z, &T1 = current.T;
                        const g1_field_type_value &X2 = base.X, &Y2 = base.Y, &T2 = base.T;

                        const g1_field_type_value A = X1 * X2;                          // A    = X1*X2
                        const g1_field_type_value B = Y1 * Y2;                          // B    = Y1*Y2
                        const g1_field_type_value C = Z1 * T2;                          // C    = Z1*T2
                        const g1_field_type_value D = T1;                               // D    = T1*Z2
                        const g1_field_type_value E = D + C;                            // E    = D+C
                        const g1_field_type_value F = (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                        const g1_field_type_value G = B + A;                            // G    = B + A (a=1)
                        const g1_field_type_value H = D - C;                            // H    = D-C
                        const g1_field_type_value I = T1 * T2;                          // I    = T1*T2

                        cc.c_ZZ = (T1 - X1) * (T2 + X2) - I + A;        // c_ZZ = (T1-X1)*(T2+X2)-I+A
                        cc.c_XY = X1 - X2 * Z1 + F;                     // c_XY = X1*Z2-X2*Z1+F
                        cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                        current.X = E * F;                              // X3   = E*F
                        current.Y = G * H;                              // Y3   = G*H
                        current.Z = F * G;                              // Z3   = F*G
                        current.T = E * H;                              // T3   = E*H
                    }

                public:
                    using g1_precomputed_type = typename policy_type::tate_g1_precomp;

                    static typename policy_type::tate_g1_precomp process(const typename g1_type::value_type &P) {

                        typename policy_type::tate_g1_precomp result;

                        typename g1_affine_type::value_type Pcopy = P.to_affine();

                        extended_g1_projective P_ext;
                        P_ext.X = Pcopy.X;
                        P_ext.Y = Pcopy.Y;
                        P_ext.Z = Pcopy.Z;
                        P_ext.T = Pcopy.X * Pcopy.Y;

                        extended_g1_projective R = P_ext;

                        bool found_one = false;
                        for (long i = params_type::scalar_field_bits; i >= 0; --i) {
                            const bool bit =
                                nil::crypto3::multiprecision::bit_test(params_type::scalar_field_modulus, i);
                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            /* code below gets executed for all bits (EXCEPT the MSB itself) of
                               params_type::scalar_field_modulus (skipping leading zeros) in MSB to LSB
                               order */
                            policy_type::Fq_conic_coefficients cc;

                            doubling_step_for_miller_loop(R, cc);
                            result.push_back(cc);

                            if (bit) {
                                mixed_addition_step_for_miller_loop(P_ext, R, cc);
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
#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_TATE_PRECOMPUTE_G1_HPP
