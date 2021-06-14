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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_FUNCTIONS_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_FUNCTIONS_HPP

#include <nil/crypto3/algebra/pairing/detail/edwards/basic_policy.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<std::size_t Version = 183>
                    class edwards_pairing_functions;

                    template<>
                    class edwards_pairing_functions<183> : public edwards_basic_policy<183> {
                        using policy_type = edwards_basic_policy<183>;

                    public:
                        using fp_type = typename policy_type::fp_type;
                        using fq_type = typename policy_type::fq_type;
                        using fqe_type = typename policy_type::fqe_type;
                        using fqk_type = typename policy_type::fqk_type;

                        using g1_type = typename policy_type::g1_type;
                        using g2_type = typename policy_type::g2_type;
                        using gt_type = typename policy_type::gt_type;

                        constexpr static const typename policy_type::number_type ate_loop_count =
                            policy_type::ate_loop_count;

                        constexpr static const typename g2_type::underlying_field_type::value_type twist =
                            g2_type::value_type::twist;
                        // must be
                        // constexpr static const typename g2_type::underlying_field_type::value_type
                        //    twist = g2::one()::twist;
                        // when constexpr ready
                        // but it's better to implement a structure pairing_params with such values

                    private:
                        using g1 = typename g1_type::value_type;
                        using g2 = typename g2_type::value_type;
                        using Fq = typename fq_type::value_type;
                        using Fq3 = typename fqe_type::value_type;
                        using gt = typename fqk_type::value_type;

                    public:
                        struct Fq_conic_coefficients {

                            Fq c_ZZ;
                            Fq c_XY;
                            Fq c_XZ;

                            bool operator==(const Fq_conic_coefficients &other) const {
                                return (this->c_ZZ == other.c_ZZ && this->c_XY == other.c_XY &&
                                        this->c_XZ == other.c_XZ);
                            }
                        };

                        struct Fq3_conic_coefficients {
                            Fq3 c_ZZ;
                            Fq3 c_XY;
                            Fq3 c_XZ;

                            bool operator==(const Fq3_conic_coefficients &other) const {
                                return (this->c_ZZ == other.c_ZZ && this->c_XY == other.c_XY &&
                                        this->c_XZ == other.c_XZ);
                            }
                        };

                        using tate_g1_precomp = std::vector<Fq_conic_coefficients>;
                        using ate_g2_precomp = std::vector<Fq3_conic_coefficients>;

                        struct ate_g1_precomp {
                            Fq P_XY;
                            Fq P_XZ;
                            Fq P_ZZplusYZ;

                            bool operator==(const ate_g1_precomp &other) const {
                                return (this->P_XY == other.P_XY && this->P_XZ == other.P_XZ &&
                                        this->P_ZZplusYZ == other.P_ZZplusYZ);
                            }
                        };

                        struct tate_g2_precomp {
                            Fq3 y0, eta;

                            bool operator==(const tate_g2_precomp &other) const {
                                return (this->y0 == other.y0 && this->eta == other.eta);
                            }
                        };

                        using g1_precomp = ate_g1_precomp;

                        using g2_precomp = ate_g2_precomp;

                    private:
                        /*************************  FINAL EXPONENTIATIONS  ***********************************/

                        static gt final_exponentiation_last_chunk(const gt &elt, const gt &elt_inv) {

                            const gt elt_q = elt.Frobenius_map(1);

                            gt w1_part = elt_q.cyclotomic_exp(policy_type::final_exponent_last_chunk_w1);
                            gt w0_part = gt::zero();

                            if (policy_type::final_exponent_last_chunk_is_w0_neg) {
                                w0_part = elt_inv.cyclotomic_exp(policy_type::final_exponent_last_chunk_abs_of_w0);
                            } else {
                                w0_part = elt.cyclotomic_exp(policy_type::final_exponent_last_chunk_abs_of_w0);
                            }

                            return w1_part * w0_part;
                        }

                        static gt final_exponentiation_first_chunk(const gt &elt, const gt &elt_inv) {

                            /* (q^3-1)*(q+1) */

                            /* elt_q3 = elt^(q^3) */
                            const gt elt_q3 = elt.Frobenius_map(3);
                            /* elt_q3_over_elt = elt^(q^3-1) */
                            const gt elt_q3_over_elt = elt_q3 * elt_inv;
                            /* alpha = elt^((q^3-1) * q) */
                            const gt alpha = elt_q3_over_elt.Frobenius_map(1);
                            /* beta = elt^((q^3-1)*(q+1) */
                            const gt beta = alpha * elt_q3_over_elt;

                            return beta;
                        }

                    public:
                        static gt final_exponentiation(const gt &elt) {
                            const gt elt_inv = elt.inversed();
                            const gt elt_to_first_chunk = final_exponentiation_first_chunk(elt, elt_inv);
                            const gt elt_inv_to_first_chunk = final_exponentiation_first_chunk(elt_inv, elt);
                            return final_exponentiation_last_chunk(elt_to_first_chunk, elt_inv_to_first_chunk);
                        }

                    private:
                        static tate_g2_precomp tate_precompute_g2(const g2 &Q) {
                            g2 Qcopy = Q.to_affine();
                            tate_g2_precomp result;
                            result.y0 = Qcopy.Y * Qcopy.Z.inversed();
                            result.eta = (Qcopy.Z + Qcopy.Y) * gt::one().mul_by_non_residue(Qcopy.X).inversed();
                            // must be
                            // gt::mul_by_non_residue(Qcopy.X).inversed();
                            // when constexpr will be ready

                            return result;
                        }

                        struct extended_g1_projective {
                            Fq X;
                            Fq Y;
                            Fq Z;
                            Fq T;
                        };

                        static void doubling_step_for_miller_loop(extended_g1_projective &current,
                                                                  Fq_conic_coefficients &cc) {
                            const Fq &X = current.X, &Y = current.Y, &Z = current.Z, &T = current.T;
                            const Fq A = X.squared();          // A    = X1^2
                            const Fq B = Y.squared();          // B    = Y1^2
                            const Fq C = Z.squared();          // C    = Z1^2
                            const Fq D = (X + Y).squared();    // D    = (X1+Y1)^2
                            const Fq E = (Y + Z).squared();    // E    = (Y1+Z1)^2
                            const Fq F = D - (A + B);          // F    = D-(A+B)
                            const Fq G = E - (B + C);          // G    = E-(B+C)
                            const Fq &H = A;                   // H    = A (a=1)
                            const Fq I = H + B;                // I    = H+B
                            const Fq J = C - I;                // J    = C-I
                            const Fq K = J + C;                // K    = J+C

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
                                                                       Fq_conic_coefficients &cc) {
                            const Fq &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z, &T1 = current.T;
                            const Fq &X2 = base.X, &Y2 = base.Y, &Z2 = base.Z, &T2 = base.T;

                            const Fq A = X1 * X2;                          // A    = X1*X2
                            const Fq B = Y1 * Y2;                          // B    = Y1*Y2
                            const Fq C = Z1 * T2;                          // C    = Z1*T2
                            const Fq D = T1 * Z2;                          // D    = T1*Z2
                            const Fq E = D + C;                            // E    = D+C
                            const Fq F = (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                            const Fq G = B + A;                            // G    = B + A (a=1)
                            const Fq H = D - C;                            // H    = D-C
                            const Fq I = T1 * T2;                          // I    = T1*T2

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
                                                                        Fq_conic_coefficients &cc) {
                            const Fq &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z, &T1 = current.T;
                            const Fq &X2 = base.X, &Y2 = base.Y, &T2 = base.T;

                            const Fq A = X1 * X2;                          // A    = X1*X2
                            const Fq B = Y1 * Y2;                          // B    = Y1*Y2
                            const Fq C = Z1 * T2;                          // C    = Z1*T2
                            const Fq D = T1;                               // D    = T1*Z2
                            const Fq E = D + C;                            // E    = D+C
                            const Fq F = (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                            const Fq G = B + A;                            // G    = B + A (a=1)
                            const Fq H = D - C;                            // H    = D-C
                            const Fq I = T1 * T2;                          // I    = T1*T2

                            cc.c_ZZ = (T1 - X1) * (T2 + X2) - I + A;        // c_ZZ = (T1-X1)*(T2+X2)-I+A
                            cc.c_XY = X1 - X2 * Z1 + F;                     // c_XY = X1*Z2-X2*Z1+F
                            cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                            current.X = E * F;                              // X3   = E*F
                            current.Y = G * H;                              // Y3   = G*H
                            current.Z = F * G;                              // Z3   = F*G
                            current.T = E * H;                              // T3   = E*H
                        }

                        static tate_g1_precomp tate_precompute_g1(const g1 &P) {

                            tate_g1_precomp result;

                            g1 Pcopy = P.to_affine();

                            extended_g1_projective P_ext;
                            P_ext.X = Pcopy.X;
                            P_ext.Y = Pcopy.Y;
                            P_ext.Z = Pcopy.Z;
                            P_ext.T = Pcopy.X * Pcopy.Y;

                            extended_g1_projective R = P_ext;

                            bool found_one = false;
                            for (long i = policy_type::scalar_field_bits; i >= 0; --i) {
                                const bool bit =
                                    nil::crypto3::multiprecision::bit_test(policy_type::scalar_field_modulus, i);
                                if (!found_one) {
                                    /* this skips the MSB itself */
                                    found_one |= bit;
                                    continue;
                                }

                                /* code below gets executed for all bits (EXCEPT the MSB itself) of
                                   policy_type::scalar_field_modulus (skipping leading zeros) in MSB to LSB
                                   order */
                                Fq_conic_coefficients cc;

                                doubling_step_for_miller_loop(R, cc);
                                result.push_back(cc);

                                if (bit) {
                                    mixed_addition_step_for_miller_loop(P_ext, R, cc);
                                    result.push_back(cc);
                                }
                            }

                            return result;
                        }

                        static gt tate_miller_loop(const tate_g1_precomp &prec_P, const tate_g2_precomp &prec_Q) {

                            gt f = gt::one();

                            bool found_one = false;
                            std::size_t idx = 0;
                            for (long i = policy_type::scalar_field_bits - 1; i >= 0; --i) {
                                const bool bit =
                                    nil::crypto3::multiprecision::bit_test(policy_type::scalar_field_modulus, i);
                                if (!found_one) {
                                    /* this skips the MSB itself */
                                    found_one |= bit;
                                    continue;
                                }

                                /* code below gets executed for all bits (EXCEPT the MSB itself) of
                                   policy_type::scalar_field_modulus (skipping leading zeros) in MSB to LSB
                                   order */
                                Fq_conic_coefficients cc = prec_P[idx++];
                                gt g_RR_at_Q =
                                    gt(Fq3(cc.c_XZ, Fq(0l), Fq(0l)) + cc.c_XY * prec_Q.y0, cc.c_ZZ * prec_Q.eta);
                                f = f.squared() * g_RR_at_Q;
                                if (bit) {
                                    cc = prec_P[idx++];

                                    gt g_RP_at_Q =
                                        gt(Fq3(cc.c_XZ, Fq(0l), Fq(0l)) + cc.c_XY * prec_Q.y0, cc.c_ZZ * prec_Q.eta);
                                    f = f * g_RP_at_Q;
                                }
                            }

                            return f;
                        }

                        static gt tate_pair(const g1 &P, const g2 &Q) {
                            tate_g1_precomp prec_P = tate_precompute_g1(P);
                            tate_g2_precomp prec_Q = tate_precompute_g2(Q);
                            gt result = tate_miller_loop(prec_P, prec_Q);

                            return result;
                        }

                        static gt tate_pair_reduced(const g1 &P, const g2 &Q) {
                            const gt f = tate_pair(P, Q);
                            const gt result = final_exponentiation(f);

                            return result;
                        }

                        struct extended_g2_projective {
                            Fq3 X;
                            Fq3 Y;
                            Fq3 Z;
                            Fq3 T;
                        };

                        static void doubling_step_for_flipped_miller_loop(extended_g2_projective &current,
                                                                          Fq3_conic_coefficients &cc) {
                            const Fq3 &X = current.X, &Y = current.Y, &Z = current.Z, &T = current.T;
                            const Fq3 A = X.squared();              // A    = X1^2
                            const Fq3 B = Y.squared();              // B    = Y1^2
                            const Fq3 C = Z.squared();              // C    = Z1^2
                            const Fq3 D = (X + Y).squared();        // D    = (X1+Y1)^2
                            const Fq3 E = (Y + Z).squared();        // E    = (Y1+Z1)^2
                            const Fq3 F = D - (A + B);              // F    = D-(A+B)
                            const Fq3 G = E - (B + C);              // G    = E-(B+C)
                            const Fq3 H = g2::one().mul_by_a(A);    // param_twist_coeff_a is 1 * X for us
                            // must be
                            // const Fq3 H = g2::mul_by_a(A);    // param_twist_coeff_a is 1 * X for us
                            // when constexpr will be ready
                            // H    = twisted_a * A
                            const Fq3 I = H + B;    // I    = H+B
                            const Fq3 J = C - I;    // J    = C-I
                            const Fq3 K = J + C;    // K    = J+C

                            cc.c_ZZ = Y * (T - X);    // c_ZZ = 2*Y1*(T1-X1)
                            cc.c_ZZ = cc.c_ZZ + cc.c_ZZ;

                            // c_XY = 2*(C-a * A * delta_3-B)+G (a = 1 for us)
                            cc.c_XY = C - g2::one().mul_by_a(A) - B;    // param_twist_coeff_a is 1 * X for us
                            // must be
                            // cc.c_XY = C - g2::mul_by_a(A) - B;    // param_twist_coeff_a is 1 * X for us
                            // when constexpr will be ready
                            cc.c_XY = cc.c_XY + cc.c_XY + G;

                            // c_XZ = 2*(a*X1*T1*delta_3-B) (a = 1 for us)
                            cc.c_XZ = g2::one().mul_by_a(X * T) - B;    // param_twist_coeff_a is 1 * X for us
                            // must be
                            // cc.c_XZ = g2::mul_by_a(X * T) - B;    // param_twist_coeff_a is 1 * X for us
                            // when constexpr will be ready
                            cc.c_XZ = cc.c_XZ + cc.c_XZ;

                            current.X = F * K;          // X3 = F*K
                            current.Y = I * (B - H);    // Y3 = I*(B-H)
                            current.Z = I * K;          // Z3 = I*K
                            current.T = F * (B - H);    // T3 = F*(B-H)
                        }

                        static void full_addition_step_for_flipped_miller_loop(const extended_g2_projective &base,
                                                                               extended_g2_projective &current,
                                                                               Fq3_conic_coefficients &cc) {

                            const Fq3 &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z, &T1 = current.T;
                            const Fq3 &X2 = base.X, &Y2 = base.Y, &Z2 = base.Z, &T2 = base.T;

                            const Fq3 A = X1 * X2;                          // A    = X1*X2
                            const Fq3 B = Y1 * Y2;                          // B    = Y1*Y2
                            const Fq3 C = Z1 * T2;                          // C    = Z1*T2
                            const Fq3 D = T1 * Z2;                          // D    = T1*Z2
                            const Fq3 E = D + C;                            // E    = D+C
                            const Fq3 F = (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                            // G = B + twisted_a * A
                            const Fq3 G = B + g2::one().mul_by_a(A);    // param_twist_coeff_a is 1*X for us
                            // must be
                            // const Fq3 G = B + g2::mul_by_a(A);    // param_twist_coeff_a is 1*X for us
                            // when constexpr will be ready
                            const Fq3 H = D - C;      // H    = D-C
                            const Fq3 I = T1 * T2;    // I    = T1*T2

                            // c_ZZ = delta_3* ((T1-X1)*(T2+X2)-I+A)
                            cc.c_ZZ = g2::one().mul_by_a((T1 - X1) * (T2 + X2) - I +
                                                         A);    // param_twist_coeff_a is 1*X for us
                            // must be
                            // cc.c_ZZ = g2::mul_by_a((T1 - X1) * (T2 + X2) - I + A);    // param_twist_coeff_a is 1*X
                            // for us when constexpr will be ready

                            cc.c_XY = X1 * Z2 - X2 * Z1 + F;                // c_XY = X1*Z2-X2*Z1+F
                            cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                            current.X = E * F;                              // X3   = E*F
                            current.Y = G * H;                              // Y3   = G*H
                            current.Z = F * G;                              // Z3   = F*G
                            current.T = E * H;                              // T3   = E*H
                        }

                        static void mixed_addition_step_for_flipped_miller_loop(const extended_g2_projective &base,
                                                                                extended_g2_projective &current,
                                                                                Fq3_conic_coefficients &cc) {

                            const Fq3 &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z, &T1 = current.T;
                            const Fq3 &X2 = base.X, &Y2 = base.Y, &T2 = base.T;

                            const Fq3 A = X1 * X2;                          // A    = X1*X2
                            const Fq3 B = Y1 * Y2;                          // B    = Y1*Y2
                            const Fq3 C = Z1 * T2;                          // C    = Z1*T2
                            const Fq3 E = T1 + C;                           // E    = T1+C
                            const Fq3 F = (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                            // G = B + twisted_a * A
                            const Fq3 G = B + g2::one().mul_by_a(A);    // param_twist_coeff_a is 1*X for us
                            // must be
                            // const Fq3 G = B + g2::mul_by_a(A);    // param_twist_coeff_a is 1*X for us
                            // when constexpr will be ready
                            const Fq3 H = T1 - C;     // H    = T1-C
                            const Fq3 I = T1 * T2;    // I    = T1*T2

                            // c_ZZ = delta_3* ((T1-X1)*(T2+X2)-I+A)
                            cc.c_ZZ = g2::one().mul_by_a((T1 - X1) * (T2 + X2) - I +
                                                         A);    // param_twist_coeff_a is 1*X for us
                            // must be
                            // cc.c_ZZ = g2::mul_by_a((T1 - X1) * (T2 + X2) - I + A);    // param_twist_coeff_a is 1*X
                            // for us when constexpr will be ready

                            cc.c_XY = X1 - X2 * Z1 + F;                     // c_XY = X1*Z2-X2*Z1+F
                            cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                            current.X = E * F;                              // X3   = E*F
                            current.Y = G * H;                              // Y3   = G*H
                            current.Z = F * G;                              // Z3   = F*G
                            current.T = E * H;                              // T3   = E*H
                        }

                        static ate_g1_precomp ate_precompute_g1(const g1 &P) {
                            g1 Pcopy = P.to_affine();
                            ate_g1_precomp result;
                            result.P_XY = Pcopy.X * Pcopy.Y;
                            result.P_XZ = Pcopy.X;                        // P.X * P.Z but P.Z = 1
                            result.P_ZZplusYZ = (Fq::one() + Pcopy.Y);    // (P.Z + P.Y) * P.Z but P.Z =

                            return result;
                        }

                        static ate_g2_precomp ate_precompute_g2(const g2 &Q) {
                            const typename policy_type::number_type &loop_count = policy_type::ate_loop_count;

                            ate_g2_precomp result;

                            g2 Qcopy = Q.to_affine();

                            extended_g2_projective Q_ext;
                            Q_ext.X = Qcopy.X;
                            Q_ext.Y = Qcopy.Y;
                            Q_ext.Z = Qcopy.Z;
                            Q_ext.T = Qcopy.X * Qcopy.Y;

                            extended_g2_projective R = Q_ext;

                            bool found_one = false;
                            for (long i = policy_type::number_type_max_bits - 1; i >= 0; --i) {
                                const bool bit = nil::crypto3::multiprecision::bit_test(loop_count, i);
                                if (!found_one) {
                                    /* this skips the MSB itself */
                                    found_one |= bit;
                                    continue;
                                }

                                Fq3_conic_coefficients cc;
                                doubling_step_for_flipped_miller_loop(R, cc);
                                result.push_back(cc);
                                if (bit) {
                                    mixed_addition_step_for_flipped_miller_loop(Q_ext, R, cc);
                                    result.push_back(cc);
                                }
                            }

                            return result;
                        }

                        static gt ate_miller_loop(const ate_g1_precomp &prec_P, const ate_g2_precomp &prec_Q) {
                            const typename policy_type::number_type &loop_count = policy_type::ate_loop_count;

                            gt f = gt::one();

                            bool found_one = false;
                            std::size_t idx = 0;
                            for (long i = number_type_max_bits - 1; i >= 0; --i) {
                                const bool bit = nil::crypto3::multiprecision::bit_test(loop_count, i);
                                if (!found_one) {
                                    /* this skips the MSB itself */
                                    found_one |= bit;
                                    continue;
                                }

                                /* code below gets executed for all bits (EXCEPT the MSB itself) of
                                   param_p (skipping leading zeros) in MSB to LSB
                                   order */
                                Fq3_conic_coefficients cc = prec_Q[idx++];

                                gt g_RR_at_P =
                                    gt(prec_P.P_XY * cc.c_XY + prec_P.P_XZ * cc.c_XZ, prec_P.P_ZZplusYZ * cc.c_ZZ);
                                f = f.squared() * g_RR_at_P;
                                if (bit) {
                                    cc = prec_Q[idx++];
                                    gt g_RQ_at_P =
                                        gt(prec_P.P_ZZplusYZ * cc.c_ZZ, prec_P.P_XY * cc.c_XY + prec_P.P_XZ * cc.c_XZ);
                                    f = f * g_RQ_at_P;
                                }
                            }

                            return f;
                        }

                        static gt ate_double_miller_loop(const ate_g1_precomp &prec_P1, const ate_g2_precomp &prec_Q1,
                                                         const ate_g1_precomp &prec_P2, const ate_g2_precomp &prec_Q2) {
                            const typename policy_type::number_type &loop_count = policy_type::ate_loop_count;

                            gt f = gt::one();

                            bool found_one = false;
                            std::size_t idx = 0;
                            for (long i = number_type_max_bits - 1; i >= 0; --i) {
                                const bool bit = nil::crypto3::multiprecision::bit_test(loop_count, i);
                                if (!found_one) {
                                    /* this skips the MSB itself */
                                    found_one |= bit;
                                    continue;
                                }

                                /* code below gets executed for all bits (EXCEPT the MSB itself) of
                                   param_p (skipping leading zeros) in MSB to LSB
                                   order */
                                Fq3_conic_coefficients cc1 = prec_Q1[idx];
                                Fq3_conic_coefficients cc2 = prec_Q2[idx];
                                ++idx;

                                gt g_RR_at_P1 = gt(prec_P1.P_XY * cc1.c_XY + prec_P1.P_XZ * cc1.c_XZ,
                                                   prec_P1.P_ZZplusYZ * cc1.c_ZZ);

                                gt g_RR_at_P2 = gt(prec_P2.P_XY * cc2.c_XY + prec_P2.P_XZ * cc2.c_XZ,
                                                   prec_P2.P_ZZplusYZ * cc2.c_ZZ);
                                f = f.squared() * g_RR_at_P1 * g_RR_at_P2;

                                if (bit) {
                                    cc1 = prec_Q1[idx];
                                    cc2 = prec_Q2[idx];
                                    ++idx;
                                    gt g_RQ_at_P1 = gt(prec_P1.P_ZZplusYZ * cc1.c_ZZ,
                                                       prec_P1.P_XY * cc1.c_XY + prec_P1.P_XZ * cc1.c_XZ);
                                    gt g_RQ_at_P2 = gt(prec_P2.P_ZZplusYZ * cc2.c_ZZ,
                                                       prec_P2.P_XY * cc2.c_XY + prec_P2.P_XZ * cc2.c_XZ);
                                    f = f * g_RQ_at_P1 * g_RQ_at_P2;
                                }
                            }

                            return f;
                        }

                        static gt ate_pair(const g1 &P, const g2 &Q) {
                            ate_g1_precomp prec_P = ate_precompute_g1(P);
                            ate_g2_precomp prec_Q = ate_precompute_g2(Q);
                            gt result = ate_miller_loop(prec_P, prec_Q);
                            return result;
                        }

                        static gt ate_pair_reduced(const g1 &P, const g2 &Q) {
                            const gt f = ate_pair(P, Q);
                            const gt result = final_exponentiation(f);

                            return result;
                        }

                        /*************************  CHOICE OF PAIRING ***********************************/

                    public:
                        static g1_precomp precompute_g1(const g1 &P) {
                            return ate_precompute_g1(P);
                        }

                        static g2_precomp precompute_g2(const g2 &Q) {
                            return ate_precompute_g2(Q);
                        }

                        static gt miller_loop(const g1_precomp &prec_P, const g2_precomp &prec_Q) {
                            return ate_miller_loop(prec_P, prec_Q);
                        }

                        static gt double_miller_loop(const g1_precomp &prec_P1,
                                                     const g2_precomp &prec_Q1,
                                                     const g1_precomp &prec_P2,
                                                     const g2_precomp &prec_Q2) {
                            return ate_double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
                        }

                        static gt pair(const g1 &P, const g2 &Q) {
                            return ate_pair(P, Q);
                        }

                        static gt pair_reduced(const g1 &P, const g2 &Q) {
                            return ate_pair_reduced(P, Q);
                        }
                    };

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_FUNCTIONS_HPP
