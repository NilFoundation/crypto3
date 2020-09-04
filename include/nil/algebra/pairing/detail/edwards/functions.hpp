//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_EDWARDS_FUNCTIONS_HPP
#define ALGEBRA_PAIRING_EDWARDS_FUNCTIONS_HPP

#include <sstream>

#include <nil/algebra/pairing/detail/edwards/basic_policy.hpp>

#include <nil/algebra/curves/edwards.hpp>

#include <nil/algebra/fields/detail/params/edwards/fq.hpp>
#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/element/fp6_3over2.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                using edwards_Fq = curves::edwards_g1<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                using edwards_Fq3 = curves::edwards_g2<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                struct edwards_Fq_conic_coefficients {

                    edwards_Fq<ModulusBits, GeneratorBits> c_ZZ;
                    edwards_Fq<ModulusBits, GeneratorBits> c_XY;
                    edwards_Fq<ModulusBits, GeneratorBits> c_XZ;

                    bool operator==(const edwards_Fq_conic_coefficients &other) const {
                        return (this->c_ZZ == other.c_ZZ && this->c_XY == other.c_XY && this->c_XZ == other.c_XZ);
                    }
                };

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                struct edwards_tate_g2_precomp {
                    edwards_Fq3<ModulusBits, GeneratorBits> y0, eta;

                    bool operator==(const edwards_tate_g2_precomp &other) const {
                        return (this->y0 == other.y0 && this->eta == other.eta);
                    }
                };

                typedef edwards_ate_g2_precomp edwards_g2_precomp;

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                struct edwards_Fq3_conic_coefficients {
                    edwards_Fq3<ModulusBits, GeneratorBits> c_ZZ;
                    edwards_Fq3<ModulusBits, GeneratorBits> c_XY;
                    edwards_Fq3<ModulusBits, GeneratorBits> c_XZ;

                    bool operator==(const edwards_Fq3_conic_coefficients &other) const {
                        return (this->c_ZZ == other.c_ZZ && this->c_XY == other.c_XY && this->c_XZ == other.c_XZ);
                    }
                };

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                struct edwards_ate_g1_precomp {
                    edwards_Fq<ModulusBits, GeneratorBits> P_XY;
                    edwards_Fq<ModulusBits, GeneratorBits> P_XZ;
                    edwards_Fq<ModulusBits, GeneratorBits> P_ZZplusYZ;

                    bool operator==(const edwards_ate_g1_precomp<ModulusBits, GeneratorBits> &other) const {
                        return (this->P_XY == other.P_XY && this->P_XZ == other.P_XZ &&
                                this->P_ZZplusYZ == other.P_ZZplusYZ);
                    }
                };

                typedef edwards_ate_g1_precomp edwards_g1_precomp;

                /* final exponentiations */
                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                curves::edwards_gt<ModulusBits, GeneratorBits> edwards_final_exponentiation_last_chunk(
                    const curves::edwards_gt<ModulusBits, GeneratorBits> &elt,
                    const curves::edwards_gt<ModulusBits, GeneratorBits> &elt_inv) {

                    const curves::edwards_gt<ModulusBits, GeneratorBits> elt_q = elt.Frobenius_map(1);

                    curves::edwards_gt<ModulusBits, GeneratorBits> w1_part = elt_q.cyclotomic_exp(
                        basic_policy<edwards<ModulusBits, GeneratorBits>>::final_exponent_last_chunk_w1);
                    curves::edwards_gt<ModulusBits, GeneratorBits> w0_part;

                    if (basic_policy<edwards<ModulusBits, GeneratorBits>>::final_exponent_last_chunk_is_w0_neg) {
                        w0_part = elt_inv.cyclotomic_exp(
                            basic_policy<edwards<ModulusBits, GeneratorBits>>::final_exponent_last_chunk_abs_of_w0);
                    } else {
                        w0_part = elt.cyclotomic_exp(
                            basic_policy<edwards<ModulusBits, GeneratorBits>>::final_exponent_last_chunk_abs_of_w0);
                    }

                    curves::edwards_gt<ModulusBits, GeneratorBits> result = w1_part * w0_part;

                    return result;
                }

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                curves::edwards_gt<ModulusBits, GeneratorBits> edwards_final_exponentiation_first_chunk(
                    const curves::edwards_gt<ModulusBits, GeneratorBits> &elt,
                    const curves::edwards_gt<ModulusBits, GeneratorBits> &elt_inv) {

                    /* (q^3-1)*(q+1) */

                    /* elt_q3 = elt^(q^3) */
                    const curves::edwards_gt<ModulusBits, GeneratorBits> elt_q3 = elt.Frobenius_map(3);
                    /* elt_q3_over_elt = elt^(q^3-1) */
                    const curves::edwards_gt<ModulusBits, GeneratorBits> elt_q3_over_elt = elt_q3 * elt_inv;
                    /* alpha = elt^((q^3-1) * q) */
                    const curves::edwards_gt<ModulusBits, GeneratorBits> alpha = elt_q3_over_elt.Frobenius_map(1);
                    /* beta = elt^((q^3-1)*(q+1) */
                    const curves::edwards_gt<ModulusBits, GeneratorBits> beta = alpha * elt_q3_over_elt

                                                                                return beta;
                }

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                curves::edwards_gt<ModulusBits, GeneratorBits>
                    edwards_final_exponentiation(const curves::edwards_gt<ModulusBits, GeneratorBits> &elt) {
                    const curves::edwards_gt<ModulusBits, GeneratorBits> elt_inv = elt.inversed();
                    const curves::edwards_gt<ModulusBits, GeneratorBits> elt_to_first_chunk =
                        edwards_final_exponentiation_first_chunk(elt, elt_inv);
                    const curves::edwards_gt<ModulusBits, GeneratorBits> elt_inv_to_first_chunk =
                        edwards_final_exponentiation_first_chunk(elt_inv, elt);
                    curves::edwards_gt<ModulusBits, GeneratorBits> result =
                        edwards_final_exponentiation_last_chunk(elt_to_first_chunk, elt_inv_to_first_chunk)

                            return result;
                }

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                edwards_tate_g2_precomp edwards_tate_precompute_g2(const edwards_g2 &Q) {
                    edwards_g2 Qcopy = Q;
                    Qcopy.to_affine_coordinates();
                    edwards_tate_g2_precomp result;
                    result.y0 = Qcopy.Y * Qcopy.Z.inversed();    // Y/Z
                    result.eta = (Qcopy.Z + Qcopy.Y) *
                                 curves::edwards_gt<ModulusBits, GeneratorBits>::mul_by_non_residue(Qcopy.X)
                                     .inversed();    // (Z+Y)/(nqr*X

                    return result;
                }

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                struct extended_edwards_g1_projective {
                    edwards_Fq<ModulusBits, GeneratorBits> X;
                    edwards_Fq<ModulusBits, GeneratorBits> Y;
                    edwards_Fq<ModulusBits, GeneratorBits> Z;
                    edwards_Fq<ModulusBits, GeneratorBits> T;
                };

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                void doubling_step_for_miller_loop(extended_edwards_g1_projective &current,
                                                   edwards_Fq_conic_coefficients &cc) {
                    const edwards_Fq<ModulusBits, GeneratorBits> &X = current.X, &Y = current.Y, &Z = current.Z,
                                                                 &T = current.T;
                    const edwards_Fq<ModulusBits, GeneratorBits> A = X.squared();          // A    = X1^2
                    const edwards_Fq<ModulusBits, GeneratorBits> B = Y.squared();          // B    = Y1^2
                    const edwards_Fq<ModulusBits, GeneratorBits> C = Z.squared();          // C    = Z1^2
                    const edwards_Fq<ModulusBits, GeneratorBits> D = (X + Y).squared();    // D    = (X1+Y1)^2
                    const edwards_Fq<ModulusBits, GeneratorBits> E = (Y + Z).squared();    // E    = (Y1+Z1)^2
                    const edwards_Fq<ModulusBits, GeneratorBits> F = D - (A + B);          // F    = D-(A+B)
                    const edwards_Fq<ModulusBits, GeneratorBits> G = E - (B + C);          // G    = E-(B+C)
                    const edwards_Fq<ModulusBits, GeneratorBits> &H = A;                   // H    = A (edwards_a=1)
                    const edwards_Fq<ModulusBits, GeneratorBits> I = H + B;                // I    = H+B
                    const edwards_Fq<ModulusBits, GeneratorBits> J = C - I;                // J    = C-I
                    const edwards_Fq<ModulusBits, GeneratorBits> K = J + C;                // K    = J+C

                    cc.c_ZZ = Y * (T - X);    // c_ZZ = 2*Y1*(T1-X1)
                    cc.c_ZZ = cc.c_ZZ + cc.c_ZZ;

                    cc.c_XY = J + J + G;    // c_XY = 2*J+G
                    cc.c_XZ = X * T - B;    // c_XZ = 2*(X1*T1-B) (edwards_a=1)
                    cc.c_XZ = cc.c_XZ + cc.c_XZ;

                    current.X = F * K;          // X3 = F*K
                    current.Y = I * (B - H);    // Y3 = I*(B-H)
                    current.Z = I * K;          // Z3 = I*K
                    current.T = F * (B - H);    // T3 = F*(B-H)
                }

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                void full_addition_step_for_miller_loop(const extended_edwards_g1_projective &base,
                                                        extended_edwards_g1_projective &current,
                                                        edwards_Fq_conic_coefficients &cc) {
                    const edwards_Fq<ModulusBits, GeneratorBits> &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z,
                                                                 &T1 = current.T;
                    const edwards_Fq<ModulusBits, GeneratorBits> &X2 = base.X, &Y2 = base.Y, &Z2 = base.Z, &T2 = base.T;

                    const edwards_Fq<ModulusBits, GeneratorBits> A = X1 * X2;    // A    = X1*X2
                    const edwards_Fq<ModulusBits, GeneratorBits> B = Y1 * Y2;    // B    = Y1*Y2
                    const edwards_Fq<ModulusBits, GeneratorBits> C = Z1 * T2;    // C    = Z1*T2
                    const edwards_Fq<ModulusBits, GeneratorBits> D = T1 * Z2;    // D    = T1*Z2
                    const edwards_Fq<ModulusBits, GeneratorBits> E = D + C;      // E    = D+C
                    const edwards_Fq<ModulusBits, GeneratorBits> F =
                        (X1 - Y1) * (X2 + Y2) + B - A;                           // F    = (X1-Y1)*(X2+Y2)+B-A
                    const edwards_Fq<ModulusBits, GeneratorBits> G = B + A;      // G    = B + A (edwards_a=1)
                    const edwards_Fq<ModulusBits, GeneratorBits> H = D - C;      // H    = D-C
                    const edwards_Fq<ModulusBits, GeneratorBits> I = T1 * T2;    // I    = T1*T2

                    cc.c_ZZ = (T1 - X1) * (T2 + X2) - I + A;        // c_ZZ = (T1-X1)*(T2+X2)-I+A
                    cc.c_XY = X1 * Z2 - X2 * Z1 + F;                // c_XY = X1*Z2-X2*Z1+F
                    cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                    current.X = E * F;                              // X3   = E*F
                    current.Y = G * H;                              // Y3   = G*H
                    current.Z = F * G;                              // Z3   = F*G
                    current.T = E * H;                              // T3   = E*H
                }

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                void mixed_addition_step_for_miller_loop(const extended_edwards_g1_projective &base,
                                                         extended_edwards_g1_projective &current,
                                                         edwards_Fq_conic_coefficients &cc) {
                    const edwards_Fq<ModulusBits, GeneratorBits> &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z,
                                                                 &T1 = current.T;
                    const edwards_Fq<ModulusBits, GeneratorBits> &X2 = base.X, &Y2 = base.Y, &T2 = base.T;

                    const edwards_Fq<ModulusBits, GeneratorBits> A = X1 * X2;    // A    = X1*X2
                    const edwards_Fq<ModulusBits, GeneratorBits> B = Y1 * Y2;    // B    = Y1*Y2
                    const edwards_Fq<ModulusBits, GeneratorBits> C = Z1 * T2;    // C    = Z1*T2
                    const edwards_Fq<ModulusBits, GeneratorBits> D = T1;         // D    = T1*Z2
                    const edwards_Fq<ModulusBits, GeneratorBits> E = D + C;      // E    = D+C
                    const edwards_Fq<ModulusBits, GeneratorBits> F =
                        (X1 - Y1) * (X2 + Y2) + B - A;                           // F    = (X1-Y1)*(X2+Y2)+B-A
                    const edwards_Fq<ModulusBits, GeneratorBits> G = B + A;      // G    = B + A (edwards_a=1)
                    const edwards_Fq<ModulusBits, GeneratorBits> H = D - C;      // H    = D-C
                    const edwards_Fq<ModulusBits, GeneratorBits> I = T1 * T2;    // I    = T1*T2

                    cc.c_ZZ = (T1 - X1) * (T2 + X2) - I + A;        // c_ZZ = (T1-X1)*(T2+X2)-I+A
                    cc.c_XY = X1 - X2 * Z1 + F;                     // c_XY = X1*Z2-X2*Z1+F
                    cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                    current.X = E * F;                              // X3   = E*F
                    current.Y = G * H;                              // Y3   = G*H
                    current.Z = F * G;                              // Z3   = F*G
                    current.T = E * H;                              // T3   = E*H
                }

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                edwards_tate_g1_precomp edwards_tate_precompute_g1(const edwards_g1 &P) {
                    edwards_tate_g1_precomp result;

                    edwards_g1 Pcopy = P;
                    Pcopy.to_affine_coordinates();

                    extended_edwards_g1_projective P_ext;
                    P_ext.X = Pcopy.X;
                    P_ext.Y = Pcopy.Y;
                    P_ext.Z = Pcopy.Z;
                    P_ext.T = Pcopy.X * Pcopy.Y;

                    extended_edwards_g1_projective R = P_ext;

                    bool found_one = false;
                    for (long i = edwards_modulus_r.max_bits(); i >= 0; --i) {
                        const bool bit = edwards_modulus_r.test_bit(i);
                        if (!found_one) {
                            /* this skips the MSB itself */
                            found_one |= bit;
                            continue;
                        }

                        /* code below gets executed for all bits (EXCEPT the MSB itself) of
                           edwards_modulus_r (skipping leading zeros) in MSB to LSB
                           order */
                        edwards_Fq_conic_coefficients cc;
                        doubling_step_for_miller_loop(R, cc);
                        result.push_back(cc);

                        if (bit) {
                            mixed_addition_step_for_miller_loop(P_ext, R, cc);
                            result.push_back(cc);
                        }
                    }

                    return result;
                }

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                curves::edwards_gt<ModulusBits, GeneratorBits>
                    edwards_tate_miller_loop(const edwards_tate_g1_precomp &prec_P,
                                             const edwards_tate_g2_precomp &prec_Q) {

                    curves::edwards_gt<ModulusBits, GeneratorBits> f =
                        curves::edwards_gt<ModulusBits, GeneratorBits>::one();

                    bool found_one = false;
                    size_t idx = 0;
                    for (long i = edwards_modulus_r.max_bits() - 1; i >= 0; --i) {
                        const bool bit = edwards_modulus_r.test_bit(i);
                        if (!found_one) {
                            /* this skips the MSB itself */
                            found_one |= bit;
                            continue;
                        }

                        /* code below gets executed for all bits (EXCEPT the MSB itself) of
                           edwards_modulus_r (skipping leading zeros) in MSB to LSB
                           order */
                        edwards_Fq_conic_coefficients cc = prec_P[idx++];
                        curves::edwards_gt<ModulusBits, GeneratorBits> g_RR_at_Q =
                            curves::edwards_gt<ModulusBits, GeneratorBits>(
                                edwards_Fq3(cc.c_XZ, edwards_Fq(0l), edwards_Fq(0l)) + cc.c_XY * prec_Q.y0,
                                cc.c_ZZ * prec_Q.eta);
                        f = f.squared() * g_RR_at_Q;
                        if (bit) {
                            cc = prec_P[idx++];

                            curves::edwards_gt<ModulusBits, GeneratorBits> g_RP_at_Q =
                                curves::edwards_gt<ModulusBits, GeneratorBits>(
                                    edwards_Fq3(cc.c_XZ, edwards_Fq(0l), edwards_Fq(0l)) + cc.c_XY * prec_Q.y0,
                                    cc.c_ZZ * prec_Q.eta);
                            f = f * g_RP_at_Q;
                        }

                        return f;
                    }

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    curves::edwards_gt<ModulusBits, GeneratorBits> edwards_tate_pairing(const edwards_g1 &P,
                                                                                        const edwards_g2 &Q) {
                        edwards_tate_g1_precomp prec_P = edwards_tate_precompute_g1(P);
                        edwards_tate_g2_precomp prec_Q = edwards_tate_precompute_g2(Q);
                        curves::edwards_gt<ModulusBits, GeneratorBits> result = edwards_tate_miller_loop(prec_P, prec_Q)

                            return result;
                    }

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    curves::edwards_gt<ModulusBits, GeneratorBits> edwards_tate_reduced_pairing(const edwards_g1 &P,
                                                                                                const edwards_g2 &Q) {
                        const curves::edwards_gt<ModulusBits, GeneratorBits> f = edwards_tate_pairing(P, Q);
                        const curves::edwards_gt<ModulusBits, GeneratorBits> result = edwards_final_exponentiation(f)

                            return result;
                    }

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    struct extended_edwards_g2_projective {
                        edwards_Fq3<ModulusBits, GeneratorBits> X;
                        edwards_Fq3<ModulusBits, GeneratorBits> Y;
                        edwards_Fq3<ModulusBits, GeneratorBits> Z;
                        edwards_Fq3<ModulusBits, GeneratorBits> T;
                    };

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    void doubling_step_for_flipped_miller_loop(
                        extended_edwards_g2_projective<ModulusBits, GeneratorBits> & current,
                        edwards_Fq3_conic_coefficients & cc) {
                        const edwards_Fq3<ModulusBits, GeneratorBits> &X = current.X, &Y = current.Y, &Z = current.Z,
                                                                      &T = current.T;
                        const edwards_Fq3<ModulusBits, GeneratorBits> A = X.squared();          // A    = X1^2
                        const edwards_Fq3<ModulusBits, GeneratorBits> B = Y.squared();          // B    = Y1^2
                        const edwards_Fq3<ModulusBits, GeneratorBits> C = Z.squared();          // C    = Z1^2
                        const edwards_Fq3<ModulusBits, GeneratorBits> D = (X + Y).squared();    // D    = (X1+Y1)^2
                        const edwards_Fq3<ModulusBits, GeneratorBits> E = (Y + Z).squared();    // E    = (Y1+Z1)^2
                        const edwards_Fq3<ModulusBits, GeneratorBits> F = D - (A + B);          // F    = D-(A+B)
                        const edwards_Fq3<ModulusBits, GeneratorBits> G = E - (B + C);          // G    = E-(B+C)
                        const edwards_Fq3<ModulusBits, GeneratorBits> H =
                            edwards_g2::mul_by_a(A);    // edwards_param_twist_coeff_a is 1 * X for us
                                                        // H    = twisted_a * A
                        const edwards_Fq3<ModulusBits, GeneratorBits> I = H + B;    // I    = H+B
                        const edwards_Fq3<ModulusBits, GeneratorBits> J = C - I;    // J    = C-I
                        const edwards_Fq3<ModulusBits, GeneratorBits> K = J + C;    // K    = J+C

                        cc.c_ZZ = Y * (T - X);    // c_ZZ = 2*Y1*(T1-X1)
                        cc.c_ZZ = cc.c_ZZ + cc.c_ZZ;

                        // c_XY = 2*(C-edwards_a * A * delta_3-B)+G (edwards_a = 1 for us)
                        cc.c_XY = C - edwards_g2::mul_by_a(A) - B;    // edwards_param_twist_coeff_a is 1 * X for us
                        cc.c_XY = cc.c_XY + cc.c_XY + G;

                        // c_XZ = 2*(edwards_a*X1*T1*delta_3-B) (edwards_a = 1 for us)
                        cc.c_XZ = edwards_g2::mul_by_a(X * T) - B;    // edwards_param_twist_coeff_a is 1 * X for us
                        cc.c_XZ = cc.c_XZ + cc.c_XZ;

                        current.X = F * K;          // X3 = F*K
                        current.Y = I * (B - H);    // Y3 = I*(B-H)
                        current.Z = I * K;          // Z3 = I*K
                        current.T = F * (B - H);    // T3 = F*(B-H)
                    }

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    void full_addition_step_for_flipped_miller_loop(
                        const extended_edwards_g2_projective<ModulusBits, GeneratorBits> &base,
                        extended_edwards_g2_projective<ModulusBits, GeneratorBits> &current,
                        edwards_Fq3_conic_coefficients c) {
                        const edwards_Fq3<ModulusBits, GeneratorBits> &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z,
                                                                      &T1 = current.T;
                        const edwards_Fq3<ModulusBits, GeneratorBits> &X2 = base.X, &Y2 = base.Y, &Z2 = base.Z,
                                                                      &T2 = base.T;

                        const edwards_Fq3<ModulusBits, GeneratorBits> A = X1 * X2;    // A    = X1*X2
                        const edwards_Fq3<ModulusBits, GeneratorBits> B = Y1 * Y2;    // B    = Y1*Y2
                        const edwards_Fq3<ModulusBits, GeneratorBits> C = Z1 * T2;    // C    = Z1*T2
                        const edwards_Fq3<ModulusBits, GeneratorBits> D = T1 * Z2;    // D    = T1*Z2
                        const edwards_Fq3<ModulusBits, GeneratorBits> E = D + C;      // E    = D+C
                        const edwards_Fq3<ModulusBits, GeneratorBits> F =
                            (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                        // G = B + twisted_edwards_a * A
                        const edwards_Fq3<ModulusBits, GeneratorBits> G =
                            B + edwards_g2::mul_by_a(A);    // edwards_param_twist_coeff_a is 1*X for us
                        const edwards_Fq3<ModulusBits, GeneratorBits> H = D - C;      // H    = D-C
                        const edwards_Fq3<ModulusBits, GeneratorBits> I = T1 * T2;    // I    = T1*T2

                        // c_ZZ = delta_3* ((T1-X1)*(T2+X2)-I+A)
                        cc.c_ZZ = edwards_g2::mul_by_a((T1 - X1) * (T2 + X2) - I +
                                                       A);    // edwards_param_twist_coeff_a is 1*X for us

                        cc.c_XY = X1 * Z2 - X2 * Z1 + F;                // c_XY = X1*Z2-X2*Z1+F
                        cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                        current.X = E * F;                              // X3   = E*F
                        current.Y = G * H;                              // Y3   = G*H
                        current.Z = F * G;                              // Z3   = F*G
                        current.T = E * H;                              // T3   = E*H

                    }

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    void mixed_addition_step_for_flipped_miller_loop(
                        const extended_edwards_g2_projective<ModulusBits, GeneratorBits> &base,
                        extended_edwards_g2_projective<ModulusBits, GeneratorBits> &current,
                        edwards_Fq3_conic_coefficients &cc) {
                        const edwards_Fq3<ModulusBits, GeneratorBits> &X1 = current.X, &Y1 = current.Y, &Z1 = current.Z,
                                                                      &T1 = current.T;
                        const edwards_Fq3<ModulusBits, GeneratorBits> &X2 = base.X, &Y2 = base.Y, &T2 = base.T;

                        const edwards_Fq3<ModulusBits, GeneratorBits> A = X1 * X2;    // A    = X1*X2
                        const edwards_Fq3<ModulusBits, GeneratorBits> B = Y1 * Y2;    // B    = Y1*Y2
                        const edwards_Fq3<ModulusBits, GeneratorBits> C = Z1 * T2;    // C    = Z1*T2
                        const edwards_Fq3<ModulusBits, GeneratorBits> E = T1 + C;     // E    = T1+C
                        const edwards_Fq3<ModulusBits, GeneratorBits> F =
                            (X1 - Y1) * (X2 + Y2) + B - A;    // F    = (X1-Y1)*(X2+Y2)+B-A
                        // G = B + twisted_edwards_a * A
                        const edwards_Fq3<ModulusBits, GeneratorBits> G =
                            B + edwards_g2::mul_by_a(A);    // edwards_param_twist_coeff_a is 1*X for us
                        const edwards_Fq3<ModulusBits, GeneratorBits> H = T1 - C;     // H    = T1-C
                        const edwards_Fq3<ModulusBits, GeneratorBits> I = T1 * T2;    // I    = T1*T2

                        // c_ZZ = delta_3* ((T1-X1)*(T2+X2)-I+A)
                        cc.c_ZZ = edwards_g2::mul_by_a((T1 - X1) * (T2 + X2) - I +
                                                       A);    // edwards_param_twist_coeff_a is 1*X for us

                        cc.c_XY = X1 - X2 * Z1 + F;                     // c_XY = X1*Z2-X2*Z1+F
                        cc.c_XZ = (Y1 - T1) * (Y2 + T2) - B + I - H;    // c_XZ = (Y1-T1)*(Y2+T2)-B+I-H
                        current.X = E * F;                              // X3   = E*F
                        current.Y = G * H;                              // Y3   = G*H
                        current.Z = F * G;                              // Z3   = F*G
                        current.T = E * H;                              // T3   = E*H
                    }

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    edwards_ate_g1_precomp<ModulusBits, GeneratorBits> edwards_ate_precompute_g1(const edwards_g1 &P) {
                        edwards_g1 Pcopy = P;
                        Pcopy.to_affine_coordinates();
                        edwards_ate_g1_precomp<ModulusBits, GeneratorBits> result;
                        result.P_XY = Pcopy.X * Pcopy.Y;
                        result.P_XZ = Pcopy.X;                                // P.X * P.Z but P.Z = 1
                        result.P_ZZplusYZ = (edwards_Fq::one() + Pcopy.Y);    // (P.Z + P.Y) * P.Z but P.Z =

                        return result;
                    }

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    edwards_ate_g2_precomp<ModulusBits, GeneratorBits> edwards_ate_precompute_g2(const edwards_g2 &Q) {
                        const bigint<edwards_Fr::num_limbs> &loop_count = edwards_ate_loop_count;
                        edwards_ate_g2_precomp<ModulusBits, GeneratorBits> result;

                        edwards_g2 Qcopy(Q);
                        Qcopy.to_affine_coordinates();

                        extended_edwards_g2_projective<ModulusBits, GeneratorBits> Q_ext;
                        Q_ext.X = Qcopy.X;
                        Q_ext.Y = Qcopy.Y;
                        Q_ext.Z = Qcopy.Z;
                        Q_ext.T = Qcopy.X * Qcopy.Y;

                        extended_edwards_g2_projective<ModulusBits, GeneratorBits> R = Q_ext;

                        bool found_one = false;
                        for (long i = loop_count.max_bits() - 1; i >= 0; --i) {
                            const bool bit = loop_count.test_bit(i);
                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            edwards_Fq3_conic_coefficients<ModulusBits, GeneratorBits> cc;
                            doubling_step_for_flipped_miller_loop<ModulusBits, GeneratorBits>(R, cc);
                            result.push_back(cc);
                            if (bit) {
                                mixed_addition_step_for_flipped_miller_loop<ModulusBits, GeneratorBits>(Q_ext, R, cc);
                                result.push_back(cc);
                            }
                        }

                        return result;
                    }

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    curves::edwards_gt<ModulusBits, GeneratorBits> edwards_ate_miller_loop(
                        const edwards_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P,
                        const edwards_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q) {
                        const bigint<edwards_Fr::num_limbs> &loop_count = edwards_ate_loop_count;

                        curves::edwards_gt<ModulusBits, GeneratorBits> f =
                            curves::edwards_gt<ModulusBits, GeneratorBits>::one();

                        bool found_one = false;
                        size_t idx = 0;
                        for (long i = loop_count.max_bits() - 1; i >= 0; --i) {
                            const bool bit = loop_count.test_bit(i);
                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            /* code below gets executed for all bits (EXCEPT the MSB itself) of
                               edwards_param_p (skipping leading zeros) in MSB to LSB
                               order */
                            edwards_Fq3_conic_coefficients cc = prec_Q[idx++];

                            curves::edwards_gt<ModulusBits, GeneratorBits> g_RR_at_P =
                                curves::edwards_gt<ModulusBits, GeneratorBits>(
                                    prec_P.P_XY * cc.c_XY + prec_P.P_XZ * cc.c_XZ, prec_P.P_ZZplusYZ * cc.c_ZZ);
                            f = f.squared() * g_RR_at_P;
                            if (bit) {
                                cc = prec_Q[idx++];
                                curves::edwards_gt<ModulusBits, GeneratorBits> g_RQ_at_P =
                                    curves::edwards_gt<ModulusBits, GeneratorBits>(
                                        prec_P.P_ZZplusYZ * cc.c_ZZ, prec_P.P_XY * cc.c_XY + prec_P.P_XZ * cc.c_XZ);
                                f = f * g_RQ_at_P;
                            }

                            return f;
                        }

                        template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                        curves::edwards_gt<ModulusBits, GeneratorBits> edwards_ate_double_miller_loop(
                            const edwards_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P1,
                            const edwards_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q1,
                            const edwards_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P2,
                            const edwards_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q2) {
                            const bigint<edwards_Fr::num_limbs> &loop_count = edwards_ate_loop_count;

                            curves::edwards_gt<ModulusBits, GeneratorBits> f =
                                curves::edwards_gt<ModulusBits, GeneratorBits>::one();

                            bool found_one = false;
                            size_t idx = 0;
                            for (long i = loop_count.max_bits() - 1; i >= 0; --i) {
                                const bool bit = loop_count.test_bit(i);
                                if (!found_one) {
                                    /* this skips the MSB itself */
                                    found_one |= bit;
                                    continue;
                                }

                                /* code below gets executed for all bits (EXCEPT the MSB itself) of
                                   edwards_param_p (skipping leading zeros) in MSB to LSB
                                   order */
                                edwards_Fq3_conic_coefficients cc1 = prec_Q1[idx];
                                edwards_Fq3_conic_coefficients cc2 = prec_Q2[idx];
                                ++idx;

                                curves::edwards_gt<ModulusBits, GeneratorBits> g_RR_at_P1 =
                                    curves::edwards_gt<ModulusBits, GeneratorBits>(prec_P1.P_XY * cc1.c_XY +
                                                                                       prec_P1.P_XZ * cc1.c_XZ,
                                                                                   prec_P1.P_ZZplusYZ * cc1.c_ZZ);

                                curves::edwards_gt<ModulusBits, GeneratorBits> g_RR_at_P2 =
                                    curves::edwards_gt<ModulusBits, GeneratorBits>(prec_P2.P_XY * cc2.c_XY +
                                                                                       prec_P2.P_XZ * cc2.c_XZ,
                                                                                   prec_P2.P_ZZplusYZ * cc2.c_ZZ);
                                f = f.squared() * g_RR_at_P1 * g_RR_at_P2;

                                if (bit) {
                                    cc1 = prec_Q1[idx];
                                    cc2 = prec_Q2[idx];
                                    ++idx;
                                    curves::edwards_gt<ModulusBits, GeneratorBits> g_RQ_at_P1 =
                                        curves::edwards_gt<ModulusBits, GeneratorBits>(prec_P1.P_ZZplusYZ * cc1.c_ZZ,
                                                                                       prec_P1.P_XY * cc1.c_XY +
                                                                                           prec_P1.P_XZ * cc1.c_XZ);
                                    curves::edwards_gt<ModulusBits, GeneratorBits> g_RQ_at_P2 =
                                        curves::edwards_gt<ModulusBits, GeneratorBits>(prec_P2.P_ZZplusYZ * cc2.c_ZZ,
                                                                                       prec_P2.P_XY * cc2.c_XY +
                                                                                           prec_P2.P_XZ * cc2.c_XZ);
                                    f = f * g_RQ_at_P1 * g_RQ_at_P2;
                                }
                            }

                            return f;
                        }

                        template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                        curves::edwards_gt<ModulusBits, GeneratorBits> edwards_ate_pairing(const edwards_g1 &P,
                                                                                           const edwards_g2 &Q) {
                            edwards_ate_g1_precomp<ModulusBits, GeneratorBits> prec_P =
                                edwards_ate_precompute_g1<ModulusBits, GeneratorBits>(P);
                            edwards_ate_g2_precomp<ModulusBits, GeneratorBits> prec_Q =
                                edwards_ate_precompute_g2<ModulusBits, GeneratorBits>(Q);
                            curves::edwards_gt<ModulusBits, GeneratorBits> result =
                                edwards_ate_miller_loop<ModulusBits, GeneratorBits>(prec_P, prec_Q);
                            return result;
                        }

                        template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                        curves::edwards_gt<ModulusBits, GeneratorBits> edwards_ate_reduced_pairing(
                            const edwards_g1 &P, const edwards_g2 &Q) {
                            const curves::edwards_gt<ModulusBits, GeneratorBits> f =
                                edwards_ate_pairing<ModulusBits, GeneratorBits>(P, Q);
                            const curves::edwards_gt<ModulusBits, GeneratorBits> result =
                                edwards_final_exponentiation<ModulusBits, GeneratorBits>(f);

                            return result;
                        }

                        template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                        edwards_g1_precomp<ModulusBits, GeneratorBits> edwards_precompute_g1(const edwards_g1 &P) {
                            return edwards_ate_precompute_g1<ModulusBits, GeneratorBits>(P);
                        }

                        template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                        edwards_g2_precomp<ModulusBits, GeneratorBits> edwards_precompute_g2(const edwards_g2 &Q) {
                            return edwards_ate_precompute_g2<ModulusBits, GeneratorBits>(Q);
                        }

                        template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                        curves::edwards_gt<ModulusBits, GeneratorBits> edwards_miller_loop(
                            const edwards_g1_precomp<ModulusBits, GeneratorBits> &prec_P,
                            const edwards_g2_precomp<ModulusBits, GeneratorBits> &prec_Q) {
                            return edwards_ate_miller_loop(prec_P, prec_Q);
                        }

                        template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                        curves::edwards_gt<ModulusBits, GeneratorBits> edwards_double_miller_loop(
                            const edwards_g1_precomp<ModulusBits, GeneratorBits> &prec_P1,
                            const edwards_g2_precomp<ModulusBits, GeneratorBits> &prec_Q1,
                            const edwards_g1_precomp<ModulusBits, GeneratorBits> &prec_P2,
                            const edwards_g2_precomp<ModulusBits, GeneratorBits> &prec_Q2) {
                            return edwards_ate_double_miller_loop<ModulusBits, GeneratorBits>(
                                prec_P1, prec_Q1, prec_P2, prec_Q2);
                        }

                        template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                        curves::edwards_gt<ModulusBits, GeneratorBits> edwards_pairing(const edwards_g1 &P,
                                                                                       const edwards_g2 &Q) {
                            return edwards_ate_pairing<ModulusBits, GeneratorBits>(P, Q);
                        }

                        template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                        curves::edwards_gt<ModulusBits, GeneratorBits> edwards_reduced_pairing(const edwards_g1 &P,
                                                                                               const edwards_g2 &Q) {
                            return edwards_ate_reduced_pairing<ModulusBits, GeneratorBits>(P, Q);
                        }

            }       // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_EDWARDS_FUNCTIONS_HPP
