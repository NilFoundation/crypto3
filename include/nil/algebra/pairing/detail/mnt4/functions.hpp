//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_MNT4_FUNCTIONS_HPP
#define ALGEBRA_PAIRING_MNT4_FUNCTIONS_HPP

#include <nil/algebra/pairing/detail/mnt4/basic_policy.hpp>

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                class mnt4_pairing_functions;

                template<>
                class mnt4_pairing_functions<298, CHAR_BIT> : public mnt4_basic_policy<298, CHAR_BIT>{
                    using policy_type = mnt4_basic_policy<298, CHAR_BIT>;
                public:

                    using Fq = typename policy_type::Fq;
                    using Fq2 = typename policy_type::Fq2;
                    using gt = typename policy_type::gt;
                    using g1 = typename policy_type::g1;
                    using g2 = typename policy_type::g2;

                    struct affine_ate_g1_precomputation {
                        Fq PX;
                        Fq PY;
                        Fq2 PY_twist_squared;
                    };

                    struct affine_ate_coeffs {
                        // TODO: trim (not all of them are needed)
                        Fq2 old_RX;
                        Fq2 old_RY;
                        Fq2 gamma;
                        Fq2 gamma_twist;
                        Fq2 gamma_X;
                    };

                    struct affine_ate_g2_precomputation {
                        Fq2 QX;
                        Fq2 QY;
                        std::vector<affine_ate_coeffs> coeffs;
                    };

                    /* ate pairing */

                    struct ate_g1_precomp {
                        Fq PX;
                        Fq PY;
                        Fq2 PX_twist;
                        Fq2 PY_twist;

                        bool operator==(const ate_g1_precomp &other) const {
                            return (this->PX == other.PX && this->PY == other.PY && this->PX_twist == other.PX_twist &&
                                    this->PY_twist == other.PY_twist);
                        }
                    };

                    typedef ate_g1_precomp g1_precomp;

                    struct ate_dbl_coeffs {
                        Fq2 c_H;
                        Fq2 c_4C;
                        Fq2 c_J;
                        Fq2 c_L;

                        bool operator==(const ate_dbl_coeffs &other) const {
                            return (this->c_H == other.c_H && this->c_4C == other.c_4C && this->c_J == other.c_J &&
                                    this->c_L == other.c_L);
                        }
                    };

                    struct ate_add_coeffs {
                        Fq2 c_L1;
                        Fq2 c_RZ;

                        bool operator==(const ate_add_coeffs &other) const {
                            return (this->c_L1 == other.c_L1 && this->c_RZ == other.c_RZ);
                        }
                    };

                    struct ate_g2_precomp {
                        Fq2 QX;
                        Fq2 QY;
                        Fq2 QY2;
                        Fq2 QX_over_twist;
                        Fq2 QY_over_twist;
                        std::vector<ate_dbl_coeffs> dbl_coeffs;
                        std::vector<ate_add_coeffs> add_coeffs;

                        bool operator==(const ate_g2_precomp &other) const {
                            return (this->QX == other.QX && this->QY == other.QY && this->QY2 == other.QY2 &&
                                    this->QX_over_twist == other.QX_over_twist &&
                                    this->QY_over_twist == other.QY_over_twist && this->dbl_coeffs == other.dbl_coeffs &&
                                    this->add_coeffs == other.add_coeffs);
                        }
                    };

                    typedef ate_g2_precomp g2_precomp;

                        /* final exponentiations */

                    gt final_exponentiation_last_chunk(const gt &elt, const gt &elt_inv) {

                        const gt elt_q = elt.Frobenius_map(1);
                        gt w1_part = elt_q.cyclotomic_exp(
                            policy_type::final_exponent_last_chunk_w1);
                        gt w0_part;
                        if (policy_type::final_exponent_last_chunk_is_w0_neg) {
                            w0_part = elt_inv.cyclotomic_exp(
                                policy_type::final_exponent_last_chunk_abs_of_w0);
                        } else {
                            w0_part = elt.cyclotomic_exp(
                                policy_type::final_exponent_last_chunk_abs_of_w0);
                        }
                        gt result = w1_part * w0_part;

                        return result;
                    }

                    gt final_exponentiation_first_chunk(const gt &elt, const gt &elt_inv) {

                        /* (q^2-1) */

                        /* elt_q2 = elt^(q^2) */
                        const gt elt_q2 = elt.Frobenius_map(2);
                        /* elt_q3_over_elt = elt^(q^2-1) */
                        const gt elt_q2_over_elt = elt_q2 * elt_inv;

                        return elt_q2_over_elt;
                    }

                    gt final_exponentiation(const gt &elt) {

                        const gt elt_inv = elt.inversed();
                        const gt elt_to_first_chunk =
                            final_exponentiation_first_chunk(elt, elt_inv);
                        const gt elt_inv_to_first_chunk =
                            final_exponentiation_first_chunk(elt_inv, elt);
                        gt result =
                            final_exponentiation_last_chunk(elt_to_first_chunk, elt_inv_to_first_chunk);

                        return result;
                    }

                    /* affine ate miller loop */

                    affine_ate_g1_precomputation affine_ate_precompute_g1(const g1 &P) {

                        g1 Pcopy = P.to_affine_coordinates();

                        affine_ate_g1_precomputation result;
                        result.PX = Pcopy.X;
                        result.PY = Pcopy.Y;
                        result.PY_twist_squared = Pcopy.Y * g2::one().twist.squared();
                        // must be
                        // result.PY_twist_squared = Pcopy.Y * g1::twist.squared();
                        // when constexpr ready

                        return result;
                    }

                    affine_ate_g2_precomputation affine_ate_precompute_g2(const g2 &Q) {

                        g2 Qcopy = Q.to_affine_coordinates();

                        affine_ate_g2_precomputation result;
                        result.QX = Qcopy.X;
                        result.QY = Qcopy.Y;

                        Fq2 RX = Qcopy.X;
                        Fq2 RY = Qcopy.Y;

                        const typename policy_type::number_type &loop_count =
                            policy_type::ate_loop_count;
                        bool found_nonzero = false;

                        std::vector<long> NAF = find_wnaf(1, loop_count);
                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            affine_ate_coeffs c;
                            c.old_RX = RX;
                            c.old_RY = RY;
                            Fq2 old_RX_2 = c.old_RX.squared();
                            c.gamma =
                                (old_RX_2 + old_RX_2 + old_RX_2 + g2::one().twist_coeff_a) * (c.old_RY + c.old_RY).inversed();
                            // must be
                            // (old_RX_2 + old_RX_2 + old_RX_2 + g2::twist_coeff_a) * (c.old_RY + c.old_RY).inversed();
                            // when constexpr ready
                            c.gamma_twist = c.gamma * g2::one().twist;
                            // must be
                            // c.gamma_twist = c.gamma * g2::twist;
                            // when constexpr ready

                            c.gamma_X = c.gamma * c.old_RX;
                            result.coeffs.push_back(c);

                            RX = c.gamma.squared() - (c.old_RX + c.old_RX);
                            RY = c.gamma * (c.old_RX - RX) - c.old_RY;

                            if (NAF[i] != 0) {
                                affine_ate_coeffs c;
                                c.old_RX = RX;
                                c.old_RY = RY;
                                if (NAF[i] > 0) {
                                    c.gamma = (c.old_RY - result.QY) * (c.old_RX - result.QX).inversed();
                                } else {
                                    c.gamma = (c.old_RY + result.QY) * (c.old_RX - result.QX).inversed();
                                }
                                c.gamma_twist = c.gamma * g2::one().twist;
                                // must be
                                // c.gamma_twist = c.gamma * g2::twist;
                                // when constexpr ready

                                c.gamma_X = c.gamma * result.QX;
                                result.coeffs.push_back(c);

                                RX = c.gamma.squared() - (c.old_RX + result.QX);
                                RY = c.gamma * (c.old_RX - RX) - c.old_RY;
                            }
                        }

                        return result;
                    }

                    gt affine_ate_miller_loop(const affine_ate_g1_precomputation &prec_P, const affine_ate_g2_precomputation &prec_Q) {

                        gt f = gt::one();

                        bool found_nonzero = false;
                        size_t idx = 0;
                        const typename policy_type::number_type &loop_count =
                            policy_type::ate_loop_count;

                        std::vector<long> NAF = find_wnaf(1, loop_count);
                        for (long i = NAF.size() - 1; i >= 0; --i) {
                            if (!found_nonzero) {
                                /* this skips the MSB itself */
                                found_nonzero |= (NAF[i] != 0);
                                continue;
                            }

                            /* code below gets executed for all bits (EXCEPT the MSB itself) of
                               param_p (skipping leading zeros) in MSB to LSB
                               order */
                            affine_ate_coeffs c = prec_Q.coeffs[idx++];

                            gt g_RR_at_P =
                                gt(
                                    prec_P.PY_twist_squared, -prec_P.PX * c.gamma_twist + c.gamma_X - c.old_RY);
                            f = f.squared().mul_by_023(g_RR_at_P);

                            if (NAF[i] != 0) {
                                affine_ate_coeffs c = prec_Q.coeffs[idx++];
                                gt g_RQ_at_P;
                                if (NAF[i] > 0) {
                                    g_RQ_at_P = gt(
                                        prec_P.PY_twist_squared, -prec_P.PX * c.gamma_twist + c.gamma_X - prec_Q.QY);
                                } else {
                                    g_RQ_at_P = gt(
                                        prec_P.PY_twist_squared, -prec_P.PX * c.gamma_twist + c.gamma_X + prec_Q.QY);
                                }
                                f = f.mul_by_023(g_RQ_at_P);
                            }
                        }

                        return f;
                    }

                    /* ate pairing */

                    struct extended_g2_projective {
                        Fq2 X;
                        Fq2 Y;
                        Fq2 Z;
                        Fq2 T;
                    };

                    void doubling_step_for_flipped_miller_loop(extended_g2_projective &current, ate_dbl_coeffs &dc) {
                        const Fq2 X = current.X, Y = current.Y, Z = current.Z, T = current.T;

                        const Fq2 A = T.squared();                             // A = T1^2
                        const Fq2 B = X.squared();                             // B = X1^2
                        const Fq2 C = Y.squared();                             // C = Y1^2
                        const Fq2 D = C.squared();                             // D = C^2
                        const Fq2 E = (X + C).squared() - B - D;               // E = (X1+C)^2-B-D
                        const Fq2 F = (B + B + B) + g2::one().twist_coeff_a * A;    // F = 3*B +  a  *A
                        // must be
                        // const Fq2 F = (B + B + B) + g2::twist_coeff_a * A;    // F = 3*B +  a  *A
                        // when constexpr ready
                        const Fq2 G = F.squared();                             // G = F^2

                        current.X = -E.doubled().doubled() + G;                     // X3 = -4*E+G
                        current.Y = -Fq(0x8) * D + F * (E + E - current.X);    // Y3 = -8*D+F*(2*E-X3)
                        current.Z = (Y + Z).squared() - C - Z.squared();            // Z3 = (Y1+Z1)^2-C-Z1^2
                        current.T = current.Z.squared();                            // T3 = Z3^2

                        dc.c_H = (current.Z + T).squared() - current.T - A;    // H = (Z3+T1)^2-T3-A
                        dc.c_4C = C + C + C + C;                               // fourC = 4*C
                        dc.c_J = (F + T).squared() - G - A;                    // J = (F+T1)^2-G-A
                        dc.c_L = (F + X).squared() - G - B;                    // L = (F+X1)^2-G-B
                    }

                    void mixed_addition_step_for_flipped_miller_loop(const Fq2 base_X, const Fq2 base_Y,
                                                                     const Fq2 base_Y_squared,
                                                                     extended_g2_projective &current,
                                                                     ate_add_coeffs &ac) {
                        const Fq2 X1 = current.X, Y1 = current.Y, Z1 = current.Z, T1 = current.T;
                        const Fq2 &x2 = base_X, &y2 = base_Y, &y2_squared = base_Y_squared;

                        const Fq2 B = x2 * T1;    // B = x2 * T1
                        const Fq2 D =
                            ((y2 + Z1).squared() - y2_squared - T1) * T1;    // D = ((y2 + Z1)^2 - y2squared - T1) * T1
                        const Fq2 H = B - X1;                           // H = B - X1
                        const Fq2 I = H.squared();                      // I = H^2
                        const Fq2 E = I + I + I + I;                    // E = 4*I
                        const Fq2 J = H * E;                            // J = H * E
                        const Fq2 V = X1 * E;                           // V = X1 * E
                        const Fq2 L1 = D - (Y1 + Y1);                   // L1 = D - 2 * Y1

                        current.X = L1.squared() - J - (V + V);              // X3 = L1^2 - J - 2*V
                        current.Y = L1 * (V - current.X) - (Y1 + Y1) * J;    // Y3 = L1 * (V-X3) - 2*Y1 * J
                        current.Z = (Z1 + H).squared() - T1 - I;             // Z3 = (Z1 + H)^2 - T1 - I
                        current.T = current.Z.squared();                     // T3 = Z3^2

                        ac.c_L1 = L1;
                        ac.c_RZ = current.Z;
                    }

                    ate_g1_precomp ate_precompute_g1(const g1 &P) {

                        g1 Pcopy = P.to_affine_coordinates();

                        ate_g1_precomp result;
                        result.PX = Pcopy.X;
                        result.PY = Pcopy.Y;
                        result.PX_twist = Pcopy.X * g2::one().twist;
                        // must be
                        // result.PX_twist = Pcopy.X * g2::twist;
                        // when constexpr ready 
                        result.PY_twist = Pcopy.Y * g2::one().twist;
                        // must be
                        // result.PY_twist = Pcopy.Y * g2::twist;
                        // when constexpr ready 

                        return result;
                    }

                    ate_g2_precomp ate_precompute_g2(const g2 &Q) {

                        g2 Qcopy = Q.to_affine_coordinates();

                        ate_g2_precomp result;
                        result.QX = Qcopy.X;
                        result.QY = Qcopy.Y;
                        result.QY2 = Qcopy.Y.squared();
                        result.QX_over_twist = Qcopy.X * g2::one().twist.inversed();
                        // must be
                        // result.QX_over_twist = Qcopy.X * g2::twist.inversed();
                        // when constexpr ready 
                        result.QY_over_twist = Qcopy.Y * g2::one().twist.inversed();
                        // must be
                        // result.QY_over_twist = Qcopy.Y * g2::twist.inversed();
                        // when constexpr ready 

                        extended_g2_projective R;
                        R.X = Qcopy.X;
                        R.Y = Qcopy.Y;
                        R.Z = Fq2::one();
                        R.T = Fq2::one();

                        const typename policy_type::number_type &loop_count =
                            policy_type::ate_loop_count;
                        bool found_one = false;

                        for (long i = policy_type::number_type_max_bits - 1; i >= 0; --i) {
                            const bool bit = boost::multiprecision::bit_test(loop_count, i);
                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            ate_dbl_coeffs dc;
                            doubling_step_for_flipped_miller_loop(R, dc);
                            result.dbl_coeffs.push_back(dc);
                            if (bit) {
                                ate_add_coeffs ac;
                                mixed_addition_step_for_flipped_miller_loop(result.QX, result.QY, result.QY2, R, ac);
                                result.add_coeffs.push_back(ac);
                            }
                        }

                        if (policy_type::ate_is_loop_count_neg) {
                            Fq2 RZ_inv = R.Z.inversed();
                            Fq2 RZ2_inv = RZ_inv.squared();
                            Fq2 RZ3_inv = RZ2_inv * RZ_inv;
                            Fq2 minus_R_affine_X = R.X * RZ2_inv;
                            Fq2 minus_R_affine_Y = -R.Y * RZ3_inv;
                            Fq2 minus_R_affine_Y2 = minus_R_affine_Y.squared();
                            ate_add_coeffs ac;
                            mixed_addition_step_for_flipped_miller_loop(minus_R_affine_X, minus_R_affine_Y,
                                                                        minus_R_affine_Y2, R, ac);
                            result.add_coeffs.push_back(ac);
                        }

                        return result;
                    }

                    gt ate_miller_loop(const ate_g1_precomp &prec_P, const ate_g2_precomp &prec_Q) {

                        Fq2 L1_coeff = Fq2(prec_P.PX, Fq::zero()) - prec_Q.QX_over_twist;

                        gt f = gt::one();

                        bool found_one = false;
                        size_t dbl_idx = 0;
                        size_t add_idx = 0;

                        const typename policy_type::number_type &loop_count =
                            policy_type::ate_loop_count;
                        for (long i = policy_type::number_type_max_bits - 1; i >= 0; --i) {
                            const bool bit = boost::multiprecision::bit_test(loop_count, i);

                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            /* code below gets executed for all bits (EXCEPT the MSB itself) of
                               param_p (skipping leading zeros) in MSB to LSB
                               order */
                            ate_dbl_coeffs dc = prec_Q.dbl_coeffs[dbl_idx++];

                            gt g_RR_at_P =
                                gt(-dc.c_4C - dc.c_J * prec_P.PX_twist + dc.c_L,
                                                                            dc.c_H * prec_P.PY_twist);
                            f = f.squared() * g_RR_at_P;
                            if (bit) {
                                ate_add_coeffs ac = prec_Q.add_coeffs[add_idx++];

                                gt g_RQ_at_P =
                                    gt(
                                        ac.c_RZ * prec_P.PY_twist, -(prec_Q.QY_over_twist * ac.c_RZ + L1_coeff * ac.c_L1));
                                f = f * g_RQ_at_P;
                            }
                        }

                        if (policy_type::ate_is_loop_count_neg) {
                            ate_add_coeffs ac = prec_Q.add_coeffs[add_idx++];
                            gt g_RnegR_at_P =
                                gt(
                                    ac.c_RZ * prec_P.PY_twist, -(prec_Q.QY_over_twist * ac.c_RZ + L1_coeff * ac.c_L1));
                            f = (f * g_RnegR_at_P).inversed();
                        }

                        return f;
                    }

                    gt ate_double_miller_loop(const ate_g1_precomp &prec_P1, const ate_g2_precomp &prec_Q1,
                                              const ate_g1_precomp &prec_P2, const ate_g2_precomp &prec_Q2) {

                        Fq2 L1_coeff1 = Fq2(prec_P1.PX, Fq::zero()) - prec_Q1.QX_over_twist;
                        Fq2 L1_coeff2 = Fq2(prec_P2.PX, Fq::zero()) - prec_Q2.QX_over_twist;

                        gt f = gt::one();

                        bool found_one = false;
                        size_t dbl_idx = 0;
                        size_t add_idx = 0;

                        const typename policy_type::number_type &loop_count =
                            policy_type::ate_loop_count;

                        for (long i = policy_type::number_type_max_bits - 1; i >= 0; --i) {
                            const bool bit = boost::multiprecision::bit_test(loop_count, i);

                            if (!found_one) {
                                /* this skips the MSB itself */
                                found_one |= bit;
                                continue;
                            }

                            /* code below gets executed for all bits (EXCEPT the MSB itself) of
                               param_p (skipping leading zeros) in MSB to LSB
                               order */
                            ate_dbl_coeffs dc1 = prec_Q1.dbl_coeffs[dbl_idx];
                            ate_dbl_coeffs dc2 = prec_Q2.dbl_coeffs[dbl_idx];
                            ++dbl_idx;

                            gt g_RR_at_P1 =
                                gt(
                                    -dc1.c_4C - dc1.c_J * prec_P1.PX_twist + dc1.c_L, dc1.c_H * prec_P1.PY_twist);

                            gt g_RR_at_P2 =
                                gt(
                                    -dc2.c_4C - dc2.c_J * prec_P2.PX_twist + dc2.c_L, dc2.c_H * prec_P2.PY_twist);

                            f = f.squared() * g_RR_at_P1 * g_RR_at_P2;

                            if (bit) {
                                ate_add_coeffs ac1 = prec_Q1.add_coeffs[add_idx];
                                ate_add_coeffs ac2 = prec_Q2.add_coeffs[add_idx];
                                ++add_idx;

                                gt g_RQ_at_P1 =
                                    gt(
                                        ac1.c_RZ * prec_P1.PY_twist,
                                        -(prec_Q1.QY_over_twist * ac1.c_RZ + L1_coeff1 * ac1.c_L1));
                                gt g_RQ_at_P2 =
                                    gt(
                                        ac2.c_RZ * prec_P2.PY_twist,
                                        -(prec_Q2.QY_over_twist * ac2.c_RZ + L1_coeff2 * ac2.c_L1));

                                f = f * g_RQ_at_P1 * g_RQ_at_P2;
                            }
                        }

                        if (policy_type::ate_is_loop_count_neg) {
                            ate_add_coeffs ac1 = prec_Q1.add_coeffs[add_idx];
                            ate_add_coeffs ac2 = prec_Q2.add_coeffs[add_idx];
                            ++add_idx;
                            gt g_RnegR_at_P1 =
                                gt(
                                    ac1.c_RZ * prec_P1.PY_twist,
                                    -(prec_Q1.QY_over_twist * ac1.c_RZ + L1_coeff1 * ac1.c_L1));
                            gt g_RnegR_at_P2 =
                                gt(
                                    ac2.c_RZ * prec_P2.PY_twist,
                                    -(prec_Q2.QY_over_twist * ac2.c_RZ + L1_coeff2 * ac2.c_L1));

                            f = (f * g_RnegR_at_P1 * g_RnegR_at_P2).inversed();
                        }

                        return f;
                    }

                    gt ate_pairing(const g1 &P, const g2 &Q) {

                        ate_g1_precomp prec_P = ate_precompute_g1(P);
                        ate_g2_precomp prec_Q = ate_precompute_g2(Q);
                        gt result = ate_miller_loop(prec_P, prec_Q);
                        return result;
                    }

                    gt ate_reduced_pairing(const g1 &P, const g2 &Q) {

                        const gt f = ate_pairing(P, Q);
                        const gt result = final_exponentiation(f);
                        return result;
                    }

                    g1_precomp precompute_g1(const g1 &P) {
                        return ate_precompute_g1(P);
                    }

                    g2_precomp precompute_g2(const g2 &Q) {
                        return ate_precompute_g2(Q);
                    }

                    gt miller_loop(const g1_precomp &prec_P, const g2_precomp &prec_Q) {
                        return ate_miller_loop(prec_P, prec_Q);
                    }

                    gt double_miller_loop(const g1_precomp &prec_P1, const g2_precomp &prec_Q1,
                                          const g1_precomp &prec_P2, const g2_precomp &prec_Q2) {
                        return ate_double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
                    }

                    gt pairing(const g1 &P, const g2 &Q) {
                        return ate_pairing(P, Q);
                    }

                    gt reduced_pairing(const g1 &P, const g2 &Q) {
                        return ate_reduced_pairing(P, Q);
                    }

                    gt affine_reduced_pairing(const g1 &P, const g2 &Q) {
                        const affine_ate_g1_precomputation prec_P = affine_ate_precompute_g1(P);
                        const affine_ate_g2_precomputation prec_Q = affine_ate_precompute_g2(Q);
                        const gt f = affine_ate_miller_loop(prec_P, prec_Q);
                        const gt result = final_exponentiation(f);
                        return result;
                    }

                };

            }    // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_MNT4_FUNCTIONS_HPP