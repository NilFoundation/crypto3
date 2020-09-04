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

#include <sstream>

#include <nil/algebra/pairing/ate.hpp>
#include <nil/algebra/pairing/basic_policy.hpp>

#include <nil/algebra/curves/mnt4.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail{

                using nil::algebra;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                using mnt4_Fq = curves::mnt4_g1<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                using mnt4_Fq2 = curves::mnt4_g2<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_affine_ate_g1_precomputation {
                    mnt4_Fq PX;
                    mnt4_Fq PY;
                    mnt4_Fq2 PY_twist_squared;
                };

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_affine_ate_coeffs {
                    // TODO: trim (not all of them are needed)
                    mnt4_Fq2 old_RX;
                    mnt4_Fq2 old_RY;
                    mnt4_Fq2 gamma;
                    mnt4_Fq2 gamma_twist;
                    mnt4_Fq2 gamma_X;
                };

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_affine_ate_g2_precomputation {
                    mnt4_Fq2 QX;
                    mnt4_Fq2 QY;
                    std::vector<mnt4_affine_ate_coeffs> coeffs;
                };

                mnt4_affine_ate_g1_precomputation mnt4_affine_ate_precompute_g1(const mnt4_g1& P);
                mnt4_affine_ate_g2_precomputation mnt4_affine_ate_precompute_g2(const mnt4_g2& Q);

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_affine_ate_miller_loop(const mnt4_affine_ate_g1_precomputation &prec_P,
                                                     const mnt4_affine_ate_g2_precomputation &prec_Q);

                /* ate pairing */

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_ate_g1_precomp {
                    mnt4_Fq PX;
                    mnt4_Fq PY;
                    mnt4_Fq2 PX_twist;
                    mnt4_Fq2 PY_twist;

                    bool operator==(const mnt4_ate_g1_precomp &other) const {
                        return (this->PX == other.PX &&
                                this->PY == other.PY &&
                                this->PX_twist == other.PX_twist &&
                                this->PY_twist == other.PY_twist);
                    }
                };

                typedef mnt4_ate_g1_precomp mnt4_g1_precomp;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_ate_dbl_coeffs {
                    mnt4_Fq2 c_H;
                    mnt4_Fq2 c_4C;
                    mnt4_Fq2 c_J;
                    mnt4_Fq2 c_L;

                    bool operator==(const mnt4_ate_dbl_coeffs &other) const {
                        return (this->c_H == other.c_H &&
                                this->c_4C == other.c_4C &&
                                this->c_J == other.c_J &&
                                this->c_L == other.c_L);
                    }

                };

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_ate_add_coeffs {
                    mnt4_Fq2 c_L1;
                    mnt4_Fq2 c_RZ;

                    bool operator==(const mnt4_ate_add_coeffs &other) const {
                        return (this->c_L1 == other.c_L1 &&
                                this->c_RZ == other.c_RZ);
                    }
                };

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_ate_g2_precomp {
                    mnt4_Fq2 QX;
                    mnt4_Fq2 QY;
                    mnt4_Fq2 QY2;           
                    mnt4_Fq2 QX_over_twist;
                    mnt4_Fq2 QY_over_twist;
                    std::vector<mnt4_ate_dbl_coeffs> dbl_coeffs;
                    std::vector<mnt4_ate_add_coeffs> add_coeffs;

                    bool operator==(const mnt4_ate_g2_precomp &other) const {
                        return (this->QX == other.QX &&
                                this->QY == other.QY &&
                                this->QY2 == other.QY2 &&
                                this->QX_over_twist == other.QX_over_twist &&
                                          this->QY_over_twist == other.QY_over_twist &&
                                this->dbl_coeffs == other.dbl_coeffs &&
                                this->add_coeffs == other.add_coeffs);
                    }
                };

                typedef mnt4_ate_g2_precomp mnt4_g2_precomp;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                bool mnt4_ate_g2_precomp::

                /* final exponentiations */

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_final_exponentiation_last_chunk(const curves::mnt4_gt<ModulusBits, GeneratorBits> &elt, const curves::mnt4_gt<ModulusBits, GeneratorBits> &elt_inv) {
                    
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> elt_q = elt.Frobenius_map(1);
                    curves::mnt4_gt<ModulusBits, GeneratorBits> w1_part = elt_q.cyclotomic_exp(basic_policy<mnt4<ModulusBits, GeneratorBits>>::final_exponent_last_chunk_w1);
                    curves::mnt4_gt<ModulusBits, GeneratorBits> w0_part;
                    if (basic_policy<mnt4<ModulusBits, GeneratorBits>>::final_exponent_last_chunk_is_w0_neg) {
                        w0_part = elt_inv.cyclotomic_exp(basic_policy<mnt4<ModulusBits, GeneratorBits>>::final_exponent_last_chunk_abs_of_w0);
                    } else {
                        w0_part = elt.cyclotomic_exp(basic_policy<mnt4<ModulusBits, GeneratorBits>>::final_exponent_last_chunk_abs_of_w0);
                    }
                    curves::mnt4_gt<ModulusBits, GeneratorBits> result = w1_part * w0_part;

                    return result;
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_final_exponentiation_first_chunk(const curves::mnt4_gt<ModulusBits, GeneratorBits> &elt, const curves::mnt4_gt<ModulusBits, GeneratorBits> &elt_inv) {

                    /* (q^2-1) */

                    /* elt_q2 = elt^(q^2) */
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> elt_q2 = elt.Frobenius_map(2);
                    /* elt_q3_over_elt = elt^(q^2-1) */
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> elt_q2_over_elt = elt_q2 * elt_inv;

                    return elt_q2_over_elt;
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_final_exponentiation(const curves::mnt4_gt<ModulusBits, GeneratorBits> &elt) {
                    
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> elt_inv = elt.inverse();
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> elt_to_first_chunk = mnt4_final_exponentiation_first_chunk(elt, elt_inv);
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> elt_inv_to_first_chunk = mnt4_final_exponentiation_first_chunk(elt_inv, elt);
                    curves::mnt4_gt<ModulusBits, GeneratorBits> result = mnt4_final_exponentiation_last_chunk(elt_to_first_chunk, elt_inv_to_first_chunk);

                    return result;
                }

                /* affine ate miller loop */

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                mnt4_affine_ate_g1_precomputation mnt4_affine_ate_precompute_g1(const mnt4_g1& P) {
                    

                    mnt4_g1 Pcopy = P;
                    Pcopy.to_affine_coordinates();

                    mnt4_affine_ate_g1_precomputation result;
                    result.PX = Pcopy.X;
                    result.PY = Pcopy.Y;
                    result.PY_twist_squared = Pcopy.Y * mnt4_twist.square();

                    return result;
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                mnt4_affine_ate_g2_precomputation mnt4_affine_ate_precompute_g2(const mnt4_g2& Q) {
                    

                    mnt4_g2 Qcopy(Q);
                    Qcopy.to_affine_coordinates();

                    mnt4_affine_ate_g2_precomputation result;
                    result.QX = Qcopy.X;
                    result.QY = Qcopy.Y;

                    mnt4_Fq2 RX = Qcopy.X;
                    mnt4_Fq2 RY = Qcopy.Y;

                    const typename basic_policy<mnt4<ModulusBits, GeneratorBits>> :: number_type &loop_count = basic_policy<mnt4<ModulusBits, GeneratorBits>>::ate_loop_count;
                    bool found_nonzero = false;

                    std::vector<long> NAF = find_wnaf(1, loop_count);
                    for (long i = NAF.size() - 1; i >= 0; --i) {
                        if (!found_nonzero) {
                            /* this skips the MSB itself */
                            found_nonzero |= (NAF[i] != 0);
                            continue;
                        }

                        mnt4_affine_ate_coeffs c;
                        c.old_RX = RX;
                        c.old_RY = RY;
                        mnt4_Fq2 old_RX_2 = c.old_RX.square();
                        c.gamma = (old_RX_2 + old_RX_2 + old_RX_2 + mnt4_twist_coeff_a) * (c.old_RY + c.old_RY).inverse();
                        c.gamma_twist = c.gamma * mnt4_twist;
                        c.gamma_X = c.gamma * c.old_RX;
                        result.coeffs.push_back(c);

                        RX = c.gamma.square() - (c.old_RX+c.old_RX);
                        RY = c.gamma * (c.old_RX - RX) - c.old_RY;

                        if (NAF[i] != 0) {
                            mnt4_affine_ate_coeffs c;
                            c.old_RX = RX;
                            c.old_RY = RY;
                            if (NAF[i] > 0) {
                                c.gamma = (c.old_RY - result.QY) * (c.old_RX - result.QX).inverse();
                            }
                            else {
                                c.gamma = (c.old_RY + result.QY) * (c.old_RX - result.QX).inverse();
                            }
                            c.gamma_twist = c.gamma * mnt4_twist;
                            c.gamma_X = c.gamma * result.QX;
                            result.coeffs.push_back(c);

                            RX = c.gamma.square() - (c.old_RX+result.QX);
                            RY = c.gamma * (c.old_RX - RX) - c.old_RY;
                        }
                    }

                    return result;
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_affine_ate_miller_loop(const mnt4_affine_ate_g1_precomputation &prec_P,
                                                     const mnt4_affine_ate_g2_precomputation &prec_Q) {
                    

                    curves::mnt4_gt<ModulusBits, GeneratorBits> f = curves::mnt4_gt<ModulusBits, GeneratorBits>::one();

                    bool found_nonzero = false;
                    size_t idx = 0;
                    const typename basic_policy<mnt4<ModulusBits, GeneratorBits>> :: number_type &loop_count = basic_policy<mnt4<ModulusBits, GeneratorBits>>::ate_loop_count;

                    std::vector<long> NAF = find_wnaf(1, loop_count);
                    for (long i = NAF.size() - 1; i >= 0; --i) {
                        if (!found_nonzero) {
                            /* this skips the MSB itself */
                            found_nonzero |= (NAF[i] != 0);
                            continue;
                        }

                        /* code below gets executed for all bits (EXCEPT the MSB itself) of
                           mnt4_param_p (skipping leading zeros) in MSB to LSB
                           order */
                        mnt4_affine_ate_coeffs c = prec_Q.coeffs[idx++];

                        curves::mnt4_gt<ModulusBits, GeneratorBits> g_RR_at_P = curves::mnt4_gt<ModulusBits, GeneratorBits>(prec_P.PY_twist_squared,
                                                      - prec_P.PX * c.gamma_twist + c.gamma_X - c.old_RY);
                        f = f.square().mul_by_023(g_RR_at_P);

                        if (NAF[i] != 0) {
                            mnt4_affine_ate_coeffs c = prec_Q.coeffs[idx++];
                            curves::mnt4_gt<ModulusBits, GeneratorBits> g_RQ_at_P;
                            if (NAF[i] > 0) {
                                g_RQ_at_P = curves::mnt4_gt<ModulusBits, GeneratorBits>(prec_P.PY_twist_squared,
                                                     - prec_P.PX * c.gamma_twist + c.gamma_X - prec_Q.QY);
                            }
                            else {
                                g_RQ_at_P = curves::mnt4_gt<ModulusBits, GeneratorBits>(prec_P.PY_twist_squared,
                                                     - prec_P.PX * c.gamma_twist + c.gamma_X + prec_Q.QY);
                            }
                            f = f.mul_by_023(g_RQ_at_P);
                        }
                    }


                    return f;
                }

                /* ate pairing */

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct extended_mnt4_g2_projective {
                    mnt4_Fq2 X;
                    mnt4_Fq2 Y;
                    mnt4_Fq2 Z;
                    mnt4_Fq2 T;
                };

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                void doubling_step_for_flipped_miller_loop(extended_mnt4_g2_projective &current,
                                                           mnt4_ate_dbl_coeffs &dc) {
                    const mnt4_Fq2 X = current.X, Y = current.Y, Z = current.Z, T = current.T;

                    const mnt4_Fq2 A = T.square(); // A = T1^2
                    const mnt4_Fq2 B = X.square(); // B = X1^2
                    const mnt4_Fq2 C = Y.square(); // C = Y1^2
                    const mnt4_Fq2 D = C.square(); // D = C^2
                    const mnt4_Fq2 E = (X+C).square() - B - D; // E = (X1+C)^2-B-D
                    const mnt4_Fq2 F = (B+B+B) + mnt4_twist_coeff_a * A; // F = 3*B +  a  *A
                    const mnt4_Fq2 G = F.square(); // G = F^2

                    current.X = -E.dbl().dbl() + G; // X3 = -4*E+G
                    current.Y = -mnt4_Fq(0x8)*D + F*(E+E-current.X); // Y3 = -8*D+F*(2*E-X3)
                    current.Z = (Y+Z).square() - C - Z.square(); // Z3 = (Y1+Z1)^2-C-Z1^2
                    current.T = current.Z.square(); // T3 = Z3^2

                    dc.c_H = (current.Z + T).square() - current.T - A; // H = (Z3+T1)^2-T3-A
                    dc.c_4C = C+C+C+C; // fourC = 4*C
                    dc.c_J = (F+T).square() - G - A; // J = (F+T1)^2-G-A
                    dc.c_L = (F+X).square() - G - B; // L = (F+X1)^2-G-B

                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                void mixed_addition_step_for_flipped_miller_loop(const mnt4_Fq2 base_X, const mnt4_Fq2 base_Y, const mnt4_Fq2 base_Y_squared,
                                                                 extended_mnt4_g2_projective &current,
                                                                 mnt4_ate_add_coeffs &ac) {
                    const mnt4_Fq2 X1 = current.X, Y1 = current.Y, Z1 = current.Z, T1 = current.T;
                    const mnt4_Fq2 &x2 = base_X,    &y2 =  base_Y, &y2_squared = base_Y_squared;

                    const mnt4_Fq2 B = x2 * T1; // B = x2 * T1
                    const mnt4_Fq2 D = ((y2 + Z1).square() - y2_squared - T1) * T1; // D = ((y2 + Z1)^2 - y2squared - T1) * T1
                    const mnt4_Fq2 H = B - X1; // H = B - X1
                    const mnt4_Fq2 I = H.square(); // I = H^2
                    const mnt4_Fq2 E = I + I + I + I; // E = 4*I
                    const mnt4_Fq2 J = H * E; // J = H * E
                    const mnt4_Fq2 V = X1 * E; // V = X1 * E
                    const mnt4_Fq2 L1 = D - (Y1 + Y1); // L1 = D - 2 * Y1

                    current.X = L1.square() - J - (V+V); // X3 = L1^2 - J - 2*V
                    current.Y = L1 * (V-current.X) - (Y1+Y1) * J; // Y3 = L1 * (V-X3) - 2*Y1 * J
                    current.Z = (Z1+H).square() - T1 - I; // Z3 = (Z1 + H)^2 - T1 - I
                    current.T = current.Z.square(); // T3 = Z3^2

                    ac.c_L1 = L1;
                    ac.c_RZ = current.Z;
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                mnt4_ate_g1_precomp mnt4_ate_precompute_g1(const mnt4_g1& P) {
                    

                    mnt4_g1 Pcopy = P;
                    Pcopy.to_affine_coordinates();

                    mnt4_ate_g1_precomp result;
                    result.PX = Pcopy.X;
                    result.PY = Pcopy.Y;
                    result.PX_twist = Pcopy.X * mnt4_twist;
                               result.PY_twist = Pcopy.Y * mnt4_twist;

                    return result;
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                mnt4_ate_g2_precomp mnt4_ate_precompute_g2(const mnt4_g2& Q) {           
                    

                    mnt4_g2 Qcopy(Q);
                    Qcopy.to_affine_coordinates();

                    mnt4_ate_g2_precomp result;
                    result.QX = Qcopy.X;
                    result.QY = Qcopy.Y;
                    result.QY2 = Qcopy.Y.square();
                    result.QX_over_twist = Qcopy.X * mnt4_twist.inverse();
                    result.QY_over_twist = Qcopy.Y * mnt4_twist.inverse();

                    extended_mnt4_g2_projective R;
                    R.X = Qcopy.X;
                    R.Y = Qcopy.Y;
                    R.Z = mnt4_Fq2::one();
                    R.T = mnt4_Fq2::one();

                    const typename basic_policy<mnt4<ModulusBits, GeneratorBits>> :: number_type &loop_count = basic_policy<mnt4<ModulusBits, GeneratorBits>>::ate_loop_count;
                    bool found_one = false;

                    for (long i = loop_count.max_bits() - 1; i >= 0; --i) {
                        const bool bit = loop_count.test_bit(i);
                        if (!found_one) {
                            /* this skips the MSB itself */
                            found_one |= bit;
                            continue;
                        }

                        mnt4_ate_dbl_coeffs dc;
                        doubling_step_for_flipped_miller_loop(R, dc);
                        result.dbl_coeffs.push_back(dc);
                        if (bit) {
                            mnt4_ate_add_coeffs ac;
                            mixed_addition_step_for_flipped_miller_loop(result.QX, result.QY, result.QY2, R, ac);
                            result.add_coeffs.push_back(ac);
                        }
                    }

                    if (basic_policy<mnt4<ModulusBits, GeneratorBits>>::ate_is_loop_count_neg) {
                        mnt4_Fq2 RZ_inv = R.Z.inverse();
                        mnt4_Fq2 RZ2_inv = RZ_inv.square();
                        mnt4_Fq2 RZ3_inv = RZ2_inv * RZ_inv;
                        mnt4_Fq2 minus_R_affine_X = R.X * RZ2_inv;
                        mnt4_Fq2 minus_R_affine_Y = - R.Y * RZ3_inv;
                        mnt4_Fq2 minus_R_affine_Y2 = minus_R_affine_Y.square();
                        mnt4_ate_add_coeffs ac;
                        mixed_addition_step_for_flipped_miller_loop(minus_R_affine_X, minus_R_affine_Y, minus_R_affine_Y2, R, ac);
                        result.add_coeffs.push_back(ac);
                    }

                    return result;
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_ate_miller_loop(const mnt4_ate_g1_precomp &prec_P,
                                              const mnt4_ate_g2_precomp &prec_Q) {
                    

                    mnt4_Fq2 L1_coeff = mnt4_Fq2(prec_P.PX, mnt4_Fq::zero()) - prec_Q.QX_over_twist;

                    curves::mnt4_gt<ModulusBits, GeneratorBits> f = curves::mnt4_gt<ModulusBits, GeneratorBits>::one();

                    bool found_one = false;
                    size_t dbl_idx = 0;
                    size_t add_idx = 0;

                    const typename basic_policy<mnt4<ModulusBits, GeneratorBits>> :: number_type &loop_count = basic_policy<mnt4<ModulusBits, GeneratorBits>>::ate_loop_count;
                    for (long i = loop_count.max_bits() - 1; i >= 0; --i) {
                        const bool bit = loop_count.test_bit(i);

                        if (!found_one) {
                            /* this skips the MSB itself */
                            found_one |= bit;
                            continue;
                        }

                        /* code below gets executed for all bits (EXCEPT the MSB itself) of
                           mnt4_param_p (skipping leading zeros) in MSB to LSB
                           order */
                        mnt4_ate_dbl_coeffs dc = prec_Q.dbl_coeffs[dbl_idx++];

                        curves::mnt4_gt<ModulusBits, GeneratorBits> g_RR_at_P = curves::mnt4_gt<ModulusBits, GeneratorBits>(- dc.c_4C - dc.c_J * prec_P.PX_twist + dc.c_L,
                                                      dc.c_H * prec_P.PY_twist);
                        f = f.square() * g_RR_at_P;
                        if (bit) {
                            mnt4_ate_add_coeffs ac = prec_Q.add_coeffs[add_idx++];

                            curves::mnt4_gt<ModulusBits, GeneratorBits> g_RQ_at_P = curves::mnt4_gt<ModulusBits, GeneratorBits>(ac.c_RZ * prec_P.PY_twist,
                                                          -(prec_Q.QY_over_twist * ac.c_RZ + L1_coeff * ac.c_L1));
                            f = f * g_RQ_at_P;
                        }
                    }

                    if (basic_policy<mnt4<ModulusBits, GeneratorBits>>::ate_is_loop_count_neg) {
                        mnt4_ate_add_coeffs ac = prec_Q.add_coeffs[add_idx++];
                        curves::mnt4_gt<ModulusBits, GeneratorBits> g_RnegR_at_P = curves::mnt4_gt<ModulusBits, GeneratorBits>(ac.c_RZ * prec_P.PY_twist,
                                                         -(prec_Q.QY_over_twist * ac.c_RZ + L1_coeff * ac.c_L1));
                        f = (f * g_RnegR_at_P).inverse();
                    }

                
                    return f;
                }           

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_ate_double_miller_loop(const mnt4_ate_g1_precomp &prec_P1,
                                                     const mnt4_ate_g2_precomp &prec_Q1,
                                                     const mnt4_ate_g1_precomp &prec_P2,
                                                     const mnt4_ate_g2_precomp &prec_Q2) {
                    

                    mnt4_Fq2 L1_coeff1 = mnt4_Fq2(prec_P1.PX, mnt4_Fq::zero()) - prec_Q1.QX_over_twist;
                    mnt4_Fq2 L1_coeff2 = mnt4_Fq2(prec_P2.PX, mnt4_Fq::zero()) - prec_Q2.QX_over_twist;

                    curves::mnt4_gt<ModulusBits, GeneratorBits> f = curves::mnt4_gt<ModulusBits, GeneratorBits>::one();

                    bool found_one = false;
                    size_t dbl_idx = 0;
                    size_t add_idx = 0;

                    const typename basic_policy<mnt4<ModulusBits, GeneratorBits>> :: number_type &loop_count = basic_policy<mnt4<ModulusBits, GeneratorBits>>::ate_loop_count;

                    for (long i = loop_count.max_bits() - 1; i >= 0; --i) {
                        const bool bit = loop_count.test_bit(i);

                        if (!found_one) {
                            /* this skips the MSB itself */
                            found_one |= bit;
                            continue;
                        }

                        /* code below gets executed for all bits (EXCEPT the MSB itself) of
                           mnt4_param_p (skipping leading zeros) in MSB to LSB
                           order */
                        mnt4_ate_dbl_coeffs dc1 = prec_Q1.dbl_coeffs[dbl_idx];
                        mnt4_ate_dbl_coeffs dc2 = prec_Q2.dbl_coeffs[dbl_idx];
                        ++dbl_idx;

                        curves::mnt4_gt<ModulusBits, GeneratorBits> g_RR_at_P1 = curves::mnt4_gt<ModulusBits, GeneratorBits>(- dc1.c_4C - dc1.c_J * prec_P1.PX_twist + dc1.c_L,
                                                       dc1.c_H * prec_P1.PY_twist);

                        curves::mnt4_gt<ModulusBits, GeneratorBits> g_RR_at_P2 = curves::mnt4_gt<ModulusBits, GeneratorBits>(- dc2.c_4C - dc2.c_J * prec_P2.PX_twist + dc2.c_L,
                                                       dc2.c_H * prec_P2.PY_twist);

                        f = f.square() * g_RR_at_P1 * g_RR_at_P2;

                        if (bit) {
                            mnt4_ate_add_coeffs ac1 = prec_Q1.add_coeffs[add_idx];
                            mnt4_ate_add_coeffs ac2 = prec_Q2.add_coeffs[add_idx];
                            ++add_idx;

                            curves::mnt4_gt<ModulusBits, GeneratorBits> g_RQ_at_P1 = curves::mnt4_gt<ModulusBits, GeneratorBits>(ac1.c_RZ * prec_P1.PY_twist,
                                                           -(prec_Q1.QY_over_twist * ac1.c_RZ + L1_coeff1 * ac1.c_L1));
                            curves::mnt4_gt<ModulusBits, GeneratorBits> g_RQ_at_P2 = curves::mnt4_gt<ModulusBits, GeneratorBits>(ac2.c_RZ * prec_P2.PY_twist,
                                                           -(prec_Q2.QY_over_twist * ac2.c_RZ + L1_coeff2 * ac2.c_L1));

                            f = f * g_RQ_at_P1 * g_RQ_at_P2;
                        }
                    }

                    if (basic_policy<mnt4<ModulusBits, GeneratorBits>>::ate_is_loop_count_neg) {
                        mnt4_ate_add_coeffs ac1 = prec_Q1.add_coeffs[add_idx];
                        mnt4_ate_add_coeffs ac2 = prec_Q2.add_coeffs[add_idx];
                        ++add_idx;
                        curves::mnt4_gt<ModulusBits, GeneratorBits> g_RnegR_at_P1 = curves::mnt4_gt<ModulusBits, GeneratorBits>(ac1.c_RZ * prec_P1.PY_twist,
                                                          -(prec_Q1.QY_over_twist * ac1.c_RZ + L1_coeff1 * ac1.c_L1));
                        curves::mnt4_gt<ModulusBits, GeneratorBits> g_RnegR_at_P2 = curves::mnt4_gt<ModulusBits, GeneratorBits>(ac2.c_RZ * prec_P2.PY_twist,
                                                          -(prec_Q2.QY_over_twist * ac2.c_RZ + L1_coeff2 * ac2.c_L1));

                        f = (f * g_RnegR_at_P1 * g_RnegR_at_P2).inverse();
                    }


                    return f;
                }
                
                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_ate_pairing(const mnt4_g1& P, const mnt4_g2 &Q) {
                    
                    mnt4_ate_g1_precomp prec_P = mnt4_ate_precompute_g1(P);
                    mnt4_ate_g2_precomp prec_Q = mnt4_ate_precompute_g2(Q);
                    curves::mnt4_gt<ModulusBits, GeneratorBits> result = mnt4_ate_miller_loop(prec_P, prec_Q);
                    return result;
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_ate_reduced_pairing(const mnt4_g1 &P, const mnt4_g2 &Q) {
                    
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> f = mnt4_ate_pairing(P, Q);
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> result = mnt4_final_exponentiation(f);
                    return result;
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                mnt4_g1_precomp mnt4_precompute_g1(const mnt4_g1& P) {
                    return mnt4_ate_precompute_g1(P);
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                mnt4_g2_precomp mnt4_precompute_g2(const mnt4_g2& Q) {
                    return mnt4_ate_precompute_g2(Q);
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_miller_loop(const mnt4_g1_precomp &prec_P,
                                          const mnt4_g2_precomp &prec_Q) {
                    return mnt4_ate_miller_loop(prec_P, prec_Q);
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_double_miller_loop(const mnt4_g1_precomp &prec_P1,
                                                 const mnt4_g2_precomp &prec_Q1,
                                                 const mnt4_g1_precomp &prec_P2,
                                                 const mnt4_g2_precomp &prec_Q2) {
                    return mnt4_ate_double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_pairing(const mnt4_g1& P,
                                      const mnt4_g2 &Q) {
                    return mnt4_ate_pairing(P, Q);
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_reduced_pairing(const mnt4_g1 &P,
                                             const mnt4_g2 &Q) {
                    return mnt4_ate_reduced_pairing(P, Q);
                }

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                curves::mnt4_gt<ModulusBits, GeneratorBits> mnt4_affine_reduced_pairing(const mnt4_g1 &P,
                                                    const mnt4_g2 &Q) {
                    const mnt4_affine_ate_g1_precomputation prec_P = mnt4_affine_ate_precompute_g1(P);
                    const mnt4_affine_ate_g2_precomputation prec_Q = mnt4_affine_ate_precompute_g2(Q);
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> f = mnt4_affine_ate_miller_loop(prec_P, prec_Q);
                    const curves::mnt4_gt<ModulusBits, GeneratorBits> result = mnt4_final_exponentiation(f);
                    return result;
                }

            }       // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_MNT4_FUNCTIONS_HPP