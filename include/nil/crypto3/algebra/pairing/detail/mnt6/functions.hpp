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

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT6_FUNCTIONS_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT6_FUNCTIONS_HPP

#include <nil/crypto3/algebra/pairing/detail/mnt6/basic_policy.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<std::size_t Version = 298>
                    class mnt6_pairing_functions;

                    template<>
                    class mnt6_pairing_functions<298> : public mnt6_basic_policy<298> {
                        using policy_type = mnt6_basic_policy<298>;

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
                        // but it's better to implement a structure pairing_params with such values

                    private:
                        using g1 = typename g1_type::value_type;
                        using g2 = typename g2_type::value_type;
                        using Fq = typename fq_type::value_type;
                        using Fq3 = typename fqe_type::value_type;
                        using gt = typename fqk_type::value_type;

                    public:
                        struct affine_ate_g1_precomputation {
                            Fq PX;
                            Fq PY;
                            Fq3 PY_twist_squared;
                        };

                        struct affine_ate_coeffs {
                            // TODO: trim (not all of them are needed)
                            Fq3 old_RX;
                            Fq3 old_RY;
                            Fq3 gamma;
                            Fq3 gamma_twist;
                            Fq3 gamma_X;
                        };

                        struct affine_ate_g2_precomputation {
                            Fq3 QX;
                            Fq3 QY;
                            std::vector<affine_ate_coeffs> coeffs;
                        };

                        struct ate_g1_precomp {
                            typedef Fq value_type;
                            typedef Fq3 twist_value_type;

                            value_type PX;
                            value_type PY;
                            twist_value_type PX_twist;
                            twist_value_type PY_twist;

                            bool operator==(const ate_g1_precomp &other) const {
                                return (this->PX == other.PX && this->PY == other.PY &&
                                        this->PX_twist == other.PX_twist && this->PY_twist == other.PY_twist);
                            }
                        };

                        struct ate_dbl_coeffs {
                            typedef Fq3 value_type;

                            value_type c_H;
                            value_type c_4C;
                            value_type c_J;
                            value_type c_L;

                            bool operator==(const ate_dbl_coeffs &other) const {
                                return (this->c_H == other.c_H && this->c_4C == other.c_4C && this->c_J == other.c_J &&
                                        this->c_L == other.c_L);
                            }
                        };

                        struct ate_add_coeffs {
                            typedef Fq3 value_type;

                            value_type c_L1;
                            value_type c_RZ;

                            bool operator==(const ate_add_coeffs &other) const {
                                return (this->c_L1 == other.c_L1 && this->c_RZ == other.c_RZ);
                            }
                        };

                        struct ate_g2_precomp {
                            typedef Fq3 value_type;
                            typedef ate_dbl_coeffs dbl_coeffs_type;
                            typedef ate_add_coeffs add_coeffs_type;

                            value_type QX;
                            value_type QY;
                            value_type QY2;
                            value_type QX_over_twist;
                            value_type QY_over_twist;
                            std::vector<ate_dbl_coeffs> dbl_coeffs;
                            std::vector<ate_add_coeffs> add_coeffs;

                            bool operator==(const ate_g2_precomp &other) const {
                                return (this->QX == other.QX && this->QY == other.QY && this->QY2 == other.QY2 &&
                                        this->QX_over_twist == other.QX_over_twist &&
                                        this->QY_over_twist == other.QY_over_twist &&
                                        this->dbl_coeffs == other.dbl_coeffs && this->add_coeffs == other.add_coeffs);
                            }
                        };

                        typedef ate_g1_precomp g1_precomp;
                        typedef ate_g2_precomp g2_precomp;

                    private:
                        /*************************  FINAL EXPONENTIATIONS  ***********************************/

                        static gt final_exponentiation_last_chunk(const gt &elt, const gt &elt_inv) {
                            const gt elt_q = elt.Frobenius_map(1);
                            gt w1_part = elt_q.cyclotomic_exp(policy_type::final_exponent_last_chunk_w1);
                            gt w0_part;
                            if (policy_type::final_exponent_last_chunk_is_w0_neg) {
                                w0_part = elt_inv.cyclotomic_exp(policy_type::final_exponent_last_chunk_abs_of_w0);
                            } else {
                                w0_part = elt.cyclotomic_exp(policy_type::final_exponent_last_chunk_abs_of_w0);
                            }
                            gt result = w1_part * w0_part;

                            return result;
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
                            gt result = final_exponentiation_last_chunk(elt_to_first_chunk, elt_inv_to_first_chunk);

                            return result;
                        }

                        /* affine ate miller loop */
                        static affine_ate_g1_precomputation affine_ate_precompute_g1(const g1 &P) {

                            g1 Pcopy = P.to_affine();

                            affine_ate_g1_precomputation result;
                            result.PX = Pcopy.X;
                            result.PY = Pcopy.Y;
                            result.PY_twist_squared = Pcopy.Y * g2::twist.squared();

                            return result;
                        }

                        static affine_ate_g2_precomputation affine_ate_precompute_g2(const g2 &Q) {

                            g2 Qcopy = Q.to_affine();

                            affine_ate_g2_precomputation result;
                            result.QX = Qcopy.X;
                            result.QY = Qcopy.Y;

                            Fq3 RX = Qcopy.X;
                            Fq3 RY = Qcopy.Y;

                            bool found_nonzero = false;

                            std::vector<long> NAF = multiprecision::find_wnaf(1, policy_type::ate_loop_count);

                            for (long i = NAF.size() - 1; i >= 0; --i) {
                                if (!found_nonzero) {
                                    /* this skips the MSB itself */
                                    found_nonzero |= (NAF[i] != 0);
                                    continue;
                                }

                                affine_ate_coeffs c;
                                c.old_RX = RX;
                                c.old_RY = RY;
                                Fq3 old_RX_2 = c.old_RX.squared();
                                c.gamma = (old_RX_2 + old_RX_2 + old_RX_2 + g2::twist_coeff_a) *
                                          (c.old_RY + c.old_RY).inversed();
                                c.gamma_twist = c.gamma * g2::twist;

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
                                    c.gamma_twist = c.gamma * g2::twist;

                                    c.gamma_X = c.gamma * result.QX;
                                    result.coeffs.push_back(c);

                                    RX = c.gamma.squared() - (c.old_RX + result.QX);
                                    RY = c.gamma * (c.old_RX - RX) - c.old_RY;
                                }
                            }

                            return result;
                        }

                        static gt affine_ate_miller_loop(const affine_ate_g1_precomputation &prec_P,
                                                         const affine_ate_g2_precomputation &prec_Q) {

                            gt f = gt::one();

                            bool found_nonzero = false;
                            std::size_t idx = 0;

                            std::vector<long> NAF = multiprecision::find_wnaf(1, policy_type::ate_loop_count);

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
                                    gt(prec_P.PY_twist_squared, -prec_P.PX * c.gamma_twist + c.gamma_X - c.old_RY);
                                f = f.squared().mul_by_2345(g_RR_at_P);

                                if (NAF[i] != 0) {
                                    affine_ate_coeffs c = prec_Q.coeffs[idx++];
                                    gt g_RQ_at_P;
                                    if (NAF[i] > 0) {
                                        g_RQ_at_P = gt(prec_P.PY_twist_squared,
                                                       -prec_P.PX * c.gamma_twist + c.gamma_X - prec_Q.QY);
                                    } else {
                                        g_RQ_at_P = gt(prec_P.PY_twist_squared,
                                                       -prec_P.PX * c.gamma_twist + c.gamma_X + prec_Q.QY);
                                    }
                                    f = f.mul_by_2345(g_RQ_at_P);
                                }
                            }

                            return f;
                        }

                    private:
                        /* ate pairing */

                        struct extended_g2_projective {
                            Fq3 X;
                            Fq3 Y;
                            Fq3 Z;
                            Fq3 T;
                        };

                        static void doubling_step_for_flipped_miller_loop(extended_g2_projective &current,
                                                                          ate_dbl_coeffs &dc) {
                            const Fq3 X = current.X, Y = current.Y, Z = current.Z, T = current.T;

                            const Fq3 A = T.squared();                            // A = T1^2
                            const Fq3 B = X.squared();                            // B = X1^2
                            const Fq3 C = Y.squared();                            // C = Y1^2
                            const Fq3 D = C.squared();                            // D = C^2
                            const Fq3 E = (X + C).squared() - B - D;              // E = (X1+C)^2-B-D
                            const Fq3 F = (B + B + B) + g2::twist_coeff_a * A;    // F = 3*B +  a  *A

                            const Fq3 G = F.squared();    // G = F^2

                            current.X = -(E + E + E + E) + G;                       // X3 = -4*E+G
                            current.Y = -Fq(0x08) * D + F * (E + E - current.X);    // Y3 = -8*D+F*(2*E-X3)
                            current.Z = (Y + Z).squared() - C - Z.squared();        // Z3 = (Y1+Z1)^2-C-Z1^2
                            current.T = current.Z.squared();                        // T3 = Z3^2

                            dc.c_H = (current.Z + T).squared() - current.T - A;    // H = (Z3+T1)^2-T3-A
                            dc.c_4C = C + C + C + C;                               // fourC = 4*C
                            dc.c_J = (F + T).squared() - G - A;                    // J = (F+T1)^2-G-A
                            dc.c_L = (F + X).squared() - G - B;                    // L = (F+X1)^2-G-B
                        }

                        static void mixed_addition_step_for_flipped_miller_loop(const Fq3 base_X, const Fq3 base_Y,
                                                                                const Fq3 base_Y_squared,
                                                                                extended_g2_projective &current,
                                                                                ate_add_coeffs &ac) {
                            const Fq3 X1 = current.X, Y1 = current.Y, Z1 = current.Z, T1 = current.T;
                            const Fq3 &x2 = base_X, &y2 = base_Y, &y2_squared = base_Y_squared;

                            const Fq3 B = x2 * T1;    // B = x2 * T1
                            const Fq3 D = ((y2 + Z1).squared() - y2_squared - T1) *
                                          T1;                // D = ((y2 + Z1)^2 - y2squared - T1) * T1
                            const Fq3 H = B - X1;            // H = B - X1
                            const Fq3 I = H.squared();       // I = H^2
                            const Fq3 E = I + I + I + I;     // E = 4*I
                            const Fq3 J = H * E;             // J = H * E
                            const Fq3 V = X1 * E;            // V = X1 * E
                            const Fq3 L1 = D - (Y1 + Y1);    // L1 = D - 2 * Y1

                            current.X = L1.squared() - J - (V + V);              // X3 = L1^2 - J - 2*V
                            current.Y = L1 * (V - current.X) - (Y1 + Y1) * J;    // Y3 = L1 * (V-X3) - 2*Y1 * J
                            current.Z = (Z1 + H).squared() - T1 - I;             // Z3 = (Z1 + H)^2 - T1 - I
                            current.T = current.Z.squared();                     // T3 = Z3^2

                            ac.c_L1 = L1;
                            ac.c_RZ = current.Z;
                        }

                        static ate_g1_precomp ate_precompute_g1(const g1 &P) {

                            g1 Pcopy = P.to_affine();

                            ate_g1_precomp result;
                            result.PX = Pcopy.X;
                            result.PY = Pcopy.Y;
                            result.PX_twist = Pcopy.X * g2::twist;
                            result.PY_twist = Pcopy.Y * g2::twist;

                            return result;
                        }

                        static ate_g2_precomp ate_precompute_g2(const g2 &Q) {

                            g2 Qcopy = Q.to_affine();

                            Fq3 twist_inv = g2::twist.inversed();    // could add to global params if needed

                            ate_g2_precomp result;
                            result.QX = Qcopy.X;
                            result.QY = Qcopy.Y;
                            result.QY2 = Qcopy.Y.squared();
                            result.QX_over_twist = Qcopy.X * twist_inv;
                            result.QY_over_twist = Qcopy.Y * twist_inv;

                            extended_g2_projective R;
                            R.X = Qcopy.X;
                            R.Y = Qcopy.Y;
                            R.Z = Fq3::one();
                            R.T = Fq3::one();
                            bool found_one = false;

                            for (long i = policy_type::number_type_max_bits - 1; i >= 0; --i) {
                                const bool bit = multiprecision::bit_test(policy_type::ate_loop_count, i);

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
                                    mixed_addition_step_for_flipped_miller_loop(result.QX, result.QY, result.QY2, R,
                                                                                ac);
                                    result.add_coeffs.push_back(ac);
                                }
                            }

                            if (ate_is_loop_count_neg) {
                                Fq3 RZ_inv = R.Z.inversed();
                                Fq3 RZ2_inv = RZ_inv.squared();
                                Fq3 RZ3_inv = RZ2_inv * RZ_inv;
                                Fq3 minus_R_affine_X = R.X * RZ2_inv;
                                Fq3 minus_R_affine_Y = -R.Y * RZ3_inv;
                                Fq3 minus_R_affine_Y2 = minus_R_affine_Y.squared();
                                ate_add_coeffs ac;
                                mixed_addition_step_for_flipped_miller_loop(minus_R_affine_X, minus_R_affine_Y,
                                                                            minus_R_affine_Y2, R, ac);
                                result.add_coeffs.push_back(ac);
                            }

                            return result;
                        }

                        static gt ate_miller_loop(const ate_g1_precomp &prec_P, const ate_g2_precomp &prec_Q) {

                            Fq3 L1_coeff = Fq3(prec_P.PX, Fq::zero(), Fq::zero()) - prec_Q.QX_over_twist;

                            gt f = gt::one();

                            bool found_one = false;
                            std::size_t dbl_idx = 0;
                            std::size_t add_idx = 0;

                            for (long i = policy_type::number_type_max_bits - 1; i >= 0; --i) {
                                const bool bit = nil::crypto3::multiprecision::bit_test(policy_type::ate_loop_count, i);

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
                                    gt(-dc.c_4C - dc.c_J * prec_P.PX_twist + dc.c_L, dc.c_H * prec_P.PY_twist);
                                f = f.squared() * g_RR_at_P;

                                if (bit) {
                                    ate_add_coeffs ac = prec_Q.add_coeffs[add_idx++];
                                    gt g_RQ_at_P = gt(ac.c_RZ * prec_P.PY_twist,
                                                      -(prec_Q.QY_over_twist * ac.c_RZ + L1_coeff * ac.c_L1));
                                    f = f * g_RQ_at_P;
                                }
                            }

                            if (ate_is_loop_count_neg) {
                                ate_add_coeffs ac = prec_Q.add_coeffs[add_idx++];
                                gt g_RnegR_at_P = gt(ac.c_RZ * prec_P.PY_twist,
                                                     -(prec_Q.QY_over_twist * ac.c_RZ + L1_coeff * ac.c_L1));
                                f = (f * g_RnegR_at_P).inversed();
                            }

                            return f;
                        }

                        static gt ate_double_miller_loop(const ate_g1_precomp &prec_P1, const ate_g2_precomp &prec_Q1,
                                                         const ate_g1_precomp &prec_P2, const ate_g2_precomp &prec_Q2) {

                            Fq3 L1_coeff1 = Fq3(prec_P1.PX, Fq::zero(), Fq::zero()) - prec_Q1.QX_over_twist;
                            Fq3 L1_coeff2 = Fq3(prec_P2.PX, Fq::zero(), Fq::zero()) - prec_Q2.QX_over_twist;

                            gt f = gt::one();

                            bool found_one = false;
                            std::size_t dbl_idx = 0;
                            std::size_t add_idx = 0;

                            for (long i = policy_type::number_type_max_bits - 1; i >= 0; --i) {
                                const bool bit = multiprecision::bit_test(policy_type::ate_loop_count, i);

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
                                    gt(-dc1.c_4C - dc1.c_J * prec_P1.PX_twist + dc1.c_L, dc1.c_H * prec_P1.PY_twist);

                                gt g_RR_at_P2 =
                                    gt(-dc2.c_4C - dc2.c_J * prec_P2.PX_twist + dc2.c_L, dc2.c_H * prec_P2.PY_twist);

                                f = f.squared() * g_RR_at_P1 * g_RR_at_P2;

                                if (bit) {
                                    ate_add_coeffs ac1 = prec_Q1.add_coeffs[add_idx];
                                    ate_add_coeffs ac2 = prec_Q2.add_coeffs[add_idx];
                                    ++add_idx;

                                    gt g_RQ_at_P1 = gt(ac1.c_RZ * prec_P1.PY_twist,
                                                       -(prec_Q1.QY_over_twist * ac1.c_RZ + L1_coeff1 * ac1.c_L1));
                                    gt g_RQ_at_P2 = gt(ac2.c_RZ * prec_P2.PY_twist,
                                                       -(prec_Q2.QY_over_twist * ac2.c_RZ + L1_coeff2 * ac2.c_L1));

                                    f = f * g_RQ_at_P1 * g_RQ_at_P2;
                                }
                            }

                            if (ate_is_loop_count_neg) {
                                ate_add_coeffs ac1 = prec_Q1.add_coeffs[add_idx];
                                ate_add_coeffs ac2 = prec_Q2.add_coeffs[add_idx];
                                ++add_idx;
                                gt g_RnegR_at_P1 = gt(ac1.c_RZ * prec_P1.PY_twist,
                                                      -(prec_Q1.QY_over_twist * ac1.c_RZ + L1_coeff1 * ac1.c_L1));
                                gt g_RnegR_at_P2 = gt(ac2.c_RZ * prec_P2.PY_twist,
                                                      -(prec_Q2.QY_over_twist * ac2.c_RZ + L1_coeff2 * ac2.c_L1));

                                f = (f * g_RnegR_at_P1 * g_RnegR_at_P2).inversed();
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

                        static gt double_miller_loop(const g1_precomp &prec_P1, const g2_precomp &prec_Q1,
                                                     const g1_precomp &prec_P2, const g2_precomp &prec_Q2) {
                            return ate_double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
                        }

                        static gt pair(const g1 &P, const g2 &Q) {
                            return ate_pair(P, Q);
                        }

                        static gt pair_reduced(const g1 &P, const g2 &Q) {
                            return ate_pair_reduced(P, Q);
                        }

                        static gt affine_pair_reduced(const g1 &P, const g2 &Q) {
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
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_MNT6_FUNCTIONS_HPP
