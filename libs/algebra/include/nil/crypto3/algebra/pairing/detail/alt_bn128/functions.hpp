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

#ifndef CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_FUNCTIONS_HPP
#define CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_FUNCTIONS_HPP

#include <nil/crypto3/algebra/pairing/detail/alt_bn128/basic_policy.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<std::size_t Version = 254>
                    class alt_bn128_pairing_functions;

                    template<>
                    class alt_bn128_pairing_functions<254> : public alt_bn128_basic_policy<254> {
                        using policy_type = alt_bn128_basic_policy<254>;

                    public:
                        using fp_type = typename policy_type::fp_type;
                        using fq_type = typename policy_type::fq_type;
                        using fqe_type = typename policy_type::fqe_type;
                        using fqk_type = typename policy_type::fqk_type;

                        using g1_type = curves::detail::alt_bn128_g1<254>;
                        using g2_type = curves::detail::alt_bn128_g2<254>;
                        using gt_type = typename policy_type::gt_type;

                        constexpr static const typename policy_type::integral_type ate_loop_count =
                            policy_type::ate_loop_count;

                        constexpr static const typename g2_type::underlying_field_type::value_type twist =
                            g2_type::value_type::twist;
                        // but it's better to implement a structure pairing_params with such values

                    private:
                        using g1 = typename g1_type::value_type;
                        using g2 = typename g2_type::value_type;
                        using Fq = typename fq_type::value_type;
                        using Fq2 = typename fqe_type::value_type;
                        using gt = typename fqk_type::value_type;

                    public:
                        struct ate_g1_precomputed_type {
                            Fq PX;
                            Fq PY;

                            bool operator==(const ate_g1_precomputed_type &other) const {
                                return (this->PX == other.PX && this->PY == other.PY);
                            }

                            friend std::ostream& operator<<(std::ostream &os, ate_g1_precomputed_type const& p) {
                                os << "\"PX\":" << p.PX << "," << std::endl;
                                os << "\"PY\":" << p.PY << std::endl;
                                return os;
                            }
                        };

                        struct ate_ell_coeffs {
                            Fq2 ell_0;
                            Fq2 ell_VW;
                            Fq2 ell_VV;

                            bool operator==(const ate_ell_coeffs &other) const {
                                return (this->ell_0 == other.ell_0 && this->ell_VW == other.ell_VW &&
                                        this->ell_VV == other.ell_VV);
                            }
                        };

                        struct ate_g2_precomputed_type {
                            Fq2 QX;
                            Fq2 QY;
                            std::vector<ate_ell_coeffs> coeffs;

                            bool operator==(const ate_g2_precomputed_type &other) const {
                                return (this->QX == other.QX && this->QY == other.QY && this->coeffs == other.coeffs);
                            }

                            friend std::ostream& operator<<(std::ostream &os, ate_g2_precomputed_type const& p) {
                                os << "\"QX\":" << p.QX << "," << std::endl;
                                os << "\"QY\":" << p.QY << "," << std::endl;
                                os << "\"coeffs\": [" << std::endl;
                                for(auto c = p.coeffs.begin(); c != p.coeffs.end();) {
                                    os << "{";
                                    os << "\"ell_0\": " << c->ell_0 << "," << std::endl;
                                    os << "\"ell_VW\": " << c->ell_VW << "," << std::endl;
                                    os << "\"ell_VV\": " << c->ell_VV << std::endl;
                                    os << "}";
                                    ++c;

                                    if (c!=p.coeffs.end()) {
                                        os << "," << std::endl;
                                    }
                                }
                                os << "]" << std::endl;
                                return os;
                            }
                        };

                    private:
                        /*************************  FINAL EXPONENTIATIONS  ***********************************/

                        static gt final_exponentiation_first_chunk(const gt &elt) {

                            /*
                              Computes result = elt^((q^6-1)*(q^2+1)).
                              Follows, e.g., Beuchat et al page 9, by computing result as follows:
                                 elt^((q^6-1)*(q^2+1)) = (conj(elt) * elt^(-1))^(q^2+1)
                              More precisely:
                              A = conj(elt)
                              B = elt.inversed()
                              C = A * B
                              D = C.Frobenius_map(2)
                              result = D * C
                            */

                            const gt A = gt(elt.c0, -elt.c1);
                            const gt B = elt.inversed();
                            const gt C = A * B;
                            const gt D = C.Frobenius_map(2);
                            const gt result = D * C;

                            return result;
                        }

                        static gt exp_by_neg_z(const gt &elt) {

                            gt result = elt.cyclotomic_exp(policy_type::final_exponent_z);

                            if (!policy_type::final_exponent_is_z_neg) {
                                result = result.unitary_inversed();
                            }

                            return result;
                        }

                        static gt final_exponentiation_last_chunk(const gt &elt) {

                            /*
                              Follows Laura Fuentes-Castaneda et al. "Faster hashing to g2"
                              by computing:

                              result = elt^(q^3 * (12*z^3 + 6z^2 + 4z - 1) +
                                            q^2 * (12*z^3 + 6z^2 + 6z) +
                                            q   * (12*z^3 + 6z^2 + 4z) +
                                            1   * (12*z^3 + 12z^2 + 6z + 1))
                              which equals

                              result = elt^( 2z * ( 6z^2 + 3z + 1 ) * (q^4 - q^2 + 1)/r ).

                              Using the following addition chain:

                              A = exp_by_neg_z(elt)  // = elt^(-z)
                              B = A^2                // = elt^(-2*z)
                              C = B^2                // = elt^(-4*z)
                              D = C * B              // = elt^(-6*z)
                              E = exp_by_neg_z(D)    // = elt^(6*z^2)
                              F = E^2                // = elt^(12*z^2)
                              G = epx_by_neg_z(F)    // = elt^(-12*z^3)
                              H = conj(D)            // = elt^(6*z)
                              I = conj(G)            // = elt^(12*z^3)
                              J = I * E              // = elt^(12*z^3 + 6*z^2)
                              K = J * H              // = elt^(12*z^3 + 6*z^2 + 6*z)
                              L = K * B              // = elt^(12*z^3 + 6*z^2 + 4*z)
                              M = K * E              // = elt^(12*z^3 + 12*z^2 + 6*z)
                              N = M * elt            // = elt^(12*z^3 + 12*z^2 + 6*z + 1)
                              O = L.Frobenius_map(1) // = elt^(q*(12*z^3 + 6*z^2 + 4*z))
                              P = O * N              // = elt^(q*(12*z^3 + 6*z^2 + 4*z) * (12*z^3 + 12*z^2 + 6*z + 1))
                              Q = K.Frobenius_map(2) // = elt^(q^2 * (12*z^3 + 6*z^2 + 6*z))
                              R = Q * P              // = elt^(q^2 * (12*z^3 + 6*z^2 + 6*z) + q*(12*z^3 + 6*z^2 + 4*z) *
                              (12*z^3
                              + 12*z^2 + 6*z + 1)) S = conj(elt)          // = elt^(-1) T = S * L              // =
                              elt^(12*z^3
                              + 6*z^2 + 4*z - 1) U = T.Frobenius_map(3) // = elt^(q^3(12*z^3 + 6*z^2 + 4*z - 1)) V = U *
                              R // = elt^(q^3(12*z^3 + 6*z^2 + 4*z - 1) + q^2 * (12*z^3 + 6*z^2 + 6*z) + q*(12*z^3 +
                              6*z^2 + 4*z) * (12*z^3 + 12*z^2 + 6*z + 1)) result = V

                            */

                            const gt A = exp_by_neg_z(elt);
                            const gt B = A.cyclotomic_squared();
                            const gt C = B.cyclotomic_squared();
                            const gt D = C * B;
                            const gt E = exp_by_neg_z(D);
                            const gt F = E.cyclotomic_squared();
                            const gt G = exp_by_neg_z(F);
                            const gt H = D.unitary_inversed();
                            const gt I = G.unitary_inversed();
                            const gt J = I * E;
                            const gt K = J * H;
                            const gt L = K * B;
                            const gt M = K * E;
                            const gt N = M * elt;
                            const gt O = L.Frobenius_map(1);
                            const gt P = O * N;
                            const gt Q = K.Frobenius_map(2);
                            const gt R = Q * P;
                            const gt S = elt.unitary_inversed();
                            const gt T = S * L;
                            const gt U = T.Frobenius_map(3);
                            const gt V = U * R;

                            const gt result = V;

                            return result;
                        }

                    public:
                        static gt final_exponentiation(const gt &elt) {
                            /* OLD naive version:
                                gt result = elt^final_exponent;
                            */
                            gt A = final_exponentiation_first_chunk(elt);
                            gt result = final_exponentiation_last_chunk(A);

                            return result;
                        }

                    private:
                        /* ate pairing */

                        static void doubling_step_for_flipped_miller_loop(const Fq two_inv, g2 &current,
                                                                          ate_ell_coeffs &c) {

                            const Fq2 X = current.X, Y = current.Y, Z = current.Z;

                            const Fq2 A = two_inv * (X * Y);              // A = X1 * Y1 / 2
                            const Fq2 B = Y.squared();                    // B = Y1^2
                            const Fq2 C = Z.squared();                    // C = Z1^2
                            const Fq2 D = C + C + C;                      // D = 3 * C
                            const Fq2 E = twist_coeff_b * D;              // E = twist_b * D
                            const Fq2 F = E + E + E;                      // F = 3 * E
                            const Fq2 G = two_inv * (B + F);              // G = (B+F)/2
                            const Fq2 H = (Y + Z).squared() - (B + C);    // H = (Y1+Z1)^2-(B+C)
                            const Fq2 I = E - B;                          // I = E-B
                            const Fq2 J = X.squared();                    // J = X1^2
                            const Fq2 E_squared = E.squared();            // E_squared = E^2

                            current.X = A * (B - F);                                          // X3 = A * (B-F)
                            current.Y = G.squared() - (E_squared + E_squared + E_squared);    // Y3 = G^2 - 3*E^2
                            current.Z = B * H;                                                // Z3 = B * H
                            c.ell_0 = twist * I;                                              // ell_0 = xi * I
                            c.ell_VW = -H;           // ell_VW = - H (later: * yP)
                            c.ell_VV = J + J + J;    // ell_VV = 3*J (later: * xP)
                        }

                        static void mixed_addition_step_for_flipped_miller_loop(const g2 base, g2 &current,
                                                                                ate_ell_coeffs &c) {

                            const Fq2 X1 = current.X, Y1 = current.Y, Z1 = current.Z;
                            const Fq2 &x2 = base.X, &y2 = base.Y;

                            const Fq2 D = X1 - x2 * Z1;            // D = X1 - X2*Z1
                            const Fq2 E = Y1 - y2 * Z1;            // E = Y1 - Y2*Z1
                            const Fq2 F = D.squared();             // F = D^2
                            const Fq2 G = E.squared();             // G = E^2
                            const Fq2 H = D * F;                   // H = D*F
                            const Fq2 I = X1 * F;                  // I = X1 * F
                            const Fq2 J = H + Z1 * G - (I + I);    // J = H + Z1*G - (I+I)

                            current.X = D * J;                      // X3 = D*J
                            current.Y = E * (I - J) - (H * Y1);     // Y3 = E*(I-J)-(H*Y1)
                            current.Z = Z1 * H;                     // Z3 = Z1*H
                            c.ell_0 = twist * (E * x2 - D * y2);    // ell_0 = xi * (E * X2 - D * Y2)
                            c.ell_VV = -E;                          // ell_VV = - E (later: * xP)
                            c.ell_VW = D;                           // ell_VW = D (later: * yP    )
                        }

                        static ate_g1_precomputed_type ate_precompute_g1(const g1 &P) {

                            g1 Pcopy = P.to_affine();

                            if (P.is_zero()) {
                                Pcopy.X = g1_type::field_type::value_type::zero();
                                Pcopy.Y = g1_type::field_type::value_type::zero();
                            }

                            ate_g1_precomputed_type result;
                            result.PX = Pcopy.X;
                            result.PY = Pcopy.Y;

                            return result;
                        }

                        static ate_g2_precomputed_type ate_precompute_g2(const g2 &Q) {

                            g2 Qcopy(Q).to_affine();

                            Fq two_inv = Fq(0x02).inversed();    // could add to global params if needed

                            ate_g2_precomputed_type result;
                            result.QX = Qcopy.X;
                            result.QY = Qcopy.Y;

                            g2 R;
                            R.X = Qcopy.X;
                            R.Y = Qcopy.Y;
                            R.Z = Fq2::one();

                            const typename policy_type::integral_type &loop_count = policy_type::ate_loop_count;

                            bool found_one = false;
                            ate_ell_coeffs c;

                            for (long i = loop_count.max_bits(); i >= 0; --i) {
                                const bool bit = loop_count.test_bit(i);
                                if (!found_one) {
                                    /* this skips the MSB itself */
                                    found_one |= bit;
                                    continue;
                                }

                                doubling_step_for_flipped_miller_loop(two_inv, R, c);
                                result.coeffs.push_back(c);

                                if (bit) {
                                    mixed_addition_step_for_flipped_miller_loop(Qcopy, R, c);
                                    result.coeffs.push_back(c);
                                }
                            }

                            g2 Q1 = Qcopy.mul_by_q();
                            assert(Q1.Z == Fq2::one());
                            g2 Q2 = Q1.mul_by_q();
                            assert(Q2.Z == Fq2::one());

                            if (policy_type::ate_is_loop_count_neg) {
                                R.Y = -R.Y;
                            }
                            Q2.Y = -Q2.Y;

                            mixed_addition_step_for_flipped_miller_loop(Q1, R, c);
                            result.coeffs.push_back(c);

                            mixed_addition_step_for_flipped_miller_loop(Q2, R, c);
                            result.coeffs.push_back(c);

                            return result;
                        }

                        static gt ate_miller_loop(const ate_g1_precomputed_type &prec_P,
                                                  const ate_g2_precomputed_type &prec_Q) {

                            gt f = gt::one();

                            bool found_one = false;
                            std::size_t idx = 0;

                            const typename policy_type::integral_type &loop_count = policy_type::ate_loop_count;

                            ate_ell_coeffs c;

                            for (long i = loop_count.max_bits(); i >= 0; --i) {
                                const bool bit = loop_count.test_bit(i);
                                if (!found_one) {
                                    /* this skips the MSB itself */
                                    found_one |= bit;
                                    continue;
                                }

                                /* code below gets executed for all bits (EXCEPT the MSB itself) of
                                   param_p (skipping leading zeros) in MSB to LSB
                                   order */

                                c = prec_Q.coeffs[idx++];
                                f = f.squared();
                                f = f.mul_by_024(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);

                                if (bit) {
                                    c = prec_Q.coeffs[idx++];
                                    f = f.mul_by_024(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);
                                }
                            }

                            if (policy_type::ate_is_loop_count_neg) {
                                f = f.inversed();
                            }

                            c = prec_Q.coeffs[idx++];
                            f = f.mul_by_024(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);

                            c = prec_Q.coeffs[idx++];
                            f = f.mul_by_024(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);

                            return f;
                        }

                        static gt ate_double_miller_loop(const ate_g1_precomputed_type &prec_P1,
                                                         const ate_g2_precomputed_type &prec_Q1,
                                                         const ate_g1_precomputed_type &prec_P2,
                                                         const ate_g2_precomputed_type &prec_Q2) {

                            gt f = gt::one();

                            bool found_one = false;
                            std::size_t idx = 0;

                            const typename policy_type::integral_type &loop_count = policy_type::ate_loop_count;

                            for (long i = loop_count.max_bits(); i >= 0; --i) {
                                const bool bit = loop_count.test_bit(i);
                                if (!found_one) {
                                    /* this skips the MSB itself */
                                    found_one |= bit;
                                    continue;
                                }

                                /* code below gets executed for all bits (EXCEPT the MSB itself) of
                                   param_p (skipping leading zeros) in MSB to LSB
                                   order */

                                ate_ell_coeffs c1 = prec_Q1.coeffs[idx];
                                ate_ell_coeffs c2 = prec_Q2.coeffs[idx];
                                ++idx;

                                f = f.squared();

                                f = f.mul_by_024(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                                f = f.mul_by_024(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);

                                if (bit) {
                                    ate_ell_coeffs c1 = prec_Q1.coeffs[idx];
                                    ate_ell_coeffs c2 = prec_Q2.coeffs[idx];
                                    ++idx;

                                    f = f.mul_by_024(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                                    f = f.mul_by_024(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);
                                }
                            }

                            if (policy_type::ate_is_loop_count_neg) {
                                f = f.inversed();
                            }

                            ate_ell_coeffs c1 = prec_Q1.coeffs[idx];
                            ate_ell_coeffs c2 = prec_Q2.coeffs[idx];
                            ++idx;
                            f = f.mul_by_024(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                            f = f.mul_by_024(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);

                            c1 = prec_Q1.coeffs[idx];
                            c2 = prec_Q2.coeffs[idx];
                            ++idx;
                            f = f.mul_by_024(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                            f = f.mul_by_024(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);

                            return f;
                        }

                        static gt ate_pair(const g1 &P, const g2 &Q) {
                            ate_g1_precomputed_type prec_P = ate_precompute_g1(P);
                            ate_g2_precomputed_type prec_Q = ate_precompute_g2(Q);
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
                        static g1_precomputed_type precompute_g1(const g1 &P) {
                            return ate_precompute_g1(P);
                        }

                        static g2_precomputed_type precompute_g2(const g2 &Q) {
                            return ate_precompute_g2(Q);
                        }

                        static gt miller_loop(const g1_precomputed_type &prec_P, const g2_precomputed_type &prec_Q) {
                            return ate_miller_loop(prec_P, prec_Q);
                        }

                        static gt double_miller_loop(const g1_precomputed_type &prec_P1,
                                                     const g2_precomputed_type &prec_Q1,
                                                     const g1_precomputed_type &prec_P2,
                                                     const g2_precomputed_type &prec_Q2) {
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
#endif    // CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_FUNCTIONS_HPP
