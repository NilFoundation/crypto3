//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_BLS12_FUNCTIONS_HPP
#define ALGEBRA_PAIRING_BLS12_FUNCTIONS_HPP

#include <nil/algebra/pairing/detail/bls12/basic_policy.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                class bls12_pairing_functions;

                template<>
                class bls12_pairing_functions<381, CHAR_BIT> : public bls12_basic_policy<381, CHAR_BIT>{
                    using policy_type = bls12_basic_policy<381, CHAR_BIT>;
                public:

                    using Fq = typename policy_type::Fq;
                    using Fq2 = typename policy_type::Fq2;
                    using gt = typename policy_type::gt;
                    using g1 = typename policy_type::g1;
                    using g2 = typename policy_type::g2;

                    struct ate_g1_precomp {
                        Fq PX;
                        Fq PY;

                        bool operator==(const ate_g1_precomp &other) const {
                            return (this->PX == other.PX && this->PY == other.PY);
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

                    struct ate_g2_precomp {
                        Fq2 QX;
                        Fq2 QY;
                        std::vector<ate_ell_coeffs> coeffs;

                        bool operator==(const ate_g2_precomp &other) const {
                            return (this->QX == other.QX && this->QY == other.QY && this->coeffs == other.coeffs);
                        }
                    };

                    /* final exponentiations */

                    gt final_exponentiation_first_chunk(const gt &elt) {

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

                        const gt A =
                            gt(elt.c0, -elt.c1);
                        const gt B = elt.inversed();
                        const gt C = A * B;
                        const gt D = C.Frobenius_map(2);
                        const gt result = D * C;

                        return result;
                    }

                    gt exp_by_z(const gt &elt) {

                        gt result =
                            elt.cyclotomic_exp(basic_policy::final_exponent_z);
                        if (basic_policy::final_exponent_is_z_neg) {
                            result = result.unitary_inverse();
                        }

                        return result;
                    }

                    gt final_exponentiation_last_chunk(const gt &elt) {

                        const gt A = elt.cyclotomic_squared();    // elt^2
                        const gt B = A.unitary_inverse();         // elt^(-2)
                        const gt C = exp_by_z(elt);     // elt^z
                        const gt D = C.cyclotomic_squared();      // elt^(2z)
                        const gt E = B * C;                       // elt^(z-2)
                        const gt F = exp_by_z(E);       // elt^(z^2-2z)
                        const gt G = exp_by_z(F);       // elt^(z^3-2z^2)
                        const gt H = exp_by_z(G);       // elt^(z^4-2z^3)
                        const gt I = H * D;                       // elt^(z^4-2z^3+2z)
                        const gt J = exp_by_z(I);       // elt^(z^5-2z^4+2z^2)
                        const gt K = E.unitary_inverse();         // elt^(-z+2)
                        const gt L = K * J;      // elt^(z^5-2z^4+2z^2) * elt^(-z+2)
                        const gt M = elt * L;    // elt^(z^5-2z^4+2z^2) * elt^(-z+2) * elt
                        const gt N = elt.unitary_inverse();    // elt^(-1)
                        const gt O = F * elt;                  // elt^(z^2-2z) * elt
                        const gt P = O.Frobenius_map(3);    // (elt^(z^2-2z) * elt)^(q^3)
                        const gt Q = I * N;    // elt^(z^4-2z^3+2z) * elt^(-1)
                        const gt R =
                            Q.Frobenius_map(1);                                  // (elt^(z^4-2z^3+2z) * elt^(-1))^q
                        const gt S = C * G;    // elt^(z^3-2z^2) * elt^z
                        const gt T =
                            S.Frobenius_map(2);    // (elt^(z^3-2z^2) * elt^z)^(q^2)
                        const gt U =
                            T * P;    // (elt^(z^2-2z) * elt)^(q^3) * (elt^(z^3-2z^2) * elt^z)^(q^2)
                        const gt V =
                            U * R;    // (elt^(z^2-2z) * elt)^(q^3) * (elt^(z^3-2z^2) * elt^z)^(q^2) * (elt^(z^4-2z^3+2z) *
                                      // elt^(-1))^q
                        const gt W =
                            V * M;    // (elt^(z^2-2z) * elt)^(q^3) * (elt^(z^3-2z^2) * elt^z)^(q^2) * (elt^(z^4-2z^3+2z) *
                                      // elt^(-1))^q * elt^(z^5-2z^4+2z^2) * elt^(-z+2) * elt

                        const gt result = W;

                        return result;
                    }

                    gt final_exponentiation(const gt &elt) {
                        /* OLD naive version:
                            gt result = elt^final_exponent;
                        */
                        gt A = final_exponentiation_first_chunk(elt);
                        gt result = final_exponentiation_last_chunk(A);

                        return result;
                    }

                    /* ate pairing */

                    void doubling_step_for_miller_loop(const Fq two_inv,
                                                       g2 &current,
                                                       ate_ell_coeffs &c) {
                        const Fq2 X = current.X, Y = current.Y, Z = current.Z;

                        const Fq2 A = two_inv * (X * Y);              // A = X1 * Y1 / 2
                        const Fq2 B = Y.squared();                    // B = Y1^2
                        const Fq2 C = Z.squared();                    // C = Z1^2
                        const Fq2 D = C + C + C;                      // D = 3 * C
                        const Fq2 E = twist_coeff_b * D;    // E = twist_b * D
                        const Fq2 F = E + E + E;                      // F = 3 * E
                        const Fq2 G = two_inv * (B + F);              // G = (B+F)/2
                        const Fq2 H =
                            (Y + Z).squared() - (B + C);                                        // H = (Y1+Z1)^2-(B+C)
                        const Fq2 I = E - B;                  // I = E-B
                        const Fq2 J = X.squared();            // J = X1^2
                        const Fq2 E_squared = E.squared();    // E_squared = E^2

                        current.X = A * (B - F);                                          // X3 = A * (B-F)
                        current.Y = G.squared() - (E_squared + E_squared + E_squared);    // Y3 = G^2 - 3*E^2
                        current.Z = B * H;                                                // Z3 = B * H
                        c.ell_0 = I;                                                      // ell_0 = xi * I
                        c.ell_VW = -twist * H;                                  // ell_VW = - H (later: * yP)
                        c.ell_VV = J + J + J;                                             // ell_VV = 3*J (later: * xP)
                    }

                    void mixed_addition_step_for_miller_loop(const g2 base,
                                                             g2 &current,
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

                        current.X = D * J;                     // X3 = D*J
                        current.Y = E * (I - J) - (H * Y1);    // Y3 = E*(I-J)-(H*Y1)
                        current.Z = Z1 * H;                    // Z3 = Z1*H
                        c.ell_0 = E * x2 - D * y2;             // ell_0 = xi * (E * X2 - D * Y2)
                        c.ell_VV = -E;                         // ell_VV = - E (later: * xP)
                        c.ell_VW = twist * D;        // ell_VW = D (later: * yP    )
                    }

                    ate_g1_precomp ate_precompute_g1(const g1 &P) {

                        g1 Pcopy = P;
                        Pcopy.to_affine_coordinates();

                        ate_g1_precomp result;
                        result.PX = Pcopy.X;
                        result.PY = Pcopy.Y;

                        return result;
                    }

                    ate_g2_precomp ate_precompute_g2(const g2 &Q) {

                        g2 Qcopy(Q);
                        Qcopy.to_affine_coordinates();

                        Fq two_inv = (Fq("2").inversed());    // could add to global params if needed

                        ate_g2_precomp result;
                        result.QX = Qcopy.X;
                        result.QY = Qcopy.Y;

                        g2 R;
                        R.X = Qcopy.X;
                        R.Y = Qcopy.Y;
                        R.Z = Fq2::one();

                        const typename basic_policy::number_type &loop_count =
                            basic_policy::ate_loop_count;

                        bool found_one = false;
                        ate_ell_coeffs c;

                        for (long i = loop_count.max_bits(); i >= 0; --i) {
                            const bool bit = loop_count.test_bit(i);
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

                    gt ate_miller_loop(const ate_g1_precomp &prec_P, const ate_g2_precomp &prec_Q) {

                        gt f = gt::one();

                        bool found_one = false;
                        size_t idx = 0;

                        const typename basic_policy::number_type &loop_count =
                            basic_policy::ate_loop_count;

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
                            f = f.mul_by_045(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);

                            if (bit) {
                                c = prec_Q.coeffs[idx++];
                                f = f.mul_by_045(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);
                            }
                        }

                        if (basic_policy::ate_is_loop_count_neg) {
                            f = f.inversed();
                        }

                        return f;
                    }

                    gt ate_double_miller_loop(const ate_g1_precomp &prec_P1, const ate_g2_precomp &prec_Q1,
                                              const ate_g1_precomp &prec_P2, const ate_g2_precomp &prec_Q2) {

                        gt f = gt::one();

                        bool found_one = false;
                        size_t idx = 0;

                        const typename basic_policy::number_type &loop_count =
                            basic_policy::ate_loop_count;

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

                            f = f.mul_by_045(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                            f = f.mul_by_045(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);

                            if (bit) {
                                ate_ell_coeffs c1 = prec_Q1.coeffs[idx];
                                ate_ell_coeffs c2 = prec_Q2.coeffs[idx];
                                ++idx;

                                f = f.mul_by_045(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                                f = f.mul_by_045(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);
                            }
                        }

                        if (basic_policy::ate_is_loop_count_neg) {
                            f = f.inversed();
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

                    /* choice of pairing */

                    g1_precomp precompute_g1(const g1 &P) {
                        return ate_precompute_g1(P);
                    }

                    g2_precomp precompute_g2(const g2 &Q) {
                        return ate_precompute_g2(Q);
                    }

                    gt miller_loop(const g1 _precomp &prec_P,
                                              const g2
                                                  _precomp &prec_Q) {
                        return ate_miller_loop(prec_P, prec_Q);
                    }

                    gt double_miller_loop(const g1 _precomp &prec_P1,
                                                     const g2
                                                         _precomp &prec_Q1,
                                                     const g1
                                                         _precomp &prec_P2,
                                                     const g2
                                                         _precomp &prec_Q2) {
                        return ate_double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
                    }

                    gt pairing(const g1 &P, const g2 &Q) {
                        return ate_pairing(P, Q);
                    }

                    gt reduced_pairing(const g1 &P, const g2 &Q) {
                        return ate_reduced_pairing(P, Q);
                    }
                };
            }    // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_BLS12_FUNCTIONS_HPP
