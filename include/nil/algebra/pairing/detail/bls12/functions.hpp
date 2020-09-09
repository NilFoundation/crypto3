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

#include <nil/algebra/curves/bls12.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                using bls12_Fq = curves::bls12_g1<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                using bls12_Fq2 = curves::bls12_g2<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                struct bls12_381_ate_g1_precomp {
                    bls12_Fq<ModulusBits, GeneratorBits> PX;
                    bls12_Fq<ModulusBits, GeneratorBits> PY;

                    bool operator==(const bls12_381_ate_g1_precomp &other) const {
                        return (this->PX == other.PX &&
                                this->PY == other.PY);
                    }
                };

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                struct bls12_381_ate_ell_coeffs {
                    bls12_Fq2<ModulusBits, GeneratorBits> ell_0;
                    bls12_Fq2<ModulusBits, GeneratorBits> ell_VW;
                    bls12_Fq2<ModulusBits, GeneratorBits> ell_VV;

                    bool operator==(const bls12_381_ate_ell_coeffs &other) const {
                        return (this->ell_0 == other.ell_0 &&
                                this->ell_VW == other.ell_VW &&
                                this->ell_VV == other.ell_VV);
                    }
                };

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                struct bls12_381_ate_g2_precomp {
                    bls12_Fq2<ModulusBits, GeneratorBits> QX;
                    bls12_Fq2<ModulusBits, GeneratorBits> QY;
                    std::vector<bls12_381_ate_ell_coeffs> coeffs;

                    bool operator==(const bls12_381_ate_g2_precomp &other) const {
                        return (this->QX == other.QX &&
                                this->QY == other.QY &&
                                this->coeffs == other.coeffs);
                    }
                };

                /* final exponentiations */

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_final_exponentiation_first_chunk(const bls12_gt<ModulusBits, GeneratorBits> &elt) {

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

                    const bls12_gt<ModulusBits, GeneratorBits> A = bls12_gt<ModulusBits, GeneratorBits>(elt.c0,-elt.c1);
                    const bls12_gt<ModulusBits, GeneratorBits> B = elt.inversed();
                    const bls12_gt<ModulusBits, GeneratorBits> C = A * B;
                    const bls12_gt<ModulusBits, GeneratorBits> D = C.Frobenius_map(2);
                    const bls12_gt<ModulusBits, GeneratorBits> result = D * C;


                    return result;
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_exp_by_z(const bls12_gt<ModulusBits, GeneratorBits> &elt) {

                    bls12_gt<ModulusBits, GeneratorBits> result = elt.cyclotomic_exp(basic_policy<bls12<ModulusBits, GeneratorBits>>::final_exponent_z);
                    if (basic_policy<bls12<ModulusBits, GeneratorBits>>::final_exponent_is_z_neg) {
                        result = result.unitary_inverse();
                    }


                    return result;
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_final_exponentiation_last_chunk(const bls12_gt<ModulusBits, GeneratorBits> &elt) {

                    const bls12_gt<ModulusBits, GeneratorBits> A = elt.cyclotomic_squared();   // elt^2
                    const bls12_gt<ModulusBits, GeneratorBits> B = A.unitary_inverse();        // elt^(-2)
                    const bls12_gt<ModulusBits, GeneratorBits> C = bls12_381_exp_by_z(elt);    // elt^z
                    const bls12_gt<ModulusBits, GeneratorBits> D = C.cyclotomic_squared();     // elt^(2z)
                    const bls12_gt<ModulusBits, GeneratorBits> E = B * C;                      // elt^(z-2)
                    const bls12_gt<ModulusBits, GeneratorBits> F = bls12_381_exp_by_z(E);      // elt^(z^2-2z)
                    const bls12_gt<ModulusBits, GeneratorBits> G = bls12_381_exp_by_z(F);      // elt^(z^3-2z^2)
                    const bls12_gt<ModulusBits, GeneratorBits> H = bls12_381_exp_by_z(G);      // elt^(z^4-2z^3)
                    const bls12_gt<ModulusBits, GeneratorBits> I = H * D;                      // elt^(z^4-2z^3+2z)
                    const bls12_gt<ModulusBits, GeneratorBits> J = bls12_381_exp_by_z(I);      // elt^(z^5-2z^4+2z^2)
                    const bls12_gt<ModulusBits, GeneratorBits> K = E.unitary_inverse();        // elt^(-z+2)
                    const bls12_gt<ModulusBits, GeneratorBits> L = K * J;                      // elt^(z^5-2z^4+2z^2) * elt^(-z+2)
                    const bls12_gt<ModulusBits, GeneratorBits> M = elt * L;                    // elt^(z^5-2z^4+2z^2) * elt^(-z+2) * elt
                    const bls12_gt<ModulusBits, GeneratorBits> N = elt.unitary_inverse();      // elt^(-1)
                    const bls12_gt<ModulusBits, GeneratorBits> O = F * elt;                    // elt^(z^2-2z) * elt
                    const bls12_gt<ModulusBits, GeneratorBits> P = O.Frobenius_map(3);         // (elt^(z^2-2z) * elt)^(q^3)
                    const bls12_gt<ModulusBits, GeneratorBits> Q = I * N;                      // elt^(z^4-2z^3+2z) * elt^(-1)
                    const bls12_gt<ModulusBits, GeneratorBits> R = Q.Frobenius_map(1);         // (elt^(z^4-2z^3+2z) * elt^(-1))^q
                    const bls12_gt<ModulusBits, GeneratorBits> S = C * G;                      // elt^(z^3-2z^2) * elt^z
                    const bls12_gt<ModulusBits, GeneratorBits> T = S.Frobenius_map(2);         // (elt^(z^3-2z^2) * elt^z)^(q^2)
                    const bls12_gt<ModulusBits, GeneratorBits> U = T * P;                      // (elt^(z^2-2z) * elt)^(q^3) * (elt^(z^3-2z^2) * elt^z)^(q^2)
                    const bls12_gt<ModulusBits, GeneratorBits> V = U * R;                      // (elt^(z^2-2z) * elt)^(q^3) * (elt^(z^3-2z^2) * elt^z)^(q^2) * (elt^(z^4-2z^3+2z) * elt^(-1))^q
                    const bls12_gt<ModulusBits, GeneratorBits> W = V * M;                      // (elt^(z^2-2z) * elt)^(q^3) * (elt^(z^3-2z^2) * elt^z)^(q^2) * (elt^(z^4-2z^3+2z) * elt^(-1))^q * elt^(z^5-2z^4+2z^2) * elt^(-z+2) * elt

                    const bls12_gt<ModulusBits, GeneratorBits> result = W;


                    return result;
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_final_exponentiation(const bls12_gt<ModulusBits, GeneratorBits> &elt) {
                    /* OLD naive version:
                        bls12_gt<ModulusBits, GeneratorBits> result = elt^bls12_381_final_exponent;
                    */
                    bls12_gt<ModulusBits, GeneratorBits> A = bls12_381_final_exponentiation_first_chunk(elt);
                    bls12_gt<ModulusBits, GeneratorBits> result = bls12_381_final_exponentiation_last_chunk(A);

                    return result;
                }

                /* ate pairing */

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                void doubling_step_for_miller_loop(const bls12_381_Fq two_inv,
                                                           bls12_g2<ModulusBits, GeneratorBits> &current,
                                                           bls12_381_ate_ell_coeffs &c) {
                    const bls12_Fq2<ModulusBits, GeneratorBits> X = current.X, Y = current.Y, Z = current.Z;

                    const bls12_Fq2<ModulusBits, GeneratorBits> A = two_inv * (X * Y);                     // A = X1 * Y1 / 2
                    const bls12_Fq2<ModulusBits, GeneratorBits> B = Y.squared();                           // B = Y1^2
                    const bls12_Fq2<ModulusBits, GeneratorBits> C = Z.squared();                           // C = Z1^2
                    const bls12_Fq2<ModulusBits, GeneratorBits> D = C+C+C;                                 // D = 3 * C
                    const bls12_Fq2<ModulusBits, GeneratorBits> E = bls12_381_twist_coeff_b * D;           // E = twist_b * D
                    const bls12_Fq2<ModulusBits, GeneratorBits> F = E+E+E;                                 // F = 3 * E
                    const bls12_Fq2<ModulusBits, GeneratorBits> G = two_inv * (B+F);                       // G = (B+F)/2
                    const bls12_Fq2<ModulusBits, GeneratorBits> H = (Y+Z).squared() - (B+C);               // H = (Y1+Z1)^2-(B+C)
                    const bls12_Fq2<ModulusBits, GeneratorBits> I = E-B;                                   // I = E-B
                    const bls12_Fq2<ModulusBits, GeneratorBits> J = X.squared();                           // J = X1^2
                    const bls12_Fq2<ModulusBits, GeneratorBits> E_squared = E.squared();                   // E_squared = E^2

                    current.X = A * (B-F);                                       // X3 = A * (B-F)
                    current.Y = G.squared() - (E_squared+E_squared+E_squared);   // Y3 = G^2 - 3*E^2
                    current.Z = B * H;                                           // Z3 = B * H
                    c.ell_0 = I;                               // ell_0 = xi * I
                    c.ell_VW = -bls12_381_twist * H;                                               // ell_VW = - H (later: * yP)
                    c.ell_VV = J+J+J;                                            // ell_VV = 3*J (later: * xP)
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                void mixed_addition_step_for_miller_loop(const bls12_g2<ModulusBits, GeneratorBits> base,
                                                                 bls12_g2<ModulusBits, GeneratorBits> &current,
                                                                 bls12_381_ate_ell_coeffs &c) {
                    const bls12_Fq2<ModulusBits, GeneratorBits> X1 = current.X, Y1 = current.Y, Z1 = current.Z;
                    const bls12_Fq2<ModulusBits, GeneratorBits> &x2 = base.X, &y2 = base.Y;

                    const bls12_Fq2<ModulusBits, GeneratorBits> D = X1 - x2 * Z1;          // D = X1 - X2*Z1
                    const bls12_Fq2<ModulusBits, GeneratorBits> E = Y1 - y2 * Z1;          // E = Y1 - Y2*Z1
                    const bls12_Fq2<ModulusBits, GeneratorBits> F = D.squared();           // F = D^2
                    const bls12_Fq2<ModulusBits, GeneratorBits> G = E.squared();           // G = E^2
                    const bls12_Fq2<ModulusBits, GeneratorBits> H = D*F;                   // H = D*F
                    const bls12_Fq2<ModulusBits, GeneratorBits> I = X1 * F;                // I = X1 * F
                    const bls12_Fq2<ModulusBits, GeneratorBits> J = H + Z1*G - (I+I);      // J = H + Z1*G - (I+I)

                    current.X = D * J;                           // X3 = D*J
                    current.Y = E * (I-J)-(H * Y1);              // Y3 = E*(I-J)-(H*Y1)
                    current.Z = Z1 * H;                          // Z3 = Z1*H
                    c.ell_0 = E * x2 - D * y2;                  // ell_0 = xi * (E * X2 - D * Y2)
                    c.ell_VV = - E;                              // ell_VV = - E (later: * xP)
                    c.ell_VW = bls12_381_twist * D;                                // ell_VW = D (later: * yP    )
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_381_ate_g1_precomp bls12_381_ate_precompute_g1(const bls12_g1<ModulusBits, GeneratorBits>& P) {

                    bls12_g1<ModulusBits, GeneratorBits> Pcopy = P;
                    Pcopy.to_affine_coordinates();

                    bls12_381_ate_g1_precomp result;
                    result.PX = Pcopy.X;
                    result.PY = Pcopy.Y;

                    return result;
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_381_ate_g2_precomp bls12_381_ate_precompute_g2(const bls12_g2<ModulusBits, GeneratorBits>& Q) {

                    bls12_g2<ModulusBits, GeneratorBits> Qcopy(Q);
                    Qcopy.to_affine_coordinates();

                    bls12_381_Fq two_inv = (bls12_381_Fq("2").inversed()); // could add to global params if needed

                    bls12_381_ate_g2_precomp result;
                    result.QX = Qcopy.X;
                    result.QY = Qcopy.Y;

                    bls12_g2<ModulusBits, GeneratorBits> R;
                    R.X = Qcopy.X;
                    R.Y = Qcopy.Y;
                    R.Z = bls12_Fq2<ModulusBits, GeneratorBits>::one();

                    const typename basic_policy<bls12<ModulusBits, GeneratorBits>>::number_type &loop_count =
                        basic_policy<bls12<ModulusBits, GeneratorBits>>::ate_loop_count;

                    bool found_one = false;
                    bls12_381_ate_ell_coeffs c;

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

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_ate_miller_loop(const bls12_381_ate_g1_precomp &prec_P,
                                                     const bls12_381_ate_g2_precomp &prec_Q) {

                    bls12_gt<ModulusBits, GeneratorBits> f = bls12_gt<ModulusBits, GeneratorBits>::one();

                    bool found_one = false;
                    size_t idx = 0;

                    const typename basic_policy<bls12<ModulusBits, GeneratorBits>>::number_type &loop_count =
                        basic_policy<bls12<ModulusBits, GeneratorBits>>::ate_loop_count;

                    bls12_381_ate_ell_coeffs c;

                    for (long i = loop_count.max_bits(); i >= 0; --i) {
                        const bool bit = loop_count.test_bit(i);
                        if (!found_one) {
                            /* this skips the MSB itself */
                            found_one |= bit;
                            continue;
                        }

                        /* code below gets executed for all bits (EXCEPT the MSB itself) of
                           bls12_381_param_p (skipping leading zeros) in MSB to LSB
                           order */

                        c = prec_Q.coeffs[idx++];
                        f = f.squared();
                        f = f.mul_by_045(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);

                        if (bit) {
                            c = prec_Q.coeffs[idx++];
                            f = f.mul_by_045(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);
                        }

                    }

                    if (basic_policy<bls12<ModulusBits, GeneratorBits>>::ate_is_loop_count_neg) {
                        f = f.inversed();
                    }

                    return f;
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_ate_double_miller_loop(const bls12_381_ate_g1_precomp &prec_P1,
                                                     const bls12_381_ate_g2_precomp &prec_Q1,
                                                     const bls12_381_ate_g1_precomp &prec_P2,
                                                     const bls12_381_ate_g2_precomp &prec_Q2) {

                    bls12_gt<ModulusBits, GeneratorBits> f = bls12_gt<ModulusBits, GeneratorBits>::one();

                    bool found_one = false;
                    size_t idx = 0;

                    const typename basic_policy<bls12<ModulusBits, GeneratorBits>>::number_type &loop_count =
                        basic_policy<bls12<ModulusBits, GeneratorBits>>::ate_loop_count;
                        
                    for (long i = loop_count.max_bits(); i >= 0; --i) {
                        const bool bit = loop_count.test_bit(i);
                        if (!found_one) {
                            /* this skips the MSB itself */
                            found_one |= bit;
                            continue;
                        }

                        /* code below gets executed for all bits (EXCEPT the MSB itself) of
                           bls12_381_param_p (skipping leading zeros) in MSB to LSB
                           order */

                        bls12_381_ate_ell_coeffs c1 = prec_Q1.coeffs[idx];
                        bls12_381_ate_ell_coeffs c2 = prec_Q2.coeffs[idx];
                        ++idx;

                        f = f.squared();

                        f = f.mul_by_045(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                        f = f.mul_by_045(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);

                        if (bit) {
                            bls12_381_ate_ell_coeffs c1 = prec_Q1.coeffs[idx];
                            bls12_381_ate_ell_coeffs c2 = prec_Q2.coeffs[idx];
                            ++idx;

                            f = f.mul_by_045(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                            f = f.mul_by_045(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);
                        }
                    }

                    if (basic_policy<bls12<ModulusBits, GeneratorBits>>::ate_is_loop_count_neg) {
                        f = f.inversed();
                    }


                    return f;
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_ate_pairing(const bls12_g1<ModulusBits, GeneratorBits>& P, const bls12_g2<ModulusBits, GeneratorBits> &Q) {
                    bls12_381_ate_g1_precomp prec_P = bls12_381_ate_precompute_g1(P);
                    bls12_381_ate_g2_precomp prec_Q = bls12_381_ate_precompute_g2(Q);
                    bls12_gt<ModulusBits, GeneratorBits> result = bls12_381_ate_miller_loop(prec_P, prec_Q);
                    return result;
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_ate_reduced_pairing(const bls12_g1<ModulusBits, GeneratorBits> &P, const bls12_g2<ModulusBits, GeneratorBits> &Q) {
                    const bls12_gt<ModulusBits, GeneratorBits> f = bls12_381_ate_pairing(P, Q);
                    const bls12_gt<ModulusBits, GeneratorBits> result = bls12_381_final_exponentiation(f);
                    return result;
                }

                /* choice of pairing */

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_g1<ModulusBits, GeneratorBits>_precomp bls12_381_precompute_g1(const bls12_g1<ModulusBits, GeneratorBits>& P) {
                    return bls12_381_ate_precompute_g1(P);
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_g2<ModulusBits, GeneratorBits>_precomp bls12_381_precompute_g2(const bls12_g2<ModulusBits, GeneratorBits>& Q) {
                    return bls12_381_ate_precompute_g2(Q);
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_miller_loop(const bls12_g1<ModulusBits, GeneratorBits>_precomp &prec_P,
                                          const bls12_g2<ModulusBits, GeneratorBits>_precomp &prec_Q) {
                    return bls12_381_ate_miller_loop(prec_P, prec_Q);
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_double_miller_loop(const bls12_g1<ModulusBits, GeneratorBits>_precomp &prec_P1,
                                                 const bls12_g2<ModulusBits, GeneratorBits>_precomp &prec_Q1,
                                                 const bls12_g1<ModulusBits, GeneratorBits>_precomp &prec_P2,
                                                 const bls12_g2<ModulusBits, GeneratorBits>_precomp &prec_Q2) {
                    return bls12_381_ate_double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_pairing(const bls12_g1<ModulusBits, GeneratorBits>& P,
                                      const bls12_g2<ModulusBits, GeneratorBits> &Q) {
                    return bls12_381_ate_pairing(P, Q);
                }

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                bls12_gt<ModulusBits, GeneratorBits> bls12_381_reduced_pairing(const bls12_g1<ModulusBits, GeneratorBits> &P,
                                             const bls12_g2<ModulusBits, GeneratorBits> &Q) {
                    return bls12_381_ate_reduced_pairing(P, Q);
                }

            }    // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}                // namespace nil
#endif                   // ALGEBRA_PAIRING_BLS12_FUNCTIONS_HPP
