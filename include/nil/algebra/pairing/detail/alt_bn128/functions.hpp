//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_ALT_BN128_FUNCTIONS_HPP
#define ALGEBRA_PAIRING_ALT_BN128_FUNCTIONS_HPP

#include <nil/algebra/pairing/detail/alt_bn128/basic_policy.hpp>

#include <nil/algebra/curves/alt_bn128.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail {

                using nil::algebra;

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                using alt_bn128_Fq = curves::alt_bn128_g1<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                using alt_bn128_Fq2 = curves::alt_bn128_g2<ModulusBits, GeneratorBits>::underlying_field_type_value;

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                struct alt_bn128_ate_g1_precomp {
                    alt_bn128_Fq<ModulusBits, GeneratorBits> PX;
                    alt_bn128_Fq<ModulusBits, GeneratorBits> PY;

                    bool operator==(const alt_bn128_ate_g1_precomp &other) const {
                        return (this->PX == other.PX &&
                                this->PY == other.PY);
                    }
                };

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                struct alt_bn128_ate_ell_coeffs {
                    alt_bn128_Fq2<ModulusBits, GeneratorBits> ell_0;
                    alt_bn128_Fq2<ModulusBits, GeneratorBits> ell_VW;
                    alt_bn128_Fq2<ModulusBits, GeneratorBits> ell_VV;

                    bool operator==(const alt_bn128_ate_ell_coeffs &other) const {
                        return (this->ell_0 == other.ell_0 &&
                                this->ell_VW == other.ell_VW &&
                                this->ell_VV == other.ell_VV);
                    }
                };

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                struct alt_bn128_ate_g2_precomp {
                    alt_bn128_Fq2<ModulusBits, GeneratorBits> QX;
                    alt_bn128_Fq2<ModulusBits, GeneratorBits> QY;
                    std::vector<alt_bn128_ate_ell_coeffs> coeffs;

                    bool operator==(const alt_bn128_ate_g2_precomp &other) const {
                        return (this->QX == other.QX &&
                                this->QY == other.QY &&
                                this->coeffs == other.coeffs);
                    }
                };

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_final_exponentiation_first_chunk(const curves::alt_bn128_gt<ModulusBits, GeneratorBits> &elt) {

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

                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> A = curves::alt_bn128_gt<ModulusBits, GeneratorBits>(elt.c0,-elt.c1);
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> B = elt.inversed();
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> C = A * B;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> D = C.Frobenius_map(2);
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> result = D * C;

                    return result;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_exp_by_neg_z(const curves::alt_bn128_gt<ModulusBits, GeneratorBits> &elt) {

                    curves::alt_bn128_gt<ModulusBits, GeneratorBits> result = elt.cyclotomic_exp(alt_bn128_basic_policy<ModulusBits, GeneratorBits>::alt_bn128_final_exponent_z);
                    
                    if (!alt_bn128_basic_policy<ModulusBits, GeneratorBits>::alt_bn128_final_exponent_is_z_neg) {
                        result = result.unitary_inversed();
                    }

                    return result;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_final_exponentiation_last_chunk(const curves::alt_bn128_gt<ModulusBits, GeneratorBits> &elt) {

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
                      R = Q * P              // = elt^(q^2 * (12*z^3 + 6*z^2 + 6*z) + q*(12*z^3 + 6*z^2 + 4*z) * (12*z^3 + 12*z^2 + 6*z + 1))
                      S = conj(elt)          // = elt^(-1)
                      T = S * L              // = elt^(12*z^3 + 6*z^2 + 4*z - 1)
                      U = T.Frobenius_map(3) // = elt^(q^3(12*z^3 + 6*z^2 + 4*z - 1))
                      V = U * R              // = elt^(q^3(12*z^3 + 6*z^2 + 4*z - 1) + q^2 * (12*z^3 + 6*z^2 + 6*z) + q*(12*z^3 + 6*z^2 + 4*z) * (12*z^3 + 12*z^2 + 6*z + 1))
                      result = V

                    */

                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> A = alt_bn128_exp_by_neg_z(elt);
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> B = A.cyclotomic_squared();
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> C = B.cyclotomic_squared();
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> D = C * B;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> E = alt_bn128_exp_by_neg_z(D);
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> F = E.cyclotomic_squared();
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> G = alt_bn128_exp_by_neg_z(F);
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> H = D.unitary_inversed();
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> I = G.unitary_inversed();
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> J = I * E;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> K = J * H;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> L = K * B;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> M = K * E;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> N = M * elt;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> O = L.Frobenius_map(1);
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> P = O * N;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> Q = K.Frobenius_map(2);
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> R = Q * P;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> S = elt.unitary_inversed();
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> T = S * L;
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> U = T.Frobenius_map(3);
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> V = U * R;

                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> result = V;


                    return result;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_final_exponentiation(const curves::alt_bn128_gt<ModulusBits, GeneratorBits> &elt) {
                    /* OLD naive version:
                        curves::alt_bn128_gt<ModulusBits, GeneratorBits> result = elt^alt_bn128_final_exponent;
                    */
                    curves::alt_bn128_gt<ModulusBits, GeneratorBits> A = alt_bn128_final_exponentiation_first_chunk<ModulusBits, GeneratorBits>(elt);
                    curves::alt_bn128_gt<ModulusBits, GeneratorBits> result = alt_bn128_final_exponentiation_last_chunk<ModulusBits, GeneratorBits>(A);

                    return result;
                }

                /* ate pairing */

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                void doubling_step_for_flipped_miller_loop(const alt_bn128_Fq<ModulusBits, GeneratorBits>two_inv,
                                                           alt_bn128_g2<ModulusBits, GeneratorBits> &current,
                                                           alt_bn128_ate_ell_coeffs &c) {
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>X = current.X, Y = current.Y, Z = current.Z;

                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>A = two_inv * (X * Y);                     // A = X1 * Y1 / 2
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>B = Y.squared();                           // B = Y1^2
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>C = Z.squared();                           // C = Z1^2
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>D = C+C+C;                                 // D = 3 * C
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>E = alt_bn128_twist_coeff_b * D;             // E = twist_b * D
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>F = E+E+E;                                 // F = 3 * E
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>G = two_inv * (B+F);                       // G = (B+F)/2
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>H = (Y+Z).squared() - (B+C);               // H = (Y1+Z1)^2-(B+C)
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>I = E-B;                                   // I = E-B
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>J = X.squared();                           // J = X1^2
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>E_squared = E.squared();                   // E_squared = E^2

                    current.X = A * (B-F);                                       // X3 = A * (B-F)
                    current.Y = G.squared() - (E_squared+E_squared+E_squared);   // Y3 = G^2 - 3*E^2
                    current.Z = B * H;                                           // Z3 = B * H
                    c.ell_0 = alt_bn128_twist * I;                                 // ell_0 = xi * I
                    c.ell_VW = -H;                                               // ell_VW = - H (later: * yP)
                    c.ell_VV = J+J+J;                                            // ell_VV = 3*J (later: * xP)
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                void mixed_addition_step_for_flipped_miller_loop(const alt_bn128_g2<ModulusBits, GeneratorBits> base,
                                                                 alt_bn128_g2<ModulusBits, GeneratorBits> &current,
                                                                 alt_bn128_ate_ell_coeffs &c) {
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>X1 = current.X, Y1 = current.Y, Z1 = current.Z;
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>&x2 = base.X, &y2 = base.Y;

                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>D = X1 - x2 * Z1;          // D = X1 - X2*Z1
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>E = Y1 - y2 * Z1;          // E = Y1 - Y2*Z1
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>F = D.squared();           // F = D^2
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>G = E.squared();           // G = E^2
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>H = D*F;                   // H = D*F
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>I = X1 * F;                // I = X1 * F
                    const alt_bn128_Fq2<ModulusBits, GeneratorBits>J = H + Z1*G - (I+I);      // J = H + Z1*G - (I+I)

                    current.X = D * J;                           // X3 = D*J
                    current.Y = E * (I-J)-(H * Y1);              // Y3 = E*(I-J)-(H*Y1)
                    current.Z = Z1 * H;                          // Z3 = Z1*H
                    c.ell_0 = alt_bn128_twist * (E * x2 - D * y2); // ell_0 = xi * (E * X2 - D * Y2)
                    c.ell_VV = - E;                              // ell_VV = - E (later: * xP)
                    c.ell_VW = D;                                // ell_VW = D (later: * yP    )
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                alt_bn128_ate_g1_precomp<ModulusBits, GeneratorBits> alt_bn128_ate_precompute_g1(const alt_bn128_g1& P) {

                    alt_bn128_g1<ModulusBits, GeneratorBits> Pcopy = P.to_affine_coordinates();

                    alt_bn128_ate_g1_precomp<ModulusBits, GeneratorBits> result;
                    result.PX = Pcopy.X;
                    result.PY = Pcopy.Y;

                    return result;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                alt_bn128_ate_g2_precomp<ModulusBits, GeneratorBits> alt_bn128_ate_precompute_g2(const alt_bn128_g2& Q) {

                    alt_bn128_g2<ModulusBits, GeneratorBits> Qcopy(Q).to_affine_coordinates();

                    alt_bn128_Fq<ModulusBits, GeneratorBits>two_inv = (alt_bn128_Fq(0x02).inversed()); // could add to global params if needed

                    alt_bn128_ate_g2_precomp<ModulusBits, GeneratorBits> result;
                    result.QX = Qcopy.X;
                    result.QY = Qcopy.Y;

                    alt_bn128_g2<ModulusBits, GeneratorBits> R;
                    R.X = Qcopy.X;
                    R.Y = Qcopy.Y;
                    R.Z = alt_bn128_Fq2<ModulusBits, GeneratorBits>::one();

                    const typename alt_bn128_basic_policy<ModulusBits, GeneratorBits>::number_type &loop_count =
                        alt_bn128_basic_policy<ModulusBits, GeneratorBits>::ate_loop_count;

                    bool found_one = false;
                    alt_bn128_ate_ell_coeffs c;

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

                    alt_bn128_g2<ModulusBits, GeneratorBits> Q1 = Qcopy.mul_by_q();
                    assert(Q1.Z == alt_bn128_Fq2::one());
                    alt_bn128_g2<ModulusBits, GeneratorBits> Q2 = Q1.mul_by_q();
                    assert(Q2.Z == alt_bn128_Fq2::one());

                    if (alt_bn128_basic_policy<ModulusBits, GeneratorBits>::ate_is_loop_count_neg) {
                        R.Y = - R.Y;
                    }
                    Q2.Y = - Q2.Y;

                    mixed_addition_step_for_flipped_miller_loop(Q1, R, c);
                    result.coeffs.push_back(c);

                    mixed_addition_step_for_flipped_miller_loop(Q2, R, c);
                    result.coeffs.push_back(c);

                    return result;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_ate_miller_loop(const alt_bn128_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P,
                                                     const alt_bn128_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q) {

                    curves::alt_bn128_gt<ModulusBits, GeneratorBits> f = curves::alt_bn128_gt<ModulusBits, GeneratorBits>::one();

                    bool found_one = false;
                    size_t idx = 0;

                    const typename alt_bn128_basic_policy<ModulusBits, GeneratorBits>::number_type &loop_count =
                        alt_bn128_basic_policy<ModulusBits, GeneratorBits>::ate_loop_count;

                    alt_bn128_ate_ell_coeffs c;

                    for (long i = loop_count.max_bits(); i >= 0; --i) {
                        const bool bit = loop_count.test_bit(i);
                        if (!found_one) {
                            /* this skips the MSB itself */
                            found_one |= bit;
                            continue;
                        }

                        /* code below gets executed for all bits (EXCEPT the MSB itself) of
                           alt_bn128_param_p (skipping leading zeros) in MSB to LSB
                           order */

                        c = prec_Q.coeffs[idx++];
                        f = f.squared();
                        f = f.mul_by_024(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);

                        if (bit) {
                            c = prec_Q.coeffs[idx++];
                            f = f.mul_by_024(c.ell_0, prec_P.PY * c.ell_VW, prec_P.PX * c.ell_VV);
                        }

                    }

                    if (alt_bn128_basic_policy<ModulusBits, GeneratorBits>::ate_is_loop_count_neg) {
                        f = f.inversed();
                    }

                    c = prec_Q.coeffs[idx++];
                    f = f.mul_by_024(c.ell_0,prec_P.PY * c.ell_VW,prec_P.PX * c.ell_VV);

                    c = prec_Q.coeffs[idx++];
                    f = f.mul_by_024(c.ell_0,prec_P.PY * c.ell_VW,prec_P.PX * c.ell_VV);

                    return f;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_ate_double_miller_loop(const alt_bn128_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P1,
                                                     const alt_bn128_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q1,
                                                     const alt_bn128_ate_g1_precomp<ModulusBits, GeneratorBits> &prec_P2,
                                                     const alt_bn128_ate_g2_precomp<ModulusBits, GeneratorBits> &prec_Q2) {

                    curves::alt_bn128_gt<ModulusBits, GeneratorBits> f = curves::alt_bn128_gt<ModulusBits, GeneratorBits>::one();

                    bool found_one = false;
                    size_t idx = 0;

                    const typename alt_bn128_basic_policy<ModulusBits, GeneratorBits>::number_type &loop_count =
                        alt_bn128_basic_policy<ModulusBits, GeneratorBits>::ate_loop_count;

                    for (long i = loop_count.max_bits(); i >= 0; --i) {
                        const bool bit = loop_count.test_bit(i);
                        if (!found_one) {
                            /* this skips the MSB itself */
                            found_one |= bit;
                            continue;
                        }

                        /* code below gets executed for all bits (EXCEPT the MSB itself) of
                           alt_bn128_param_p (skipping leading zeros) in MSB to LSB
                           order */

                        alt_bn128_ate_ell_coeffs c1 = prec_Q1.coeffs[idx];
                        alt_bn128_ate_ell_coeffs c2 = prec_Q2.coeffs[idx];
                        ++idx;

                        f = f.squared();

                        f = f.mul_by_024(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                        f = f.mul_by_024(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);

                        if (bit) {
                            alt_bn128_ate_ell_coeffs c1 = prec_Q1.coeffs[idx];
                            alt_bn128_ate_ell_coeffs c2 = prec_Q2.coeffs[idx];
                            ++idx;

                            f = f.mul_by_024(c1.ell_0, prec_P1.PY * c1.ell_VW, prec_P1.PX * c1.ell_VV);
                            f = f.mul_by_024(c2.ell_0, prec_P2.PY * c2.ell_VW, prec_P2.PX * c2.ell_VV);
                        }
                    }

                    if (alt_bn128_basic_policy<ModulusBits, GeneratorBits>::ate_is_loop_count_neg) {
                        f = f.inversed();
                    }

                    alt_bn128_ate_ell_coeffs c1 = prec_Q1.coeffs[idx];
                    alt_bn128_ate_ell_coeffs c2 = prec_Q2.coeffs[idx];
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

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_ate_pairing(const alt_bn128_g1& P, const alt_bn128_g2<ModulusBits, GeneratorBits> &Q) {
                    alt_bn128_ate_g1_precomp<ModulusBits, GeneratorBits> prec_P = alt_bn128_ate_precompute_g1<ModulusBits, GeneratorBits>(P);
                    alt_bn128_ate_g2_precomp<ModulusBits, GeneratorBits> prec_Q = alt_bn128_ate_precompute_g2<ModulusBits, GeneratorBits>(Q);
                    curves::alt_bn128_gt<ModulusBits, GeneratorBits> result = alt_bn128_ate_miller_loop<ModulusBits, GeneratorBits>(prec_P, prec_Q);
                    return result;
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_ate_reduced_pairing(const alt_bn128_g1<ModulusBits, GeneratorBits> &P, const alt_bn128_g2<ModulusBits, GeneratorBits> &Q) {
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> f = alt_bn128_ate_pairing<ModulusBits, GeneratorBits>(P, Q);
                    const curves::alt_bn128_gt<ModulusBits, GeneratorBits> result = alt_bn128_final_exponentiation<ModulusBits, GeneratorBits>(f);
                    return result;
                }

                /* choice of pairing */

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                alt_bn128_g1_precomp alt_bn128_precompute_g1(const alt_bn128_g1& P) {
                    return alt_bn128_ate_precompute_g1<ModulusBits, GeneratorBits>(P);
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                alt_bn128_g2_precomp alt_bn128_precompute_g2(const alt_bn128_g2& Q) {
                    return alt_bn128_ate_precompute_g2<ModulusBits, GeneratorBits>(Q);
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_miller_loop(const alt_bn128_g1_precomp &prec_P,
                                          const alt_bn128_g2_precomp &prec_Q) {
                    return alt_bn128_ate_miller_loop<ModulusBits, GeneratorBits>(prec_P, prec_Q);
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_double_miller_loop(const alt_bn128_g1_precomp &prec_P1,
                                                 const alt_bn128_g2_precomp &prec_Q1,
                                                 const alt_bn128_g1_precomp &prec_P2,
                                                 const alt_bn128_g2_precomp &prec_Q2) {
                    return alt_bn128_ate_double_miller_loop<ModulusBits, GeneratorBits>(prec_P1, prec_Q1, prec_P2, prec_Q2);
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_pairing(const alt_bn128_g1& P,
                                      const alt_bn128_g2<ModulusBits, GeneratorBits> &Q) {
                    return alt_bn128_ate_pairing<ModulusBits, GeneratorBits>(P, Q);
                }

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                curves::alt_bn128_gt<ModulusBits, GeneratorBits> alt_bn128_reduced_pairing(const alt_bn128_g1<ModulusBits, GeneratorBits> &P,
                                             const alt_bn128_g2<ModulusBits, GeneratorBits> &Q) {
                    return alt_bn128_ate_reduced_pairing<ModulusBits, GeneratorBits>(P, Q);
                }

            }    // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_ALT_BN128_FUNCTIONS_HPP
