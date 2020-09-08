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

#include <sstream>

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
                struct bls12_Fq_conic_coefficients {

                    bls12_Fq<ModulusBits, GeneratorBits> c_ZZ;
                    bls12_Fq<ModulusBits, GeneratorBits> c_XY;
                    bls12_Fq<ModulusBits, GeneratorBits> c_XZ;

                    bool operator==(const bls12_Fq_conic_coefficients &other) const {
                        return (this->c_ZZ == other.c_ZZ && this->c_XY == other.c_XY && this->c_XZ == other.c_XZ);
                    }
                };

                struct bls12_pairing_engine {
                    bls12_g1<ModulusBits, GeneratorBits> G1;
                    bls12_g2<ModulusBits, GeneratorBits> G2;
                    bls12_gt<ModulusBits, GeneratorBits> fp12;
                    bls12_Fq2<ModulusBits, GeneratorBits> fp2;
                }

                func (e *Engine) doublingStep(coeff *[3]fe2, r *PointG2) {
                    // Adaptation of Formula 3 in https://eprint.iacr.org/2010/526.pdf
                    fp2 := e.fp2
                    t := e.t2
                    t[0] = &r[0] * &r[1];
                    t[0] = t[0].mulByFq(twoInv);
                    t[1] = r[1].squared();
                    t[2] = r[2].squared();
                    
                    t[7] = t[2].doubled();
                    t[7] = t[7] + t[2];
                    t[3] = t[7].mulByB();
                    t[4] = t[3].doubled();
                    t[4] = t[4] + t[3];
                    t[5] = t[1] + t[4];
                    t[5] = t[5].mulByFq(twoInv);
                    t[6] = r[1] + r[2];
                    t[6] = t[6].squared();
                    t[7] = t[2] + t[1];
                    t[6] = t[6] - t[7];
                    coeff[0] = t[3] - t[1];
                    t[7] = r[0].squared();
                    t[4] = t[1] - t[4];
                    r[0] = t[4]  * t[0];
                    t[2] = t[3].squared();
                    t[3] = t[2].doubled();
                    t[3] = t[3] + t[2];
                    t[5] = t[5].squared();
                    r[1] = t[5] - t[3];
                    r[2] = t[1] * t[6];
                    t[0] = t[7].doubled();
                    coeff[1] = t[0] + t[7];
                    coeff[2] = -t[6];
                }

                func (e *Engine) additionStep(coeff *[3]fe2, r, q *PointG2) {
                    // Algorithm 12 in https://eprint.iacr.org/2010/526.pdf
                    fp2 := e.fp2
                    t := e.t2
                    t[0] = q[1] * r[2];
                    t[0] = -t[0];
                    t[0] = t[0] + r[1];
                    t[1] = q[0] * r[2];
                    t[1] = -t[1];
                    t[1] = t[1] + r[0];
                    t[2] = t[0].squared();
                    t[3] = t[1].squared();
                    t[4] = t[1] * t[3];
                    t[2] = r[2] * t[2];
                    t[3] = r[0] * t[3];
                    t[5] = t[3].double();
                    t[5] = t[4] - t[5];
                    t[5] = t[5] + t[2];
                    r[0] = t[1] * t[5];
                    t[2] = t[3] - t[5];
                    t[2] = t[2] * t[0];
                    t[3] = r[1] * t[4];
                    r[1] = t[2] - t[3];
                    r[2] = r[2] * t[4];
                    t[2] = t[1] * q[1];
                    t[3] = t[0] * q[0];
                    coeff[0] = t[3] - t[2];
                    coeff[1] = -t[0];
                    coeff[2].set(t[1]);
                }

                func (e *Engine) preCompute(ellCoeffs *[68][3]fe2, twistPoint *PointG2) {
                    // Algorithm 5 in https://eprint.iacr.org/2019/077.pdf
                    if e.G2.IsZero(twistPoint) {
                        return;
                    }
                    r := new(PointG2).Set(twistPoint);
                    j := 0;
                    for i := int(x.BitLen() - 2); i >= 0; i-- {
                        e.doublingStep(&ellCoeffs[j], r);
                        if x.Bit(i) != 0 {
                            j++;
                            ellCoeffs[j] = fe6{};
                            e.additionStep(&ellCoeffs[j], r, twistPoint);
                        }
                        j++;
                    }
                }

                func (e *Engine) bls12_millerLoop(f *fe12) {
                    pairs := e.pairs;
                    ellCoeffs := make([][68][3]fe2, len(pairs));
                    for (i := 0; i < len(pairs); i++) {
                        e.preCompute(&ellCoeffs[i], pairs[i].g2);
                    }
                    fp12, fp2 := e.fp12, e.fp2;
                    t := e.t2;
                    f.one();
                    j := 0
                    for (i := 62; i >= 0; i--) {
                        if (i != 62) {
                            f = f.squared();
                        }
                        for (i := 0; i <= len(pairs)-1; i++) {
                            t[0] = &ellCoeffs[i][j][2].mulByFq(&pairs[i].g1[1]);
                            t[1] = &ellCoeffs[i][j][1].mulByFq(&pairs[i].g1[0]);
                            f = mulBy014Assign(&ellCoeffs[i][j][0], t[1], t[0]);
                        }
                        if (x.Bit(i) != 0) {
                            j++;
                            for (i := 0; i <= len(pairs)-1; i++) {
                                t[0] = &ellCoeffs[i][j][2].mulByFq(&pairs[i].g1[1]);
                                t[1] = &ellCoeffs[i][j][1].mulByFq(pairs[i].g1[0]);
                                f = mulBy014Assign(&ellCoeffs[i][j][0], t[1], t[0]);
                            }
                        }
                        j++;
                    }
                    f = f.conjugate();
                }

                func bls12_final_exponentiation_internal1(n int) {
                    fp12.mulAssign(c, a);
                    for (i := 0; i < n; i++) {
                        c = c.cyclotomicSquare();
                    }
                }

                // exp raises element by x = -15132376222941642752
                func (e *Engine) bls12_final_exponentiation_internal2(c, a *fe12) {
                    // Adapted from https://github.com/supranational/blst/blob/master/src/pairing.c
                    fp12 := e.fp12;
                    chain := bls12_final_exponentiation_internal1
                    fp12.cyclotomicSquare(c, a) // (a ^ 2)
                    chain(2)                    // (a ^ (2 + 1)) ^ (2 ^ 2) = a ^ 12
                    chain(3)                    // (a ^ (12 + 1)) ^ (2 ^ 3) = a ^ 104
                    chain(9)                    // (a ^ (104 + 1)) ^ (2 ^ 9) = a ^ 53760
                    chain(32)                   // (a ^ (53760 + 1)) ^ (2 ^ 32) = a ^ 230901736800256
                    chain(16)                   // (a ^ (230901736800256 + 1)) ^ (2 ^ 16) = a ^ 15132376222941642752
                    // invert chain result since x is negative
                    fp12.conjugate(c, c)
                }
                
                func (e *Engine) bls12_final_exponentiation(f *fe12) {
                    fp12, t := e.fp12, e.t12
                    // easy part

                    t[1] = f.inversed();             // t1 = f0 ^ -1
                    conjugate(t[0], f);             // t0 = f0 ^ p6
                    t[2] =t[0] * t[1];              // t2 = f0 ^ (p6 - 1)
                    t[1] = t[2];                     // t1 = f0 ^ (p6 - 1)
                    t[2] = t[2].frobeniusMap2();     // t2 = f0 ^ ((p6 - 1) * p2)
                    mulAssign(t[2], t[1])     // t2 = f0 ^ ((p6 - 1) * (p2 + 1))

                    // f = f0 ^ ((p6 - 1) * (p2 + 1))

                    // hard part
                    // https://eprint.iacr.org/2016/130
                    // On the Computation of the Optimal Ate Pairing at the 192-bit Security Level
                    // Section 3
                    // f ^ d = λ_0 + λ_1 * p + λ_2 * p^2 + λ_3 * p^3

                    conjugate(t[1], t[2]);
                    cyclotomicSquare(t[1], t[1]);                               // t1 = f ^ (-2)
                    e.bls12_final_exponentiation_internal2(t[3], t[2]);         // t3 = f ^ (u)
                    cyclotomicSquare(t[4], t[3]);                               // t4 = f ^ (2u)
                    t[5] = t[1] * t[3];                                         // t5 = f ^ (u - 2)
                    e.bls12_final_exponentiation_internal2(t[1], t[5]);         // t1 = f ^ (u^2 - 2 * u)
                    e.bls12_final_exponentiation_internal2(t[0], t[1]);         // t0 = f ^ (u^3 - 2 * u^2)
                    e.bls12_final_exponentiation_internal2(t[6], t[0]);         // t6 = f ^ (u^4 - 2 * u^3)
                    mulAssign(t[6], t[4]);                                      // t6 = f ^ (u^4 - 2 * u^3 + 2 * u)
                    e.bls12_final_exponentiation_internal2(t[4], t[6]);         // t4 = f ^ (u^4 - 2 * u^3 + 2 * u^2)
                    conjugate(t[5], t[5]);                                      // t5 = f ^ (2 - u)
                    mulAssign(t[4], t[5]);                                      // t4 = f ^ (u^4 - 2 * u^3 + 2 * u^2 - u + 2)
                    mulAssign(t[4], t[2]);                                      // f_λ_0 = t4 = f ^ (u^4 - 2 * u^3 + 2 * u^2 - u + 3)

                    conjugate(t[5], t[2]);                                      // t5 = f ^ (-1)
                    mulAssign(t[5], t[6]);                                      // t1  = f ^ (u^4 - 2 * u^3 + 2 * u - 1)
                    frobeniusMap1(t[5]);                                        // f_λ_1 = t1 = f ^ ((u^4 - 2 * u^3 + 2 * u - 1) ^ p)

                    mulAssign(t[3], t[0]);                                       // t3 = f ^ (u^3 - 2 * u^2 + u)
                    frobeniusMap2(t[3]);                                         // f_λ_2 = t3 = f ^ ((u^3 - 2 * u^2 + u) ^ p^2)

                    mulAssign(t[1], t[2]);                                       // t1 = f ^ (u^2 - 2 * u + 1)
                    frobeniusMap3(t[1]);                                         // f_λ_3 = t1 = f ^ ((u^2 - 2 * u + 1) ^ p^3)

                    // out = f ^ (λ_0 + λ_1 + λ_2 + λ_3)
                    mulAssign(&t[3], &t[1]);
                    mulAssign(&t[3], &t[5]);
                    f = &t[3] * &t[4];
                }


            }    // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}                // namespace nil
#endif                   // ALGEBRA_PAIRING_BLS12_FUNCTIONS_HPP
