//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_ATE_HPP
#define ALGEBRA_PAIRING_ATE_HPP

#include <stdexcept>
#include <vector>

namespace nil {
    namespace algebra {
        namespace pairing {

            using nil::algebra;

            /*
                calc optimal ate pairing
                @param f [out] e(Q, P)
                @param Q [in] affine coord. (Q[0], Q[1])
                @param P [in] affine coord. (P[0], P[1])
                @note not defined for infinity point
            */
            template<typename Params>
            void opt_atePairing(element_fp12<Params> &f, const element_fp2<Params> Q[2],
                                const element_fp<Params> P[2]) {
                element_fp2<Params> T[3];
                T[0] = Q[0];
                T[1] = Q[1];
                T[2] = element_fp2({1, 0});
                element_fp2<Params> Qneg[2];

                if (useNAF) {
                    Qneg[0] = Q[0];
                    Qneg[1] = -Q[1];
                }
                // at 1.
                element_fp6<Params> d;
                d = fields::detail::pointDblLineEval(T, P);
                element_fp6 e;
                assert(Param::siTbl[1] == 1);
                e = fields::detail::pointAddLineEval(T, Q, P);
                f = fields::detail::mul_Fp2_024_Fp2_024(d, e);
                // loop from 2.
                element_fp6 l;
                // 844kclk
                for (size_t i = 2; i < Param::siTbl.size(); i++) {
                    // 3.6k x 63
                    l = fields::detail::pointDblLineEval(T, P);
                    // 4.7k x 63
                    f = f.square();
                    // 4.48k x 63
                    f = mul_Fp2_024(l);

                    if (Param::siTbl[i] > 0) {
                        // 9.8k x 3
                        // 5.1k
                        l = pointAddLineEval(T, Q, P);
                        f = mul_Fp2_024(l);
                    } else if (Param::siTbl[i] < 0) {
                        l = pointAddLineEval(T, Qneg, P);
                        f = mul_Fp2_024(l);
                    }
                }

                // addition step
                element_fp2 Q1[2];
                detail::FrobEndOnTwist_1(Q1, Q);
                element_fp2 Q2[2];

                detail::FrobEndOnTwist_2(Q2, Q);
                Q2[1] = -Q2[1];

                element_fp12 ft;
                d = pointAddLineEval(T, Q1, P);    // 5k
                e = pointAddLineEval(T, Q2, P);    // 5k
                ft = mul_Fp2_024_Fp2_024(d, e);    // 2.7k
                f = f * ft;                        // 6.4k
                // final exponentiation
                f.final_exp();
            }

            /*
                opt_atePairingJac is a wrapper function of opt_atePairing
                @param f [out] e(Q, P)
                @param Q [in] Jacobi coord. (_Q[0], _Q[1], _Q[2])
                @param _P [in] Jacobi coord. (_P[0], _P[1], _P[2])
                output : e(Q, P)
            */
            void opt_atePairingJac(element_fp12 &f, const element_fp2 _Q[3], const element_fp _P[3]) {
                if (_Q[2] == 0 || _P[2] == 0) {
                    f = 1;
                    return;
                }

                element_fp2 Q[3];
                element_fp P[3];
                detail::NormalizeJac(Q, _Q);
                detail::NormalizeJac(P, _P);
                opt_atePairing(f, Q, P);
            }

            inline void opt_atePairing(Fp12 &f, const Ec2 &Q, const Ec1 &P) {
                Q.normalize();
                P.normalize();
                if (Q.is_zero() || P.is_zero()) {
                    f = 1;
                    return;
                }
                opt_atePairing<Fp>(f, Q.p, P.p);
            }
            /*
                inQ[3] : permit not-normalized
            */
            inline void precomputeG2(std::vector<element_fp6> &coeff, element_fp2 Q[3], const element_fp2 inQ[3]) {
                detail::NormalizeJac(Q, inQ);

                element_fp2 T[3];
                T[0] = Q[0];
                T[1] = Q[1];
                T[2] = element_fp2({1, 0});
                element_fp2 Qneg[2];
                if (Param::useNAF) {
                    Qneg[0] = Q[0];
                    Qneg[1] = -Q[1];
                }

                coeff.push_back(fields::detail::pointDblLineEvalWithoutP(T));
                coeff.push_back(pointAddLineEvalWithoutP(T, Q));

                for (size_t i = 2; i < Param::siTbl.size(); i++) {
                    coeff.push_back(fields::detail::pointDblLineEvalWithoutP(T));

                    if (Param::siTbl[i] > 0) {
                        coeff.push_back(pointAddLineEvalWithoutP(T, Q));
                    } else if (Param::siTbl[i] < 0) {
                        coeff.push_back(pointAddLineEvalWithoutP(T, Qneg));
                    }
                }

                // addition step
                element_fp2 Q1[2];
                detail::FrobEndOnTwist_1(Q1, Q);
                element_fp2 Q2[2];

                detail::FrobEndOnTwist_2(Q2, Q);
                Q2[1] = -Q2[1];

                coeff.push_back(pointAddLineEvalWithoutP(T, Q1));
                coeff.push_back(pointAddLineEvalWithoutP(T, Q2));
            }

            /*
                precP : normalized point
            */
            inline void millerLoop(Fp12 &f, const std::vector<element_fp6> &Qcoeff, const element_fp precP[2]) {

                size_t idx = 0;

                element_fp6_3over2 d = Qcoeff[idx];
                d = d.mulFp6_24_Fp_01(precP);
                idx++;

                element_fp6_3over2 e = Qcoeff[idx];
                e = e.mulFp6_24_Fp_01(precP);
                f = mul_Fp2_024_Fp2_024(d, e);

                idx++;
                element_fp6 l;
                for (size_t i = 2; i < Param::siTbl.size(); i++) {
                    l = Qcoeff[idx].mulFp6_24_Fp_01(precP);
                    idx++;
                    f = f.square();

                    f = mul_Fp2_024(l);

                    if (Param::siTbl[i]) {
                        l = Qcoeff[idx];
                        idx++;
                        l = l.mulFp6_24_Fp_01(precP);
                        f = mul_Fp2_024(l);
                    }
                }

                element_fp12_2over3over2 ft;

                d = Qcoeff[idx].mulFp6_24_Fp_01(precP);
                idx++;

                e = Qcoeff[idx].mulFp6_24_Fp_01(precP);

                ft = mul_Fp2_024_Fp2_024(d, e);
                f *= ft;
            }

            inline void millerLoop2(Fp12 &f, const std::vector<Fp6> &Q1coeff, const element_fp precP1[2],
                                    const std::vector<Fp6> &Q2coeff, const element_fp precP2[2]) {
                assert(Param::siTbl[1] == 1);
                size_t idx = 0;

                element_fp6 d1 = Q1coeff[idx].mulFp6_24_Fp_01(precP1);
                element_fp6 d2 = Q2coeff[idx].mulFp6_24_Fp_01(precP2);
                idx++;

                element_fp12 f1;
                element_fp6 e1 = Q1coeff[idx].mulFp6_24_Fp_01(precP1);
                f1 = fields::detail::mul_Fp2_024_Fp2_024(d1, e1);

                element_fp12 f2;
                element_fp6 e2 = Q2coeff[idx].mulFp6_24_Fp_01(precP2);
                f2 = fields::detail::mul_Fp2_024_Fp2_024(d2, e2);
                f = f1 * f2;

                idx++;
                element_fp6 l1, l2;
                for (size_t i = 2; i < Param::siTbl.size(); i++) {
                    l1 = Q1coeff[idx];
                    l2 = Q2coeff[idx];
                    idx++;
                    f = f.square();

                    l1 = l1.mulFp6_24_Fp_01(precP1);
                    l2 = l2.mulFp6_24_Fp_01(precP2);

                    f1 = mul_Fp2_024_Fp2_024(l1, l2);
                    f = f * f1;

                    if (Param::siTbl[i]) {
                        l1 = Q1coeff[idx];
                        l2 = Q2coeff[idx];
                        idx++;

                        l1 = l1.mulFp6_24_Fp_01(precP1);
                        l2 = l2.mulFp6_24_Fp_01(precP2);
                        f1 = mul_Fp2_024_Fp2_024(l1, l2);
                        f = f * f1;
                    }
                }

                d1 = Q1coeff[idx].mulFp6_24_Fp_01(precP1);
                d2 = Q2coeff[idx].mulFp6_24_Fp_01(precP2);
                idx++;

                e1 = Q1coeff[idx].mulFp6_24_Fp_01(precP1);
                e2 = Q2coeff[idx].mulFp6_24_Fp_01(precP2);

                f1 = mul_Fp2_024_Fp2_024(d1, e1);
                f2 = mul_Fp2_024_Fp2_024(d2, e2);
                f *= f1;
                f *= f2;
            }

        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_PAIRING_ATE_HPP
