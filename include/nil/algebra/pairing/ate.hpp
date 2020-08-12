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

namespace bn {

    template<class Fp2>
    struct ParamT {
        typedef typename Fp2::Fp Fp;

        // Loop parameter for the Miller loop part of opt. ate pairing.
        typedef std::vector<signed char> SignVec;
        static SignVec siTbl;
        static bool useNAF;

        static SignVec zReplTbl;


        static inline void init(const CurveParam &cp, int mode = -1, bool useMulx = true) {

            //bool supported = cp == CurveSNARK1 || cp == CurveSNARK2;

            const int64_t org_z = cp.z;    // NOTE: hard-coded Fp12::pow_neg_t too.
            
            z.set(org_z);

            const number_type p = 21888242871839275222246405745257275088696311157297823662689037894645226208583_cppui254;
            const number_type r = 21888242871839275222246405745257275088548364400416034343698204186575808495617_cppui254;
            const number_type r = 147946756881789318990833708069417712967_cppui128;
            
            largest_c = 6 * z + 2;
            b = cp.b;    // set b before calling Fp::setModulo
            Fp::setModulo(p, mode, useMulx);
            half = Fp(1) / Fp(2);
            /*
                b_invxi = b / xi
            */
            fp2_value_type xi({cp.xi_a, cp.xi_b});
            b_invxi = xi.inverse() * fp2_value({b, 0});

            gammar[0] = mie::power(xi, (p - 1) / 6);

            for (size_t i = 1; i < sizeof(gammar) / sizeof(*gammar); ++i) {
                gammar[i] = gammar[i - 1] * gammar[0];
            }

            for (size_t i = 0; i < sizeof(gammar2) / sizeof(*gammar2); ++i) {
                gammar2[i] = Fp2(gammar[i].a_, -gammar[i].b_) * gammar[i];
            }

            for (size_t i = 0; i < sizeof(gammar2) / sizeof(*gammar2); ++i) {
                gammar3[i] = gammar[i] * gammar2[i];
            }

            W2p = mie::power(xi, (p - 1) / 3);
            W3p = mie::power(xi, (p - 1) / 2);
            fp2_value_type temp = mie::power(xi, (p * p - 1) / 6);
            
            Z = (-temp.a_).square();

            i0 = 0;
            i1 = 1;

            useNAF = util::getGoodRepl(siTbl, largest_c.abs());

            util::getGoodRepl(zReplTbl, z.abs());
        }

        // y = sum_{i=0}^4 c_i x^i
        // @todo Support signed integer substitution.
        template<class T, class U>
        static void eval(T &y, const U &x, const int *c) {
            U tmp = (((c[4] * x + c[3]) * x + c[2]) * x + c[1]) * x + c[0];
            y = tmp.get();
        }
    };

    template<class T>
    struct CompressT {
        typedef T Fp2;
        typedef typename Fp2::Fp Fp;
        typedef ParamT<Fp2> Param;
        typedef typename Fp2::Dbl Fp2Dbl;
        typedef Fp6T<Fp2> Fp6;
        typedef Fp12T<Fp6> Fp12;
        enum { N = 4 };

        Fp12 &z_;    // must be top for asm !!!
        Fp2 &g1_;
        Fp2 &g2_;
        Fp2 &g3_;
        Fp2 &g4_;
        Fp2 &g5_;

        // z is output area
        CompressT(Fp12 &z, const Fp12 &x) :
            z_(z), g1_(z.getFp2()[4]), g2_(z.getFp2()[3]), g3_(z.getFp2()[2]), g4_(z.getFp2()[1]), g5_(z.getFp2()[5]) {
            g2_ = x.getFp2()[3];
            g3_ = x.getFp2()[2];
            g4_ = x.getFp2()[1];
            g5_ = x.getFp2()[5];
        }
        CompressT(Fp12 &z, const CompressT &c) :
            z_(z), g1_(z.getFp2()[4]), g2_(z.getFp2()[3]), g3_(z.getFp2()[2]), g4_(z.getFp2()[1]), g5_(z.getFp2()[5]) {
            g2_ = c.g2_;
            g3_ = c.g3_;
            g4_ = c.g4_;
            g5_ = c.g5_;
        }

    private:
        void decompressBeforeInv(Fp2 &nume, Fp2 &denomi) const {
            assert(&nume != &denomi);

            if (g2_.is_zero()) {
                nume = g4_.dbl();
                nume *= g5_;
                denomi = g3_;
            } else {
                Fp2::mul_xi(denomi, g5_.square());
                nume = g4_.square(nume, g4_);
                nume = (denomi + ((nume - g3_).dbl() + nume)).divBy4();
                denomi = g2_;
            }
        }

        // output to z
        void decompressAfterInv() {
            Fp2 &g0 = z_.getFp2()[0];
            Fp2 t0, t1;
            // Compute g0.
            t1 = g3_ * g4_;
            t0 = (g1_.square() - t1).dbl() - t1 + g2_ * g5_;

            g0 = t0.mul_xi();
            g0.a_ += Param::i1;
        }

    public:
        // not used
        void decompress() {
            Fp2 nume, denomi;
            decompressBeforeInv(nume, denomi);
            denomi.inverse();
            g1_ = nume * denomi;    // g1 is recoverd.
            decompressAfterInv();
        }

        /*
            2275clk * 186 = 423Kclk QQQ
        */
        static void square(CompressT &z) {
            Fp2 t0, t1, t2;
            Fp2Dbl T0, T1, T2, T3;
            T0 = square(z.g4_);
            T1 = square(z.g5_);
            // # 7
            T2 = T1.mul_xi();
            // # 8
            T2 += T0;
            // # 9
            t2 = T2.mod();
            // # 1
            t0 = z.g4_ + z.g5_;
            T2 = square(t0);
            // # 2
            T0 += T1;
            //		Fp2Dbl::addNC(T0, T0, T1); // QQQ : OK?
            T2 -= T0;
            // # 3
            t0 = T2.mod();
            t1 = z.g2_ + z.g3_;
            T3 = square(t1);
            T2 = square(z.g2_);
            // # 4
            t1 = t0.mul_xi();
            // RRR
            z.g2_.a_ = t1.a_._3z_add_2xC();
            z.g2_.b_ = t1.b_._3z_add_2xC();

            t1 = t2 - z.g3_;
            t1 += t1;
            // # 11 !!!!
            T1 = square(z.g3_);
            // # 10 !!!!
            z.g3_ = t1 + t2;
            // # 12
            T0 = T1.mul_xi();
            // # 13
            T0 += T2;
            //		Fp2Dbl::addNC(T0, T0, T2); // QQQ : OK?
            // # 14
            t0 = T0.mod();
            z.g4_ = t0 - z.g4_;
            z.g4_ += z.g4_;
            // # 15
            z.g4_ += t0;
            // # 16
            T2 = addNC(T2, T1);
            T3 -= T2;
            // # 17
            t0 = T3.mod();
            // RRR
            z.g5_.a_ = t0.a_._3z_add_2xC();
            z.g5_.b_ = t0.b_._3z_add_2xC();

        }
        static void square_n(CompressT &z, int n) {
            for (int i = 0; i < n; i++) {
                square(z);
            }
        }

        /*
            Exponentiation over compression for:
            z = x^Param::z.abs()
        */
        static void fixed_power(Fp12 &z, const Fp12 &x) {
#if 0
		z = power(x, Param::z.abs());
#else
            assert(&z != &x);
            Fp12 d62;
            Fp2 c55nume, c55denomi, c62nume, c62denomi;
            CompressT c55(z, x);
            CompressT::square_n(c55, 55);    // 106k
            c55.decompressBeforeInv(c55nume, c55denomi);
            CompressT c62(d62, c55);
            CompressT::square_n(c62, 62 - 55);    // 13.6k
            c62.decompressBeforeInv(c62nume, c62denomi);
            Fp2 acc;
            acc = c55denomi * c62denomi;
            acc.inverse();
            Fp2 t;
            t = acc * c62denomi;
            c55.g1_ = c55nume * t;
            c55.decompressAfterInv();    // 1.1k
            t = acc * c55denomi;
            c62.g1_ = c62nume * t;
            c62.decompressAfterInv();
            z *= x;    // 6.5k
            z *= d62;
#endif
        }
        static void (*square_n)(CompressT &z, int n);

    private:
        CompressT(const CompressT &);
        void operator=(const CompressT &);
    };

    /*
        calc optimal ate pairing
        @param f [out] e(Q, P)
        @param Q [in] affine coord. (Q[0], Q[1])
        @param P [in] affine coord. (P[0], P[1])
        @note not defined for infinity point
    */
    template<class Fp>
    void opt_atePairing(Fp12T<Fp6T<Fp2T<Fp>>> &f, const Fp2T<Fp> Q[2], const Fp P[2]) {
        typedef Fp2T<Fp> Fp2;
        typedef ParamT<Fp2> Param;
        typedef Fp6T<Fp2> Fp6;
        typedef Fp12T<Fp6> Fp12;
        Fp2 T[3];
        T[0] = Q[0];
        T[1] = Q[1];
        T[2] = Fp2(1);
        Fp2 Qneg[2];
        if (Param::useNAF) {
            Qneg[0] = Q[0];
            Qneg[1] = -Q[1];
        }
        // at 1.
        Fp6 d;
        Fp6::pointDblLineEval(d, T, P);
        Fp6 e;
        assert(Param::siTbl[1] == 1);
        Fp6::pointAddLineEval(e, T, Q, P);
        f = mul_Fp2_024_Fp2_024(d, e);
        // loop from 2.
        Fp6 l;
        // 844kclk
        for (size_t i = 2; i < Param::siTbl.size(); i++) {
            // 3.6k x 63
            Fp6::pointDblLineEval(l, T, P);
            // 4.7k x 63
            f = f.square();
            // 4.48k x 63
            Fp12::Dbl::mul_Fp2_024(f, l);

            if (Param::siTbl[i] > 0) {
                // 9.8k x 3
                // 5.1k
                Fp6::pointAddLineEval(l, T, Q, P);
                Fp12::Dbl::mul_Fp2_024(f, l);
            } else if (Param::siTbl[i] < 0) {
                Fp6::pointAddLineEval(l, T, Qneg, P);
                Fp12::Dbl::mul_Fp2_024(f, l);
            }
        }

        // addition step
        Fp2 Q1[2];
        ecop::FrobEndOnTwist_1(Q1, Q);
        Fp2 Q2[2];

        ecop::FrobEndOnTwist_2(Q2, Q);
        Q2[1] = -Q2[1];

        Fp12 ft;
        Fp6::pointAddLineEval(d, T, Q1, P);          // 5k
        Fp6::pointAddLineEval(e, T, Q2, P);          // 5k
        Fp12::Dbl::mul_Fp2_024_Fp2_024(ft, d, e);    // 2.7k
        f = f * ft;                         // 6.4k
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
    template<class Fp>
    void opt_atePairingJac(Fp12T<Fp6T<Fp2T<Fp>>> &f, const Fp2T<Fp> _Q[3], const Fp _P[3]) {
        if (_Q[2] == 0 || _P[2] == 0) {
            f = 1;
            return;
        }

        Fp2T<Fp> Q[3];
        Fp P[3];
        ecop::NormalizeJac(Q, _Q);
        ecop::NormalizeJac(P, _P);
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

    template<>
    inline bool EcT<Fp2>::isValid() const {
        return ecop::isOnTwistECJac3(p);
    }

    template<>
    inline bool EcT<Fp>::isValid() const {
        return ecop::isOnECJac3(p);
    }

    namespace components {

        /*
            inQ[3] : permit not-normalized
        */
        inline void precomputeG2(std::vector<Fp6> &coeff, element<fp2> Q[3], const element<fp2> inQ[3]) {
            coeff.clear();
            bn::ecop::NormalizeJac(Q, inQ);

            element<fp2> T[3];
            T[0] = Q[0];
            T[1] = Q[1];
            T[2] = element<fp2>({1, 0});
            element<fp2> Qneg[2];
            if (Param::useNAF) {
                Qneg[0] = Q[0];
                Qneg[1] = -Q[1];
            }

            Fp6 d;
            Fp6::pointDblLineEvalWithoutP(d, T);
            coeff.push_back(d);

            Fp6 e;
            assert(Param::siTbl[1] == 1);
            Fp6::pointAddLineEvalWithoutP(e, T, Q);
            coeff.push_back(e);

            bn::Fp6 l;
            // 844kclk
            for (size_t i = 2; i < Param::siTbl.size(); i++) {
                Fp6::pointDblLineEvalWithoutP(l, T);
                coeff.push_back(l);

                if (Param::siTbl[i] > 0) {
                    Fp6::pointAddLineEvalWithoutP(l, T, Q);
                    coeff.push_back(l);
                } else if (Param::siTbl[i] < 0) {
                    Fp6::pointAddLineEvalWithoutP(l, T, Qneg);
                    coeff.push_back(l);
                }
            }

            // addition step
            element<fp2> Q1[2];
            bn::ecop::FrobEndOnTwist_1(Q1, Q);
            element<fp2> Q2[2];

            bn::ecop::FrobEndOnTwist_2(Q2, Q);
            Q2[1] = -Q2[1];

            Fp6::pointAddLineEvalWithoutP(d, T, Q1);
            coeff.push_back(d);

            Fp6::pointAddLineEvalWithoutP(e, T, Q2);
            coeff.push_back(e);
        }

        /*
            precP : normalized point
        */
        inline void millerLoop(Fp12 &f, const std::vector<Fp6> &Qcoeff, const Fp precP[2]) {
            
            size_t idx = 0;

            element<fp6_3over2> d = Qcoeff[idx];
            d = d.mulFp6_24_Fp_01(precP);
            idx++;

            element<fp6_3over2> e = Qcoeff[idx];
            e = e.mulFp6_24_Fp_01(precP);
            f = mul_Fp2_024_Fp2_024(d, e);

            idx++;
            bn::Fp6 l;
            for (size_t i = 2; i < Param::siTbl.size(); i++) {
                l = Qcoeff[idx];
                idx++;
                f = f.square();
                l = l.mulFp6_24_Fp_01(precP);

                f = l.mul_Fp2_024();

                if (Param::siTbl[i]) {
                    l = Qcoeff[idx];
                    idx++;
                    l = l.mulFp6_24_Fp_01(precP);
                    f = l.mul_Fp2_024();
                }
            }

            element<fp12_2over3over2> ft;

            d = Qcoeff[idx];
            d = d.mulFp6_24_Fp_01(precP);
            idx++;

            e = Qcoeff[idx];
            e = e.mulFp6_24_Fp_01(precP);

            ft = mul_Fp2_024_Fp2_024(d, e);
            f *= ft;
        }

        inline void millerLoop2(Fp12 &f, const std::vector<Fp6> &Q1coeff, const Fp precP1[2],
                                const std::vector<Fp6> &Q2coeff, const Fp precP2[2]) {
            assert(Param::siTbl[1] == 1);
            size_t idx = 0;

            Fp6 d1 = Q1coeff[idx];
            d1 = d1.mulFp6_24_Fp_01(precP1);
            Fp6 d2 = Q2coeff[idx];
            d2 = d2.mulFp6_24_Fp_01(precP2);
            idx++;

            Fp12 f1;
            Fp6 e1 = Q1coeff[idx];
            e1 = e1.mulFp6_24_Fp_01(precP1);
            f1 = mul_Fp2_024_Fp2_024(d1, e1);

            Fp12 f2;
            Fp6 e2 = Q2coeff[idx];
            e2 = e2.mulFp6_24_Fp_01(precP2);
            f2 = mul_Fp2_024_Fp2_024(d2, e2);
            f = f1 * f2;

            idx++;
            bn::Fp6 l1, l2;
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

            d1 = Q1coeff[idx];
            d1 = d1.mulFp6_24_Fp_01(precP1);

            d2 = Q2coeff[idx];
            d2 = d2.mulFp6_24_Fp_01(precP2);
            idx++;

            e1 = Q1coeff[idx];
            e1 = e1.mulFp6_24_Fp_01(precP1);

            e2 = Q2coeff[idx];
            e2 = e2.mulFp6_24_Fp_01(precP2);

            f1 = mul_Fp2_024_Fp2_024(d1, e1);
            f2 = mul_Fp2_024_Fp2_024(d2, e2);
            f *= f1;
            f *= f2;
        }

    }    // namespace components

}    // namespace bn

#endif    // ALGEBRA_PAIRING_ATE_HPP
