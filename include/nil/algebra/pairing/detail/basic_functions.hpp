//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_BASIC_FUNCTIONS_HPP
#define ALGEBRA_PAIRING_BASIC_FUNCTIONS_HPP

#include <stdexcept>
#include <vector>

namespace nil{
    namespace algebra{
        namespace pairing{
            namespace detail{

                /*
                    square over Fp4
                    Operation Count:

                    3 * Fp2Dbl::square
                    2 * Fp2Dbl::mod
                    1 * Fp2Dbl::mul_xi == 1 * (2 * Fp2::add/sub) == 2 * Fp2::add/sub
                    3 * Fp2Dbl::add/sub == 3 * (2 * Fp2::add/sub) == 6 * Fp2::add/sub
                    1 * Fp2::add/sub

                    Total:

                    3 * Fp2Dbl::square
                    2 * Fp2Dbl::mod
                    9 * Fp2::add/sub
                 */
                element <fp4> sq_Fp4UseDbl(const element<fp4> &B) {
                    double_element<fp2> T0, T1, T2;
                    element<fp2> z0, z1;
                    T0 = x0.square();
                    T1 = x1.square();
                    T2 = T1.mul_xi();
                    T2 += T0;
                    z1 = x0 + x1;
                    z0 = T2.mod();
                    // overwrite z[0] (position 0).
                    T2 = z1.square();
                    T2 -= T0;
                    T2 -= T1;
                    z1 = T2.mod();
                    return {z0, z1};
                }





            }       // namespace detail
        }       // namespace pairing
    }       // namespace algebra
}    // namespace nil






namespace bn {

    template<class Fp2>
    struct ParamT {
        typedef typename Fp2::Fp Fp;

        using fp_value_type = Fp;
        using fp2_value_type = Fp2;

        using ?? = number_type;

        static mie::Vsint z;
        static mie::Vuint p;
        static mie::Vuint r;
        static mie::Vuint t;         /* trace of Frobenius */
        static mie::Vsint largest_c; /* 6z + 2, the largest coefficient of short vector */
        static fp_value_type Z;
        static fp2_value_type W2p;
        static fp2_value_type W3p;
        static fp2_value_type gammar[5];
        static fp2_value_type gammar2[5];
        static fp2_value_type gammar3[5];
        static fp_value_type i0;    // 0
        static fp_value_type i1;    // 1
        static int b;
        static fp2_value_type b_invxi;    // b/xi of twist E' : Y^2 = X^3 + b/xi
        static fp_value_type half;

        // Loop parameter for the Miller loop part of opt. ate pairing.
        typedef std::vector<signed char> SignVec;
        static SignVec siTbl;
        static bool useNAF;

        static SignVec zReplTbl;


        static inline void init(const CurveParam &cp, int mode = -1, bool useMulx = true) {

            //bool supported = cp == CurveSNARK1 || cp == CurveSNARK2;

            mie::zmInit();
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
            assert(temp.b_.is_zero());

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

    /*
        mul_gamma(z, x) + z += y;
    */
    template<class F, class G>
    void mul_gamma_add(F &z, const F &x, const F &y) {
        G::mul_xi(z.a_, x.c_);
        z.a_ += y.a_;
        G::add(z.b_, x.a_, y.b_);
        G::add(z.c_, x.b_, y.c_);
    }

    /*
        Fp12T = Fp6[w] / (w^2 - v)
        x = a_ + b_ w
    */
    template<class T>
    struct Fp12T : public mie::local::addsubmul<Fp12T<T>> {
                
        void sqru() {
            Fp2 &z0(a_.a_);
            Fp2 &z4(a_.b_);
            Fp2 &z3(a_.c_);
            Fp2 &z2(b_.a_);
            Fp2 &z1(b_.b_);
            Fp2 &z5(b_.c_);
            Fp2 t0, t1;
            sq_Fp4UseDbl(t0, t1, z0, z1);    // a^2 = t0 + t1*y
            // For A
            z0 = t0 - z0;
            z0 += z0;
            z0 += t0;
#if 0
		Fp2_2z_add_3x(z1, t1);
#else
            z1 = (t1 + z1).dbl() + t1;
#endif
            // t0 and t1 are unnecessary from here.
            Fp2 t2, t3;
            sq_Fp4UseDbl(t0, t1, z2, z3);    // b^2 = t0 + t1*y
            sq_Fp4UseDbl(t2, t3, z4, z5);    // c^2 = t2 + t3*y
            // For C
            z4 = (t0 - z4).dbl() + t0;
#if 0
		Fp2_2z_add_3x(z5, t1);
#else
            z5 = (t1 + z5).dbl() + t1;
#endif
            // For B
            Fp2::mul_xi(t0, t3);
#if 0
		Fp2_2z_add_3x(z2, t0);
#else
            z2 = (t0 + z2).dbl() + t0;
#endif
            z3 = (t2 - z3).dbl() + t2;
        }

        /*
            This is same as sqru, but output given reference.
        */
        void sqru(Fp12T &zz) const {
            zz = *this;
            zz.sqru();
        }

        /*
            Final exponentiation based on:
            - Laura Fuentes-Casta{\~n}eda, Edward Knapp, and Francisco
            Rodr\'{\i}guez-Henr\'{\i}quez.
            Faster hashing to $\mathbb{G}_2$.
            SAC 2011, pp. 412--430. doi:10.1007/978-3-642-28496-0_25.

            *this = final_exp(*this)
        */

        static void pow_neg_t(Fp12T &out, const Fp12T &in) {
            out = in;
            Fp12T inConj;
            inConj.a_ = in.a_;
            inConj.b_ = -in.b_;    // in^-1 == in^(p^6)

            for (size_t i = 1; i < Param::zReplTbl.size(); i++) {
                out.sqru();
                if (Param::zReplTbl[i] > 0) {
                    Fp12T::mul(out, out, in);
                } else if (Param::zReplTbl[i] < 0) {
                    Fp12T::mul(out, out, inConj);
                }
            }
            // invert by conjugation
            Fp6::neg(out.b_, out.b_);
        }

        void final_exp() {
            Fp12T f, f2z, f6z, f6z2, f12z3;
            Fp12T a, b;
            Fp12T &z = *this;
            mapToCyclo(f);

            Fp12T::pow_neg_t(f2z, f);
            f2z.sqru();    // f2z = f^(-2*z)
            f2z.sqru(f6z);
            f6z *= f2z;    // f6z = f^(-6*z)
            Fp12T::pow_neg_t(f6z2, f6z);
            // A variable a is unnecessary only here.
            f6z2.sqru(a);
            // Compress::fixed_power(f12z3, a); // f12z3 = f^(-12*z^3)
            Fp12T::pow_neg_t(f12z3, a);
            // It will compute inversion of f2z, thus, conjugation free.
            f6z.b_ = -f6z.b_;        // f6z = f^(6z)
            f12z3.b_ = -f12z3.b_;    // f12z3 = f^(12*z^3)
            // Computes a and b.
            a = f12z3 * f6z2;    // a = f^(12*z^3 + 6z^2)
            a *= f6z;                      // a = f^(12*z^3 + 6z^2 + 6z)
            b = a * f2z;         // b = f^(12*z^3 + 6z^2 + 4z)w
            // @note f2z, f6z, and f12z are unnecessary from here.
            // Last part.
            z = a * f6z2;    // z = f^(12*z^3 + 12z^2 + 6z)
            z *= f;                    // z = f^(12*z^3 + 12z^2 + 6z + 1)
            b.Frobenius(f2z);          // f2z = f^(q(12*z^3 + 6z^2 + 4z))
            z *= f2z;                  // z = f^(q(12*z^3 + 6z^2 + 4z) + (12*z^3 + 12z^2 + 6z + 1))
            a.Frobenius2(f2z);         // f2z = f^(q^2(12*z^3 + 6z^2 + 6z))
            z *= f2z;    // z = f^(q^2(12*z^3 + 6z^2 + 6z) + q(12*z^3 + 6z^2 + 4z) + (12*z^3 + 12z^2 + 6z + 1))
            f.b_ = -f.b_;    // f = -f
            b *= f;                  // b = f^(12*z^3 + 6z^2 + 4z - 1)
            b.Frobenius3(f2z);       // f2z = f^(q^3(12*z^3 + 6z^2 + 4z - 1))
            z *= f2z;
            // z = f^(q^3(12*z^3 + 6z^2 + 4z - 1) +
            // q^2(12*z^3 + 6z^2 + 6z) +
            // q(12*z^3 + 6z^2 + 4z) +
            // (12*z^3 + 12z^2 + 6z + 1))
            // see page 6 in the "Faster hashing to G2" paper

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

            Fp2::mul_xi(g0, t0);
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
        static void squareC(CompressT &z) {
            Fp2 t0, t1, t2;
            Fp2Dbl T0, T1, T2, T3;
            Fp2Dbl::square(T0, z.g4_);
            Fp2Dbl::square(T1, z.g5_);
            // # 7
            Fp2Dbl::mul_xi(T2, T1);
            // # 8
            T2 += T0;
            // # 9
            Fp2Dbl::mod(t2, T2);
            // # 1
            t0 = z.g4_ + z.g5_;
            Fp2Dbl::square(T2, t0);
            // # 2
            T0 += T1;
            //		Fp2Dbl::addNC(T0, T0, T1); // QQQ : OK?
            T2 -= T0;
            // # 3
            Fp2Dbl::mod(t0, T2);
            t1 = z.g2_ + z.g3_;
            Fp2Dbl::square(T3, t1);
            Fp2Dbl::square(T2, z.g2_);
            // # 4
            Fp2::mul_xi(t1, t0);
#if 1    // RRR
            Fp::_3z_add_2xC(z.g2_.a_, t1.a_);
            Fp::_3z_add_2xC(z.g2_.b_, t1.b_);
#else
            // # 5
            z.g2_ += t1;
            z.g2_ += z.g2_;
            // # 6
            z.g2_ += t1;
#endif
            t1 = t2 - z.g3_;
            t1 += t1;
            // # 11 !!!!
            Fp2Dbl::square(T1, z.g3_);
            // # 10 !!!!
            z.g3_ = t1 + t2;
            // # 12
            Fp2Dbl::mul_xi(T0, T1);
            // # 13
            T0 += T2;
            //		Fp2Dbl::addNC(T0, T0, T2); // QQQ : OK?
            // # 14
            Fp2Dbl::mod(t0, T0);
            z.g4_ = t0 - z.g4_;
            z.g4_ += z.g4_;
            // # 15
            z.g4_ += t0;
            // # 16
            Fp2Dbl::addNC(T2, T2, T1);
            T3 -= T2;
            // # 17
            Fp2Dbl::mod(t0, T3);
#if 1    // RRR
            Fp::_3z_add_2xC(z.g5_.a_, t0.a_);
            Fp::_3z_add_2xC(z.g5_.b_, t0.b_);
#else
            z.g5_ += t0;
            z.g5_ += z.g5_;
            z.g5_ += t0;    // # 18
#endif
        }
        static void square_nC(CompressT &z, int n) {
            for (int i = 0; i < n; i++) {
                squareC(z);
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

    namespace ecop {

        /*
            @memo Jacobian coordinates: Y^2 = X^3 + b*Z^6
        */
        template<class Fp>
        inline bool isOnECJac3(const Fp *P) {
            typedef Fp2T<Fp> Fp2;
            typedef ParamT<Fp2> Param;
            if (P[2] == 0)
                return true;

            Fp Z6p_2;
            Z6p_2 = P[2].square();
            Z6p_2 *= P[2];
            Z6p_2 = Z6p_2.square();
            Z6p_2 *= Param::b;
            return P[1] * P[1] == P[0] * P[0] * P[0] + Z6p_2;
        }

        /*
            @memo Y^2=X^3+b
            Homogeneous.
        */
        template<class Fp>
        inline bool isOnECHom2(const Fp *P) {
            typedef Fp2T<Fp> Fp2;
            typedef ParamT<Fp2> Param;
            return P[1] * P[1] == P[0] * P[0] * P[0] + Param::b;
        }

        /*
            @memo Y^2=X^3+b
            Homogeneous.
        */
        template<class Fp>
        inline bool isOnECHom3(const Fp *P) {
            typedef Fp2T<Fp> Fp2;
            typedef ParamT<Fp2> Param;
            if (P[2] == 0)
                return true;

            return P[1] * P[1] * P[2] == P[0] * P[0] * P[0] + P[2].square() * P[2] * Param::b;
        }

        /*
            @memo Y^2=X^3+b/xi
        */
        template<class Fp>
        inline bool isOnTwistECJac3(const Fp2T<Fp> *P) {
            typedef Fp2T<Fp> Fp2;
            typedef ParamT<Fp2> Param;

            if (P[2] == 0)
                return true;
            
            return P[1] * P[1] == P[0] * P[0] * P[0] + ((P[2].square() * P[2]).square()) * Param::b_invxi;
        }

        /*
            @memo Y^2=X^3+b/xi
            Homogeneous.
        */
        template<class Fp>
        inline bool isOnTwistECHom2(const Fp2T<Fp> *P) {
            typedef Fp2T<Fp> Fp2;
            typedef ParamT<Fp2> Param;
            return P[1] * P[1] == (P[0] * P[0] * P[0] + Param::b_invxi);
        }

        /*
            @memo Y^2=X^3+b/xi
            Homogeneous.
        */
        template<class Fp>
        inline bool isOnTwistECHom3(const Fp2T<Fp> *P) {
            typedef Fp2T<Fp> Fp2;
            typedef ParamT<Fp2> Param;
            if (P[2] == 0)
                return true;
            return P[1] * P[1] * P[2] == (P[0] * P[0] * P[0] + Param::b_invxi * P[2] * P[2] * P[2]);
        }

        /*
            For Jacobian coordinates
        */
        template<class FF>
        inline void NormalizeJac(FF *out, const FF *in) {
            if (in[2] == 0) {
                out[0].clear();
                out[1].clear();
                out[2].clear();
            } else if (in[2] == 1) {
                copy(out, in);
            } else {
                FF A, AA;
                
                A = in[2].inverse();
                AA = A.square();

                out[0] = in[0] * AA;
                out[1] = in[1] * AA * A;
                out[2] = 1;
            }
        }

        /*
            For Homogeneous
        */
        template<class FF>
        inline void NormalizeHom(FF *out, const FF *in) {
            if (in[2] == 0) {
                out[0].clear();
                out[1].clear();
                out[2].clear();
            } else if (in[2] == 1) {
                copy(out, in);
            } else {
                FF A = in[2];
                A = A.inverse();
                out[0] = in[0] * A;
                out[1] = in[1] * A;
                out[2] = 1;
            }
        }

        /*
            Jacobi coordinate
            (out[0], out[1], out[2]) = 2(in[0], in[1], in[2])
        */
        template<class FF>
        inline void ECDouble(FF *out, const FF *in) {
            FF A, B, C, D, E;
            A = in[0].square();
            B = in[1].square();
            C = B.square();
            D = ((in[0] + B).square() - A - C).dbl();
            E = A.dbl() + A;

            out[0] = E.square() - D.dbl();
            out[1] = E * (D - out[0]) - C.dbl().dbl().dbl();
            out[2] = (in[1] * in[2]).dbl();
        }

        /*
            Jacobi coordinate
            (out[0], out[1], out[2]) = (a[0], a[1], a[2]) + (b[0], b[1], b[2])
        */
        template<class FF>
        inline void ECAdd(FF *out, const FF *a, const FF *b) {
            if (a[2].is_zero()) {
                copy(out, b);
                return;
            }
            if (b[2].is_zero()) {
                copy(out, a);
                return;
            }
            FF Z1Z1, Z2Z2, U1, S1, H, I, J, t3, r, V;

            Z1Z1 = a[2].square();
            Z2Z2 = b[2].square();
            U1 = a[0] * Z2Z2;
            S1 = a[1] * b[2] * Z2Z2;
            H = b[0] * Z1Z1 - U1;
            t3 = b[1] * a[2] * Z1Z1 - S1;

            if (H.is_zero()) {
                if (t3.is_zero()) {
                    ECDouble(out, a);
                } else {
                    out[2].clear();
                }
                return;
            }

            I = H.dbl().square();
            J = H * I;
            r = t3.dbl();
            V = U1 * I;
            out[0] = r.square() - J - (V + V);
            out[1] = r * (V - out[0]) - (S1 * J).dbl();
            out[2] = ((a[2] + b[2]).square() - Z1Z1 - Z2Z2) * H;
        }

        /*
            out = in * m
            @param out [out] Jacobi coord (out[0], out[1], out[2])
            @param in [in] Jacobi coord (in[0], in[1], in[2])
            @param m [in] scalar
            @note MSB first binary method.

            @note don't use Fp as INT
            the inner format of Fp is not compatible with mie::Vuint
        */
        template<class FF, class INT>
        inline void ScalarMult(FF *out, const FF *in, const INT &m) {
            typedef typename mie::util::IntTag<INT> Tag;
            typedef typename Tag::value_type value_type;

            if (m == 0) {
                out[0].clear();
                out[1].clear();
                out[2].clear();
                return;
            }
            FF inCopy[3];
            if (out == in) {
                ecop::copy(inCopy, in);
                in = inCopy;
            }

            const int mSize = (int)Tag::getBlockSize(m);
            const int vSize = (int)sizeof(value_type) * 8;
            const value_type mask = value_type(1) << (vSize - 1);
            assert(mSize > 0);    // if mSize == 0, it had been returned.
            /*
                Extract and process for MSB of most significant word.
            */
            value_type v = Tag::getBlock(m, mSize - 1);
            int j = 0;

            while ((v != 0) && (!(v & mask))) {
                v <<= 1;
                ++j;
            }

            v <<= 1;
            ++j;
            ecop::copy(out, in);
            /*
                Process for most significant word.
            */
            for (; j != vSize; ++j, v <<= 1) {
                ECDouble(out, out);
                if (v & mask) {
                    ECAdd(out, out, in);
                }
            }

            /*
                Process for non most significant words.
            */
            for (int i = mSize - 2; i >= 0; --i) {
                v = Tag::getBlock(m, i);
                for (j = 0; j != vSize; ++j, v <<= 1) {
                    ECDouble(out, out);
                    if (v & mask) {
                        ECAdd(out, out, in);
                    }
                }
            }
        }

        template<class Fp>
        void FrobEndOnTwist_1(Fp2T<Fp> *Q, const Fp2T<Fp> *P) {
            typedef Fp2T<Fp> Fp2;
            typedef ParamT<Fp2> Param;
            // applying Q[0] <- P[0]^q

            Q[0].a_ = P[0].a_;
            Q[0].b_ = -P[0].b_;

            // Q[0] *= xi^((p-1)/3)
            Q[0] *= Param::gammar[1];

            // applying Q[1] <- P[1]^q
            Q[1].a_ = P[1].a_;
            Q[1].b_ = -P[1].b_;

            // Q[1] *= xi^((p-1)/2)
            Q[1] *= Param::gammar[2];

        }

        template<class Fp>
        void FrobEndOnTwist_2(Fp2T<Fp> *Q, const Fp2T<Fp> *P) {

            Fp2T<Fp> scratch[2];
            FrobEndOnTwist_1(scratch, P);
            FrobEndOnTwist_1(Q, scratch);

        }

        template<class Fp>
        void FrobEndOnTwist_8(Fp2T<Fp> *Q, const Fp2T<Fp> *P) {

            Fp2T<Fp> scratch2[2], scratch4[2], scratch6[2];
            FrobEndOnTwist_2(scratch2, P);
            FrobEndOnTwist_2(scratch4, scratch2);
            FrobEndOnTwist_2(scratch6, scratch4);
            FrobEndOnTwist_2(Q, scratch6);

        }

    }    // namespace ecop

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
            Fp2::neg(Qneg[1], Q[1]);
        }
        // at 1.
        Fp6 d;
        Fp6::pointDblLineEval(d, T, P);
        Fp6 e;
        assert(Param::siTbl[1] == 1);
        Fp6::pointAddLineEval(e, T, Q, P);
        Fp12::Dbl::mul_Fp2_024_Fp2_024(f, d, e);
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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4127) /* const condition */
#endif

    template<class T>
    class EcT {
    public:
        mutable T p[3];
        EcT() {
        }
        EcT(const T &x, const T &y, bool verify = true) {
            set(x, y, verify);
        }
        EcT(const T &x, const T &y, const T &z, bool verify = true) {
            set(x, y, z, verify);
        }
        void normalize() const {
            if (is_zero() || p[2] == 1)
                return;
            T r;
            r = p[2];
            r.inverse();
            p[2] = r.square();
            p[0] *= p[2];
            r *= p[2];
            p[1] *= r;
            p[2] = 1;
        }

        bool isValid() const;

        void set(const T &x, const T &y, bool verify = true) {
            p[0] = x;
            p[1] = y;
            p[2] = 1;
            if (verify && !isValid()) {
                throw std::runtime_error("set(x, y) : bad point");
            }
        }
        void set(const T &x, const T &y, const T &z, bool verify = true) {
            p[0] = x;
            p[1] = y;
            p[2] = z;
            if (verify && !isValid()) {
                throw std::runtime_error("set(x, y, z) : bad point");
            }
        }
        void clear() {
            p[0].clear();
            p[1].clear();
            p[2].clear();
        }

        static inline void dbl(EcT &R, const EcT &P) {
            ecop::ECDouble(R.p, P.p);
        }
        static inline void add(EcT &R, const EcT &P, const EcT &Q) {
            ecop::ECAdd(R.p, P.p, Q.p);
        }
        static inline void sub(EcT &R, const EcT &P, const EcT &Q) {
            EcT negQ;
            neg(negQ, Q);
            add(R, P, negQ);
        }
        static inline void neg(EcT &R, const EcT &P) {
            R.p[0] = P.p[0];
            T::neg(R.p[1], P.p[1]);
            R.p[2] = P.p[2];
        }
        template<class N>
        static inline void mul(EcT &R, const EcT &P, const N &y) {
            ecop::ScalarMult(R.p, P.p, y);
        }
        template<class N>
        EcT &operator*=(const N &y) {
            *this *= y;
            return *this;
        }
        template<class N>
        EcT operator*(const N &y) const {
            EcT c;
            mul(c, *this, y);
            return c;
        }
        bool operator==(const EcT &rhs) const {
            normalize();
            rhs.normalize();
            if (is_zero()) {
                if (rhs.is_zero())
                    return true;
                return false;
            }
            if (rhs.is_zero())
                return false;
            return p[0] == rhs.p[0] && p[1] == rhs.p[1];
        }
        bool operator!=(const EcT &rhs) const {
            return !operator==(rhs);
        }
        bool is_zero() const {
            return p[2].is_zero();
        }
        EcT &operator+=(const EcT &rhs) {
            add(*this, *this, rhs);
            return *this;
        }
        EcT &operator-=(const EcT &rhs) {
            sub(*this, *this, rhs);
            return *this;
        }
        friend EcT operator+(const EcT &a, const EcT &b) {
            EcT c;
            EcT::add(c, a, b);
            return c;
        }
        friend EcT operator-(const EcT &a, const EcT &b) {
            EcT c;
            EcT::sub(c, a, b);
            return c;
        }
    };

#ifdef _MSC_VER
#pragma warning(pop)
#endif

    typedef mie::Fp Fp;
    typedef Fp::Dbl FpDbl;
    typedef Fp2T<Fp> Fp2;
    typedef Fp2::Dbl Fp2Dbl;
    typedef ParamT<Fp2> Param;
    typedef Fp6T<Fp2> Fp6;
    typedef Fp6::Dbl Fp6Dbl;
    typedef Fp12T<Fp6> Fp12;
    typedef Fp12::Dbl Fp12Dbl;
    typedef CompressT<Fp2> Compress;

    typedef EcT<Fp2> Ec2;
    typedef EcT<Fp> Ec1;

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

    /*
        see https://github.com/herumi/ate-pairing/blob/master/test/bn.cpp
    */
    namespace components {

        /*
            inQ[3] : permit not-normalized
        */
        inline void precomputeG2(std::vector<Fp6> &coeff, Fp2 Q[3], const Fp2 inQ[3]) {
            coeff.clear();
            bn::ecop::NormalizeJac(Q, inQ);

            Fp2 T[3];
            T[0] = Q[0];
            T[1] = Q[1];
            T[2] = Fp2(1);
            Fp2 Qneg[2];
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
            Fp2 Q1[2];
            bn::ecop::FrobEndOnTwist_1(Q1, Q);
            Fp2 Q2[2];

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
            assert(Param::siTbl[1] == 1);
            size_t idx = 0;

            Fp6 d = Qcoeff[idx];
            Fp6::mulFp6_24_Fp_01(d, precP);
            idx++;

            Fp6 e = Qcoeff[idx];
            Fp6::mulFp6_24_Fp_01(e, precP);
            Fp12::Dbl::mul_Fp2_024_Fp2_024(f, d, e);

            idx++;
            bn::Fp6 l;
            for (size_t i = 2; i < Param::siTbl.size(); i++) {
                l = Qcoeff[idx];
                idx++;
                f = f.square();
                Fp6::mulFp6_24_Fp_01(l, precP);

                Fp12::Dbl::mul_Fp2_024(f, l);

                if (Param::siTbl[i]) {
                    l = Qcoeff[idx];
                    idx++;
                    Fp6::mulFp6_24_Fp_01(l, precP);
                    Fp12::Dbl::mul_Fp2_024(f, l);
                }
            }

            Fp12 ft;

            d = Qcoeff[idx];
            Fp6::mulFp6_24_Fp_01(d, precP);
            idx++;

            e = Qcoeff[idx];
            Fp6::mulFp6_24_Fp_01(e, precP);

            Fp12::Dbl::mul_Fp2_024_Fp2_024(ft, d, e);
            f *= ft;
        }

        inline void millerLoop2(Fp12 &f, const std::vector<Fp6> &Q1coeff, const Fp precP1[2],
                                const std::vector<Fp6> &Q2coeff, const Fp precP2[2]) {
            assert(Param::siTbl[1] == 1);
            size_t idx = 0;

            Fp6 d1 = Q1coeff[idx];
            Fp6::mulFp6_24_Fp_01(d1, precP1);
            Fp6 d2 = Q2coeff[idx];
            Fp6::mulFp6_24_Fp_01(d2, precP2);
            idx++;

            Fp12 f1;
            Fp6 e1 = Q1coeff[idx];
            Fp6::mulFp6_24_Fp_01(e1, precP1);
            Fp12::Dbl::mul_Fp2_024_Fp2_024(f1, d1, e1);

            Fp12 f2;
            Fp6 e2 = Q2coeff[idx];
            Fp6::mulFp6_24_Fp_01(e2, precP2);
            Fp12::Dbl::mul_Fp2_024_Fp2_024(f2, d2, e2);
            f = f1 * f2;

            idx++;
            bn::Fp6 l1, l2;
            for (size_t i = 2; i < Param::siTbl.size(); i++) {
                l1 = Q1coeff[idx];
                l2 = Q2coeff[idx];
                idx++;
                f = f.square();

                Fp6::mulFp6_24_Fp_01(l1, precP1);
                Fp6::mulFp6_24_Fp_01(l2, precP2);

                Fp12::Dbl::mul_Fp2_024_Fp2_024(f1, l1, l2);
                Fp12::mul(f, f, f1);

                if (Param::siTbl[i]) {
                    l1 = Q1coeff[idx];
                    l2 = Q2coeff[idx];
                    idx++;
                    Fp6::mulFp6_24_Fp_01(l1, precP1);
                    Fp6::mulFp6_24_Fp_01(l2, precP2);
                    Fp12::Dbl::mul_Fp2_024_Fp2_024(f1, l1, l2);
                    Fp12::mul(f, f, f1);
                }
            }

            d1 = Q1coeff[idx];
            Fp6::mulFp6_24_Fp_01(d1, precP1);

            d2 = Q2coeff[idx];
            Fp6::mulFp6_24_Fp_01(d2, precP2);
            idx++;

            e1 = Q1coeff[idx];
            Fp6::mulFp6_24_Fp_01(e1, precP1);

            e2 = Q2coeff[idx];
            Fp6::mulFp6_24_Fp_01(e2, precP2);

            Fp12::Dbl::mul_Fp2_024_Fp2_024(f1, d1, e1);
            Fp12::Dbl::mul_Fp2_024_Fp2_024(f2, d2, e2);
            f *= f1;
            f *= f2;
        }

    }    // namespace components

}    // namespace bn

#endif    // ALGEBRA_PAIRING_BASIC_FUNCTIONS_HPP
