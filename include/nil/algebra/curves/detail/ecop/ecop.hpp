//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_ECOP_HPP
#define ALGEBRA_CURVES_ECOP_HPP

#include <stdexcept>
#include <vector>

namespace nil {
    namespace algebra {
        namespace curve {
            namespace detail {

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

            }   // namespace detail 
        }   //  namespace curve
    }   //  namespace algebra
}   //  namespace nil

#endif    // ALGEBRA_CURVES_ECOP_HPP
