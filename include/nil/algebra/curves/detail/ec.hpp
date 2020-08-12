//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_EC_HPP
#define ALGEBRA_CURVES_EC_HPP

#include <stdexcept>
#include <vector>

namespace nil {
    namespace algebra {
        namespace curve {

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
                    r = p[2].inverse();
                    p[2] = r.square();
                    p[0] *= p[2];
                    r *= p[2];
                    p[1] *= r;
                    p[2] = 1;
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
            
            typedef EcT<element<fp2>> Ec2;
            typedef EcT<element<fp>> Ec1;


        }   //  namespace curve
    }   //  namespace algebra
}   //  namespace nil

#endif    // ALGEBRA_CURVES_EC_HPP
