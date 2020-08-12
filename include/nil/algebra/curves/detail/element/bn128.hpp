//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_ELEMENT_BN128_HPP
#define ALGEBRA_CURVES_ELEMENT_BN128_HPP

#include <stdexcept>
#include <vector>

namespace nil {
    namespace algebra {
        namespace curve {

            template<class T>
            struct element_bn128 {
                mutable T p[3];
                element_bn128() {
                }

                element_bn128(const T &x, const T &y, bool verify = true) {
                    set(x, y, verify);
                }

                element_bn128(const T &x, const T &y, const T &z, bool verify = true) {
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

                static inline void dbl(element_bn128 &R, const element_bn128 &P) {
                    ecop::ECDouble(R.p, P.p);
                }

                element_bn128 operator+(const element_bn128 &B) const {
                static inline void add(element_bn128 &R, const element_bn128 &P, const element_bn128 &Q) {
                    ecop::ECAdd(R.p, P.p, Q.p);
                }

                element_bn128 operator-(const element_bn128 &B) const {
                static inline void sub(element_bn128 &R, const element_bn128 &P, const element_bn128 &Q) {
                    element_bn128 negQ;
                    neg(negQ, Q);
                    add(R, P, negQ);
                }

                element_bn128 operator-() const {
                static inline void neg(element_bn128 &R, const element_bn128 &P) {
                    R.p[0] = P.p[0];
                    T::neg(R.p[1], P.p[1]);
                    R.p[2] = P.p[2];
                }

                template<class N>
                element_bn128 operator*(const element_bn128 &B) const {
                static inline void mul(element_bn128 &R, const element_bn128 &P, const N &y) {
                    ecop::ScalarMult(R.p, P.p, y);
                }
                template<class N>
                element_bn128 &operator*=(const N &y) {
                    return *this * y;
                }
                template<class N>
                element_bn128 operator*(const N &y) const {
                    element_bn128 c;
                    mul(c, *this, y);
                    return c;
                }
                bool operator==(const element_bn128 &rhs) const {
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
                bool operator!=(const element_bn128 &rhs) const {
                    return !operator==(rhs);
                }
                bool is_zero() const {
                    return p[2].is_zero();
                }
                element_bn128 &operator+=(const element_bn128 &rhs) {
                    return *this + rhs;
                }
                element_bn128 &operator-=(const element_bn128 &rhs) {
                    return *this - rhs;
                }
            };
            
            typedef element_bn128<element_fp2> Ec2;
            typedef element_bn128<element_fp> Ec1;


        }   //  namespace curve
    }   //  namespace algebra
}   //  namespace nil

#endif    // ALGEBRA_CURVES_ELEMENT_BN128_HPP
