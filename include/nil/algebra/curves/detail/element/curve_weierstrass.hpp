//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_ELEMENT_CURVE_WEIERSTRASS_HPP
#define ALGEBRA_CURVES_ELEMENT_CURVE_WEIERSTRASS_HPP

//#include <nil/crypto3/algebra/multiexp/curves.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template<typename FieldElementType>
                struct element_curve_weierstrass {

                    FieldElementType p[3];

                    element_curve_weierstrass() {
                    }

                    element_curve_weierstrass(const FieldElementType &x, const FieldElementType &y,
                                              const FieldElementType &z) {
                        p[0] = x;
                        p[1] = y;
                        p[2] = z;
                    }

                    element_curve_weierstrass(const element_curve_weierstrass &B) {
                        p[0] = B.p[0];
                        p[1] = B.p[1];
                        p[2] = B.p[2];
                    }

                    element_curve_weierstrass normalize() const {
                        FieldElementType p_out[3];

                        if (is_zero() || p[2] == 1)
                            return *this;
                        FieldElementType r, r2;
                        r = p[2].inverse();
                        r2 = r.square();
                        p_out[0] = p[0] * r2;        // r2
                        p_out[1] = p[1] * r * r2;    // r3
                        p_out[2] = 1;

                        return element_curve_weierstrass(p_out[0], p_out[1], p_out[2]);
                    }

                    /*
                        Jacobi coordinate
                        (p_out[0], p_out[1], p_out[2]) = 2(p[0], p[1], p[2])
                    */
                    element_curve_weierstrass dbl() const {
                        FieldElementType p_out[3];

                        FieldElementType A, B, C, D, E;
                        A = p[0].square();
                        B = p[1].square();
                        C = B.square();
                        D = ((p[0] + B).square() - A - C).dbl();
                        E = A.dbl() + A;

                        p_out[0] = E.square() - D.dbl();
                        p_out[1] = E * (D - p_out[0]) - C.dbl().dbl().dbl();
                        p_out[2] = (p[1] * p[2]).dbl();

                        return element_curve_weierstrass(p_out[0], p_out[1], p_out[2]);
                    }

                    /*
                        Jacobi coordinate
                        (p_out[0], p_out[1], p_out[2]) = (p[0], p[1], p[2]) + (B.p[0], B.p[1], B.p[2])
                    */
                    element_curve_weierstrass operator+(const element_curve_weierstrass &B) const {
                        FieldElementType p_out[3];

                        if (p[2].is_zero()) {
                            return element_curve_weierstrass(B);
                        }
                        if (B.p[2].is_zero()) {
                            return element_curve_weierstrass(*this);
                        }
                        FieldElementType Z1Z1, Z2Z2, U1, S1, H, I, J, t3, r, V;

                        Z1Z1 = p[2].square();
                        Z2Z2 = B.p[2].square();
                        U1 = p[0] * Z2Z2;
                        S1 = p[1] * B.p[2] * Z2Z2;
                        H = B.p[0] * Z1Z1 - U1;
                        t3 = B.p[1] * p[2] * Z1Z1 - S1;

                        if (H.is_zero()) {
                            if (t3.is_zero()) {
                                return dbl();
                            } else {
                                p_out[2] = FieldElementType::zero();
                            }
                            return *this;
                        }

                        I = H.dbl().square();
                        J = H * I;
                        r = t3.dbl();
                        V = U1 * I;
                        p_out[0] = r.square() - J - (V + V);
                        p_out[1] = r * (V - p_out[0]) - (S1 * J).dbl();
                        p_out[2] = ((p[2] + B.p[2]).square() - Z1Z1 - Z2Z2) * H;

                        return element_curve_weierstrass(p_out[0], p_out[1], p_out[2]);
                    }

                    element_curve_weierstrass operator-(const element_curve_weierstrass &B) const {
                        return *this + (-B);
                    }

                    element_curve_weierstrass operator-() const {
                        return element_curve_weierstrass({p[0], -p[1], p[2]});
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
                    template<typename NumberType>
                    element_curve_weierstrass operator*(const NumberType N) const {
                        // return multi_exp(*this, N);
                        return *this;
                    }

                    template<class N>
                    element_curve_weierstrass &operator*=(const N &y) {
                        element_curve_weierstrass t = *this * y;

                        p[0] = t.p[0];
                        p[1] = t.p[1];
                        p[2] = t.p[2];

                        return *this;
                    }

                    bool operator==(const element_curve_weierstrass &rhs) const {
                        element_curve_weierstrass t0 = normalize();
                        element_curve_weierstrass t1 = rhs.normalize();
                        if (t0.is_zero()) {
                            if (t1.is_zero())
                                return true;
                            return false;
                        }
                        if (t1.is_zero())
                            return false;

                        return t0.p[0] == t1.p[0] && t0.p[1] == t1.p[1];
                    }

                    bool operator!=(const element_curve_weierstrass &rhs) const {
                        return !operator==(rhs);
                    }

                    bool is_zero() const {
                        return p[2].is_zero();
                    }

                    element_curve_weierstrass &operator+=(const element_curve_weierstrass &rhs) {
                        element_curve_weierstrass t = *this + rhs;

                        p[0] = t.p[0];
                        p[1] = t.p[1];
                        p[2] = t.p[2];

                        return *this;
                    }

                    element_curve_weierstrass &operator-=(const element_curve_weierstrass &rhs) {
                        element_curve_weierstrass t = *this - rhs;

                        p[0] = t.p[0];
                        p[1] = t.p[1];
                        p[2] = t.p[2];

                        return *this;
                    }
                };

            }    //  namespace detail
        }        //  namespace curves
    }            //  namespace algebra
}    //  namespace nil

#endif    // ALGEBRA_CURVES_ELEMENT_CURVE_WEIERSTRASS_HPP
