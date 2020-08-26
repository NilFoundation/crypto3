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

                    using underlying_field_type = FieldElementType;

                    underlying_field_type p[3];

                    element_curve_weierstrass() {
                    }

                    element_curve_weierstrass(const underlying_field_type &x, const underlying_field_type &y,
                                              const underlying_field_type &z) {
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
                        underlying_field_type p_out[3];

                        if (is_zero() || p[2] == 1)
                            return *this;
                        underlying_field_type r, r2;
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
                        underlying_field_type p_out[3];

                        underlying_field_type A, B, C, D, E;
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

                        element_curve_weierstrass res = *this;

                        res += B;

                        return res;
                    }

                    element_curve_weierstrass operator-(const element_curve_weierstrass &B) const {

                        element_curve_weierstrass res = *this;

                        res -= B;

                        return res;
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

                    bool operator==(const element_curve_weierstrass &B) const {
                        element_curve_weierstrass t0 = normalize();
                        element_curve_weierstrass t1 = B.normalize();
                        if (t0.is_zero()) {
                            if (t1.is_zero())
                                return true;
                            return false;
                        }
                        if (t1.is_zero())
                            return false;

                        return t0.p[0] == t1.p[0] && t0.p[1] == t1.p[1];
                    }


                    bool operator!=(const element_curve_weierstrass &B) const {
                        return !operator==(B);
                    }

                    bool is_zero() const {
                        return p[2].is_zero();
                    }

                    element_curve_weierstrass operator+=(const element_curve_weierstrass &B) {
                        
                        if (p[2].is_zero()) {
                            return B;
                        }
                        if (B.p[2].is_zero()) {
                            return *this;
                        }
                        underlying_field_type Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, t3, r, V;

                        Z1Z1 = p[2].square();
                        Z2Z2 = B.p[2].square();
                        U1 = p[0] * Z2Z2;
                        U2 = B.p[0] * Z2Z2;

                        S1 = p[1] * B.p[2] * Z2Z2;
                        S2 = B.p[1] * p[2] * Z1Z1;

                        H = U2 - U1;
                        t3 = S2 - S1;

                        if (H.is_zero()) {
                            if (t3.is_zero()) {
                                return dbl();
                            } else {
                                p[2] = underlying_field_type::zero();    //not sure
                            }
                            return *this;
                        }

                        I = H.dbl().square();
                        J = H * I;
                        r = t3.dbl();
                        V = U1 * I;
                        p[0] = r.square() - J - V.dbl();
                        p[1] = r * (V - p[0]) - (S1 * J).dbl();
                        p[2] = ((p[2] + B.p[2]).square() - Z1Z1 - Z2Z2) * H;

                        return *this;

                    }

                    element_curve_weierstrass &operator-=(const element_curve_weierstrass &B) {

                        *this += (-B);

                        return *this;
                    }

                    bn128_g1 mixed_add(const bn128_g1 &other) const {
                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return *this;
                        }

                        // no need to handle points of order 2,4
                        // (they cannot exist in a prime-order subgroup)

                        // check for doubling case

                        // using Jacobian pinates so:
                        // (X1:Y1:Z1) = (X2:Y2:Z2)
                        // iff
                        // X1/Z1^2 == X2/Z2^2 and Y1/Z1^3 == Y2/Z2^3
                        // iff
                        // X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3

                        // we know that Z2 = 1

                        underlying_field_type Z1Z1 = this->p[2].square();

                        underlying_field_type U2 = other.p[0] * Z1Z1;

                        underlying_field_type S2 = other.p[1] * this->p[2] * Z1Z1;
                        ;    // S2 = Y2*Z1*Z1Z1

                        if (this->p[0] == U2 && this->p[1] == S2) {
                            // dbl case; nothing of above can be reused
                            return this->dbl();
                        }

                        bn128_g1 result;
                        underlying_field_type H, HH, I, J, r, V;
                        // H = U2-X1
                        H = U2 - this->p[0];
                        // HH = H^2
                        HH = H.square();
                        // I = 4*HH
                        I = HH.dbl().dbl();
                        // J = H*I
                        J = H * I;
                        // r = 2*(S2-Y1)
                        r = (S2 - this->p[1]).dbl();
                        // V = X1*I
                        V = this->p[0] * I;
                        // X3 = r^2-J-2*V
                        result.p[0] = r.square() - J - V.dbl();
                        // Y3 = r*(V-X3)-2*Y1*J
                        result.p[1] = r * (V - result.p[0]) - (this->p[1] * J).dbl();
                        // Z3 = (Z1+H)^2-Z1Z1-HH
                        result.p[2] = (this->p[2] + H).square() - Z1Z1 - HH;

                        return result;
                    }
                    
                };

            }    //  namespace detail
        }        //  namespace curves
    }            //  namespace algebra
}    //  namespace nil

#endif    // ALGEBRA_CURVES_ELEMENT_CURVE_WEIERSTRASS_HPP
