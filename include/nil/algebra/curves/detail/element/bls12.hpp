//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_ELEMENT_BLS12_381_HPP
#define ALGEBRA_CURVES_ELEMENT_BLS12_381_HPP

#include <nil/crypto3/algebra/multiexp/bls12_381.hpp>

#include <vector>

namespace nil {
    namespace algebra {
        namespace curve {
            namespace detail {
                template<typename FieldType, std::size_t ModulusBits = FieldType::modulus_bits>
                struct element_bls12 { };

                template<typename FieldType>
                struct element_bls12<FieldType, 381> {

                    FieldType p[3];

                    element_bls12() {
                    }

                    element_bls12(const FieldType &x, const FieldType &y, const FieldType &z) {
                        p[0] = x;
                        p[1] = y;
                        p[2] = z;
                    }

                    element_bls12 normalize() const {
                        FieldType p_out[3];

                        if (is_zero() || p[2] == 1)
                            return;
                        FieldType r;
                        r = p[2].inverse();
                        p[2] = r.square();
                        p[0] *= p[2];
                        r *= p[2];
                        p[1] *= r;
                        p[2] = 1;
                    }

                    /*
                        Jacobi coordinate
                        (p_out[0], p_out[1], p_out[2]) = 2(p[0], p[1], p[2])
                    */
                    element_bls12 dbl() const {
                        FieldType A, B, C, D, E;
                        A = p[0].square();
                        B = p[1].square();
                        C = B.square();
                        D = ((p[0] + B).square() - A - C).dbl();
                        E = A.dbl() + A;

                        out[0] = E.square() - D.dbl();
                        out[1] = E * (D - out[0]) - C.dbl().dbl().dbl();
                        out[2] = (p[1] * p[2]).dbl();
                    }

                    /*
                        Jacobi coordinate
                        (p_out[0], p_out[1], p_out[2]) = (p[0], p[1], p[2]) + (B.p[0], B.p[1], B.p[2])
                    */
                    element_bls12 operator+(const element_bls12 &B) const {
                        FieldType p_out[3];

                        if (p[2].is_zero()) {
                            return element_bls12(B);
                        }
                        if (B.p[2].is_zero()) {
                            return element_bls12(*this);
                        }
                        FieldType Z1Z1, Z2Z2, U1, S1, H, I, J, t3, r, V;

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
                                p_out[2].clear();
                            }
                            return;
                        }

                        I = H.dbl().square();
                        J = H * I;
                        r = t3.dbl();
                        V = U1 * I;
                        p_out[0] = r.square() - J - (V + V);
                        p_out[1] = r * (V - p_out[0]) - (S1 * J).dbl();
                        p_out[2] = ((p[2] + B.p[2]).square() - Z1Z1 - Z2Z2) * H;
                    }

                    element_bls12 operator-(const element_bls12 &B) const {
                        return *this + (-B);
                    }

                    element_bls12 operator-() const {
                        return element_bls12({p[0], -p[1], p[2]});
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
                    element_bls12 operator*(const NumberType N) const {
                        return multi_exp(*this, N);
                    }

                    template<class N>
                    element_bls12 &operator*=(const N &y) {
                        return *this * y;
                    }

                    bool operator==(const element_bls12 &rhs) const {
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

                    bool operator!=(const element_bls12 &rhs) const {
                        return !operator==(rhs);
                    }

                    bool is_zero() const {
                        return p[2].is_zero();
                    }

                    element_bls12 &operator+=(const element_bls12 &rhs) {
                        return *this + rhs;
                    }

                    element_bls12 &operator-=(const element_bls12 &rhs) {
                        return *this - rhs;
                    }
                };

                typedef element_bls12<element_fp2> Ec2;
                typedef element_bls12<element_fp> Ec1;

            }    //  namespace detail
        }        //  namespace curve
    }            //  namespace algebra
}    //  namespace nil

#endif    // ALGEBRA_CURVES_ELEMENT_BLS12_381_HPP
