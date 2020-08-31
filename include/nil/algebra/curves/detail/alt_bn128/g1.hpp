//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_ALT_BN128_G1_HPP
#define ALGEBRA_CURVES_ALT_BN128_G1_HPP

#include <boost/multiprecision/cpp_int/multiply.hpp>
#include <boost/multiprecision/modular/base_params.hpp>

#include <nil/algebra/curves/detail/element/curve_weierstrass.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template<std::size_t ModulusBits>
                struct alt_bn128_g1 {

                    using policy_type = edwards<ModulusBits>;
                    constexpr static const std::size_t g1_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp<fields::detail::arithmetic_params<fields::alt_bn128_fq<g1_field_bits, CHAR_BIT>>> g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp3<fields::detail::arithmetic_params<fields::alt_bn128_fq<g2_field_bits, CHAR_BIT>>> g2_field_type_value;

                    using underlying_field_type = g1_field_type_value;

                    alt_bn128_g1() : alt_bn128_g1(underlying_field_type::one(), underlying_field_type::one(), underlying_field_type::zero()) {};

                    alt_bn128_g1(underlying_field_type X, underlying_field_type Y, underlying_field_type Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    static alt_bn128_g1 zero() {
                        return alt_bn128_g1();
                    }

                    static alt_bn128_g1 one() {
                        return alt_bn128_g1(1, 2, 1);
                    }

                    bool operator==(const alt_bn128_g1 &other) const {
                        if (this->is_zero()) {
                            return other.is_zero();
                        }

                        if (other.is_zero()) {
                            return false;
                        }

                        /* now neither is O */

                        // using Jacobian coordinates so:
                        // (X1:Y1:Z1) = (X2:Y2:Z2)
                        // iff
                        // X1/Z1^2 == X2/Z2^2 and Y1/Z1^3 == Y2/Z2^3
                        // iff
                        // X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3

                        underlying_field_type Z1_squared = (this->p[2]).squared();
                        underlying_field_type Z2_squared = (other.p[2]).squared();

                        if ((this->p[0] * Z2_squared) != (other.p[0] * Z1_squared)) {
                            return false;
                        }

                        underlying_field_type Z1_cubed = (this->p[2]) * Z1_squared;
                        underlying_field_type Z2_cubed = (other.p[2]) * Z2_squared;

                        if ((this->p[1] * Z2_cubed) != (other.p[1] * Z1_cubed)) {
                            return false;
                        }

                        return true;
                    }

                    bool operator!=(const alt_bn128_g1& other) const {
                        return !(operator==(other));
                    }

                    alt_bn128_g1 operator-() const {
                        return alt_bn128_g1(this->p[0], -(this->p[1]), this->p[2]);
                    }


                    alt_bn128_g1 operator-(const alt_bn128_g1 &other) const {
                        return (*this) + (-other);
                    }

                    alt_bn128_g1 operator+(const alt_bn128_g1 &other) const {
                        // handle special cases having to do with O
                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return *this;
                        }

                        // no need to handle points of order 2,4
                        // (they cannot exist in a prime-order subgroup)

                        // handle double case
                        if (this->operator==(other)) {
                            return this->dbl();
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl

                        underlying_field_type Z1Z1 = (this->p[2]).squared();             // Z1Z1 = Z1^2
                        underlying_field_type Z2Z2 = (other.p[2]).squared();             // Z2Z2 = Z2^2
                        underlying_field_type U1 = (this->p[0]) * Z2Z2;                  // U1 = X1 * Z2Z2
                        underlying_field_type U2 = (other.p[0]) * Z1Z1;                  // U2 = X2 * Z1Z1
                        underlying_field_type S1 = (this->p[1]) * (other.p[2]) * Z2Z2;      // S1 = Y1 * Z2 * Z2Z2
                        underlying_field_type S2 = (other.p[1]) * (this->p[2]) * Z1Z1;      // S2 = Y2 * Z1 * Z1Z1
                        underlying_field_type H = U2 - U1;                            // H = U2-U1
                        underlying_field_type S2_minus_S1 = S2 - S1;
                        underlying_field_type I = H.dbl().squared();                    // I = (2 * H)^2
                        underlying_field_type J = H * I;                              // J = H * I
                        underlying_field_type r = S2_minus_S1.dbl();          // r = 2 * (S2-S1)
                        underlying_field_type V = U1 * I;                             // V = U1 * I
                        underlying_field_type X3 = r.squared() - J - V.dbl();           // X3 = r^2 - J - 2 * V
                        underlying_field_type S1_J = S1 * J;
                        underlying_field_type Y3 = r * (V - X3) - S1_J.dbl();          // Y3 = r * (V-X3)-2 S1 J
                        underlying_field_type Z3 = ((this->p[2] + other.p[2]).squared() - Z1Z1 - Z2Z2) * H; // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2) * H

                        return alt_bn128_g1(X3, Y3, Z3);
                    }

                    alt_bn128_g1 dbl() const {
                    
                        // handle point at infinity
                        if (this->is_zero()) {
                            return (*this);
                        }

                        // no need to handle points of order 2,4
                        // (they cannot exist in a prime-order subgroup)

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

                        underlying_field_type A = (this->p[0]).squared();         // A = X1^2
                        underlying_field_type B = (this->p[1]).squared();        // B = Y1^2
                        underlying_field_type C = B.squared();                // C = B^2
                        underlying_field_type D = (this->p[0] + B).squared() - A - C;
                        D = D+D;                        // D = 2 * ((X1 + B)^2 - A - C)
                        underlying_field_type E = A.dbl() + A;                  // E = 3 * A
                        underlying_field_type F = E.squared();                // F = E^2
                        underlying_field_type X3 = F - D.dbl();                 // X3 = F - 2 D
                        underlying_field_type eightC = C.dbl().dbl().dbl();
                        underlying_field_type Y3 = E * (D - X3) - eightC;     // Y3 = E * (D - X3) - 8 * C
                        underlying_field_type Y1Z1 = (this->p[1])*(this->p[2]);
                        underlying_field_type Z3 = Y1Z1 + Y1Z1;               // Z3 = 2 * Y1 * Z1

                        return alt_bn128_g1(X3, Y3, Z3);
                    }

                    alt_bn128_g1 mixed_add(const alt_bn128_g1 &other) const {

                        // handle special cases having to do with O
                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return *this;
                        }

                        // no need to handle points of order 2,4
                        // (they cannot exist in a prime-order subgroup)

                        // check for doubling case

                        // using Jacobian coordinates so:
                        // (X1:Y1:Z1) = (X2:Y2:Z2)
                        // iff
                        // X1/Z1^2 == X2/Z2^2 and Y1/Z1^3 == Y2/Z2^3
                        // iff
                        // X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3

                        // we know that Z2 = 1

                        const underlying_field_type Z1Z1 = (this->p[2]).squared();

                        const underlying_field_type &U1 = this->p[0];
                        const underlying_field_type U2 = other.p[0] * Z1Z1;

                        const underlying_field_type Z1_cubed = (this->p[2]) * Z1Z1;

                        const underlying_field_type &S1 = (this->p[1]);                // S1 = Y1 * Z2 * Z2Z2
                        const underlying_field_type S2 = (other.p[1]) * Z1_cubed;      // S2 = Y2 * Z1 * Z1Z1

                        if (U1 == U2 && S1 == S2) {
                            // dbl case; nothing of above can be reused
                            return this->dbl();
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
                        underlying_field_type H = U2-(this->p[0]);                         // H = U2-X1
                        underlying_field_type HH = H.squared() ;                        // HH = H&2
                        underlying_field_type I = HH+HH;                                // I = 4*HH
                        I = I + I;
                        underlying_field_type J = H*I;                                  // J = H*I
                        underlying_field_type r = S2-(this->p[1]);                         // r = 2*(S2-Y1)
                        r = r + r;
                        underlying_field_type V = (this->p[0]) * I ;                       // V = X1*I
                        underlying_field_type X3 = r.squared()-J-V-V;                   // X3 = r^2-J-2*V
                        underlying_field_type Y3 = (this->p[1])*J;                         // Y3 = r*(V-X3)-2*Y1*J
                        Y3 = r*(V-X3) - Y3 - Y3;
                        underlying_field_type Z3 = ((this->p[2])+H).squared() - Z1Z1 - HH; // Z3 = (Z1+H)^2-Z1Z1-HH

                        return alt_bn128_g1(X3, Y3, Z3);
                    }



                private:

                    underlying_field_type p[3];

                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_ALT_BN128_G1_HPP
