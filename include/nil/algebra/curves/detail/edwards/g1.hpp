//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_EDWARDS_G1_HPP
#define ALGEBRA_CURVES_EDWARDS_G1_HPP

#include <boost/multiprecision/cpp_int/multiply.hpp>
#include <boost/multiprecision/modular/base_params.hpp>

#include <nil/algebra/curves/detail/element/curve_weierstrass.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template<typename PairingParams>
                struct edwards_g1 : public element_curve_weierstrass<typename PairingParams::g1_type> {

                    using policy_type = PairingParams;
                    using element_type = element_curve_weierstrass<typename policy_type::g1_type>;
                    using underlying_field_type = typename element_type::underlying_field_type;

                    edwards_g1() : element_type(underlying_field_type::one(), underlying_field_type::one(), underlying_field_type::zero()) {};

                    edwards_g1(underlying_field_type X, underlying_field_type Y, underlying_field_type Z) : element_type(X, Y, Z) {};

                    edwards_g1(underlying_field_type X, underlying_field_type Y, underlying_field_type Z) : element_type(X, Y, X*Y) {};

                    static edwards_g1 zero() {
                        return edwards_g1(underlying_field_type::zero(), underlying_field_type::one());
                    }

                    static edwards_g1 one() {
                        return edwards_g1(0x26C5DF4587AA6A5D345EFC9F2D47F8B1656517EF618F7A_cppui182,
                                            0x32D83D8AAA0C500F57B15FDA90B1AD111067F812C7DD27_cppui182);
                    }

                    bool edwards_g1::operator==(const edwards_g1 &B) const{
                        if (this->is_zero()){
                            return B.is_zero();
                        }

                        if (B.is_zero()){
                            return false;
                        }

                        /* now neither is O */

                        // X1/Z1 = X2/Z2 <=> X1*Z2 = X2*Z1
                        if ((this->p[0] * B.p[2]) != (B.p[0] * this->p[2])){
                            return false;
                        }

                        // Y1/Z1 = Y2/Z2 <=> Y1*Z2 = Y2*Z1
                        if ((this->p[1] * B.p[2]) != (B.p[1] * this->p[2])){
                            return false;
                        }

                        return true;
                    }

                    edwards_g1 operator+ (const edwards_g1 &B) const {

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-add-2007-bl

                        underlying_field_type A = (this->p[2]) * (other.p[2]);                   // A = Z1*Z2
                        underlying_field_type B = edwards_coeff_d * A.square();           // B = d*A^2
                        underlying_field_type C = (this->p[0]) * (other.p[0]);                   // C = X1*X2
                        underlying_field_type D = (this->p[1]) * (other.p[1]);                   // D = Y1*Y2
                        underlying_field_type E = C * D;                                   // E = C*D
                        underlying_field_type H = C - D;                                   // H = C-D
                        underlying_field_type I = (this->p[0]+this->p[1]) * (other.p[0] + other.p[1])-C-D; // I = (X1+Y1)*(X2+Y2)-C-D
                        underlying_field_type X3 = (E+B)*H;                                // X3 = c*(E+B)*H
                        underlying_field_type Y3 = (E-B)*I;                                // Y3 = c*(E-B)*I
                        underlying_field_type Z3 = A*H*I;                                  // Z3 = A*H*I

                        return edwards_g1(X3, Y3, Z3);
                    }

                    edwards_G1 dbl() const{
                    
                        if (this->is_zero())
                        {
                            return (*this);
                        }
                        else
                        {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#doubling-dbl-2007-bl

                            underlying_field_type A = (this->p[0]).square();                      // A = X1^2
                            underlying_field_type B = (this->p[1]).square();                      // B = Y1^2
                            underlying_field_type C = A+B;                                      // C = A+B
                            underlying_field_type D = A-B;                                      // D = A-B
                            underlying_field_type E = (this->p[0]+this->p[1]).square()-C;            // E = (X1+Y1)^2-C
                            underlying_field_type X3 = C*D;                                     // X3 = C*D
                            underlying_field_type dZZ = edwards_coeff_d * this->p[2].square();
                            underlying_field_type Y3 = E*(C-dZZ-dZZ);                           // Y3 = E*(C-2*d*Z1^2)
                            underlying_field_type Z3 = D*E;                                     // Z3 = D*E

                            return edwards_g1(X3, Y3, Z3);
                        }
                    }

                private:
                    /* additional parameters for square roots in Fq */
                    underlying_field_type bn128_coeff_b = underlying_field_type(3);
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_EDWARDS_G1_HPP
