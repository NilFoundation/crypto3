//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BN128_G1_HPP
#define ALGEBRA_CURVES_BN128_G1_HPP

#include <vector>

#include <boost/multiprecision/cpp_int/multiply.hpp>
#include <boost/multiprecision/modular/base_params.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                struct bn128_G1 : public element_bn128<pairing_params<bn128<ModulusBits>>::g1_value_type> {
                    using policy_type = element_bn128<pairing_params<bn128<ModulusBits>>::g1_value_type>;

                    bn128_G1() : policy_type(value_type::one(), value_type::one(), value_type::zero()) {};

                    bn128_G1(value_type X, value_type Y, value_type Z) : policy_type(X, Y, Z) {};

                    bool is_zero() const {
                        return coord[2].is_zero();
                    }

                    bool operator==(const bn128_G1 &other) const {
                        if (is_zero()) {
                            return other.is_zero();
                        }

                        if (other.is_zero()) {
                            return false;
                        }

                        /* now neither is O */

                        value_type Z1sq = coord[2].square();
                        value_type Z2sq = other.coord[2].square();

                        return (Z2sq * coord[0] == Z1sq * other.coord[0]) &&
                               (Z2sq * other.coord[2] * coord[1] == Z1sq * coord[2] * other.coord[1]);
                    }

                    bool operator!=(const bn128_G1 &other) const {
                        return !(operator==(other));
                    }

                    bn128_G1 mixed_add(const bn128_G1 &other) const {
                        if (is_zero()) {
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

                        value_type Z1Z1 = coord[2].square();

                        value_type U2 = other.coord[0] * Z1Z1;

                        value_type S2 = other.coord[1] * coord[2] * Z1Z1;
                        ;    // S2 = Y2*Z1*Z1Z1

                        if (coord[0] == U2 && coord[1] == S2) {
                            // dbl case; nothing of above can be reused
                            return dbl();
                        }

                        bn128_G1 result;
                        value_type H, HH, I, J, r, V, tmp;
                        // H = U2-X1
                        H = U2 - coord[0];
                        // HH = H^2
                        HH = H.square();
                        // I = 4*HH
                        tmp = HH + HH;
                        I = tmp + tmp;
                        // J = H*I
                        J = H * I;
                        // r = 2*(S2-Y1)
                        tmp = S2 - coord[1];
                        r = tmp + tmp;
                        // V = X1*I
                        V = coord[0] * I;
                        // X3 = r^2-J-2*V
                        result.coord[0] = r.square() - J - V - V;
                        // Y3 = r*(V-X3)-2*Y1*J
                        result.coord[1] = r * (V - result.coord[0]);
                        tmp = coord[1] * J;
                        result.coord[1] -= (tmp + tmp);
                        // Z3 = (Z1+H)^2-Z1Z1-HH
                        result.coord[2] = (coord[2] + H).square() - Z1Z1 - HH;

                        return result;
                    }

                    static bn128_G1 zero() {
                        return bn128_G1();
                    }

                    static bn128_G1 one() {
                        return bn128_G1(1, 2, 1);
                    }

                    template<typename NumberType>
                    static NumberType base_field_char() {
                        return arithmetic_params<base_field>::q;
                    }

                    template<typename NumberType>
                    static NumberType order() {
                        return arithmetic_params<scalar_field>::q;
                    }

                private:
                    /* additional parameters for square roots in Fq */
                    value_type bn128_coeff_b = value_type(3);
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_BN128_G1_HPP
