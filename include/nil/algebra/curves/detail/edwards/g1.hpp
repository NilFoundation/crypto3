//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_EDWARDS_G1_HPP
#define ALGEBRA_CURVES_EDWARDS_G1_HPP

#include <nil/algebra/curves/detail/edwards/basic_policy.hpp>
#include <nil/algebra/curves/detail/edwards/g2.hpp>

#include <nil/algebra/fields/fp3.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                struct edwards_g1 {

                    using policy_type = edwards_basic_policy<ModulusBits, GeneratorBits>;
                    constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                    typedef typename policy_type::base_field_type::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = policy_type::base_field_bits;
                    typedef typename fields::fp3<typename policy_type::base_field_type>::value_type g2_field_type_value;

                    using underlying_field_type_value = g1_field_type_value;

                    underlying_field_type_value p[3];

                    edwards_g1() :
                        edwards_g1(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                   underlying_field_type_value::zero()) {};
                    // must be
                    // edwards_g1() : edwards_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    // when constexpr fields will be finished

                    edwards_g1(underlying_field_type_value X, underlying_field_type_value Y,
                               underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    edwards_g1(underlying_field_type_value X, underlying_field_type_value Y) :
                        edwards_g1(X, Y, X * Y) {};

                    static edwards_g1 zero() {
                        return edwards_g1();
                    }

                    static edwards_g1 one() {
                        return edwards_g1(
                            underlying_field_type_value(0x26C5DF4587AA6A5D345EFC9F2D47F8B1656517EF618F7A_cppui182),
                            underlying_field_type_value(
                                0x32D83D8AAA0C500F57B15FDA90B1AD111067F812C7DD27_cppui182));    // it's better to
                                                                                                // precompute also
                                                                                                // one_fill[2]
                        // must be
                        // return edwards_g1(one_fill[0], one_fill[1]);    // it's better to precompute also one_fill[2]
                        // when constexpr fields will be finished
                    }

                    bool operator==(const edwards_g1 &other) const {
                        if (this->is_zero()) {
                            return other.is_zero();
                        }

                        if (other.is_zero()) {
                            return false;
                        }

                        /* now neither is O */

                        // X1/Z1 = X2/Z2 <=> X1*Z2 = X2*Z1
                        if ((this->p[0] * other.p[2]) != (other.p[0] * this->p[2])) {
                            return false;
                        }

                        // Y1/Z1 = Y2/Z2 <=> Y1*Z2 = Y2*Z1
                        if ((this->p[1] * other.p[2]) != (other.p[1] * this->p[2])) {
                            return false;
                        }

                        return true;
                    }

                    bool operator!=(const edwards_g1 &other) const {
                        return !(operator==(other));
                    }

                    bool is_zero() const {
                        return (this->p[1].is_zero() && this->p[2].is_zero());
                    }

                    edwards_g1 operator+(const edwards_g1 &other) const {

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-add-2007-bl

                        underlying_field_type_value A = (this->p[2]) * (other.p[2]);    // A = Z1*Z2
                        underlying_field_type_value B = d * A.squared();                // B = d*A^2
                        underlying_field_type_value C = (this->p[0]) * (other.p[0]);    // C = X1*X2
                        underlying_field_type_value D = (this->p[1]) * (other.p[1]);    // D = Y1*Y2
                        underlying_field_type_value E = C * D;                          // E = C*D
                        underlying_field_type_value H = C - D;                          // H = C-D
                        underlying_field_type_value I =
                            (this->p[0] + this->p[1]) * (other.p[0] + other.p[1]) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                        underlying_field_type_value X3 = (E + B) * H;                         // X3 = c*(E+B)*H
                        underlying_field_type_value Y3 = (E - B) * I;                         // Y3 = c*(E-B)*I
                        underlying_field_type_value Z3 = A * H * I;                           // Z3 = A*H*I

                        return edwards_g1(X3, Y3, Z3);
                    }

                    edwards_g1 operator-() const {
                        return edwards_g1(-(this->p[0]), this->p[1], this->p[2]);
                    }

                    edwards_g1 operator-(const edwards_g1 &B) const {
                        return (*this) + (-B);
                    }

                    edwards_g1 doubled() const {

                        if (this->is_zero()) {
                            return (*this);
                        } else {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#doubling-dbl-2007-bl

                            underlying_field_type_value A = (this->p[0]).squared();    // A = X1^2
                            underlying_field_type_value B = (this->p[1]).squared();    // B = Y1^2
                            underlying_field_type_value C = A + B;                     // C = A+B
                            underlying_field_type_value D = A - B;                     // D = A-B
                            underlying_field_type_value E =
                                (this->p[0] + this->p[1]).squared() - C;    // E = (X1+Y1)^2-C
                            underlying_field_type_value X3 = C * D;         // X3 = C*D
                            underlying_field_type_value dZZ = d * this->p[2].squared();
                            underlying_field_type_value Y3 = E * (C - dZZ - dZZ);    // Y3 = E*(C-2*d*Z1^2)
                            underlying_field_type_value Z3 = D * E;                  // Z3 = D*E

                            return edwards_g1(X3, Y3, Z3);
                        }
                    }

                    edwards_g1 mixed_add(const edwards_g1 &other) const {

                        // handle special cases having to do with O
                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return *this;
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-madd-2007-lb

                        underlying_field_type_value A = this->p[2];                     // A = Z1
                        underlying_field_type_value B = d * A.squared();                // B = d*A^2
                        underlying_field_type_value C = (this->p[0]) * (other.p[0]);    // C = X1*X2
                        underlying_field_type_value D = (this->p[1]) * (other.p[1]);    // D = Y1*Y2
                        underlying_field_type_value E = C * D;                          // E = C*D
                        underlying_field_type_value H = C - D;                          // H = C-D
                        underlying_field_type_value I =
                            (this->p[0] + this->p[1]) * (other.p[0] + other.p[1]) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                        underlying_field_type_value X3 = (E + B) * H;                         // X3 = c*(E+B)*H
                        underlying_field_type_value Y3 = (E - B) * I;                         // Y3 = c*(E-B)*I
                        underlying_field_type_value Z3 = A * H * I;                           // Z3 = A*H*I

                        return edwards_g1(X3, Y3, Z3);
                    }

                    void to_affine_coordinates() {
                        if (this->is_zero()) {
                            this->p[0] = underlying_field_type_value::zero();
                            this->p[1] = underlying_field_type_value::one();
                            this->p[2] = underlying_field_type_value::one();
                        } else {
                            // go from inverted coordinates to projective coordinates
                            underlying_field_type_value tX = this->p[1] * this->p[2];
                            underlying_field_type_value tY = this->p[0] * this->p[2];
                            underlying_field_type_value tZ = this->p[0] * this->p[1];
                            // go from projective coordinates to affine coordinates
                            underlying_field_type_value tZ_inv = tZ.inversed();
                            this->p[0] = tX * tZ_inv;
                            this->p[1] = tY * tZ_inv;
                            this->p[2] = underlying_field_type_value::one();
                        }
                    }

                    void to_special() {
                        if (this->p[2].is_zero()) {
                            return;
                        }

                        underlying_field_type_value Z_inv = this->p[2].inversed();
                        this->p[0] = this->p[0] * Z_inv;
                        this->p[1] = this->p[1] * Z_inv;
                        this->p[2] = underlying_field_type_value::one();
                    }

                    bool is_special() const {
                        return (this->is_zero() || this->p[2] == underlying_field_type_value::one());
                    }

                private:
                    /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                    /*constexpr static */ const g1_field_type_value d = g1_field_type_value(policy_type::d);

                    /*constexpr static const g2_field_type_value
                        twist = g2_field_type_value(typename g2_field_type_value::underlying_type::zero(),
                                                    typename g2_field_type_value::underlying_type::one(),
                                                    typename g2_field_type_value::underlying_type::zero());
                    constexpr static const g2_field_type_value twist_coeff_a = twist.mul_by_Fp(a);
                    constexpr static const g2_field_type_value twist_coeff_d = twist.mul_by_Fp(d);

                    constexpr static const g1_field_type_value twist_mul_by_a_c0 = a * g2_field_type_value::non_residue;
                    constexpr static const g1_field_type_value twist_mul_by_a_c1 = a;
                    constexpr static const g1_field_type_value twist_mul_by_a_c2 = a;
                    constexpr static const g1_field_type_value twist_mul_by_d_c0 = d * g2_field_type_value::non_residue;
                    constexpr static const g1_field_type_value twist_mul_by_d_c1 = d;
                    constexpr static const g1_field_type_value twist_mul_by_d_c2 = d;
                    constexpr static const g1_field_type_value
                        twist_mul_by_q_Y =
                    g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180); constexpr static
                    const g1_field_type_value twist_mul_by_q_Z =
                    g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);

                    constexpr static const underlying_field_type_value zero_fill = {
                        underlying_field_type_value::zero(), underlying_field_type_value::one(),
                        underlying_field_type_value::zero()};

                    constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(0x26C5DF4587AA6A5D345EFC9F2D47F8B1656517EF618F7A_cppui182),
                        underlying_field_type_value(0x32D83D8AAA0C500F57B15FDA90B1AD111067F812C7DD27_cppui182)};*/
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_EDWARDS_G1_HPP
