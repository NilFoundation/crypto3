//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_MNT6_G2_HPP
#define ALGEBRA_CURVES_MNT6_G2_HPP

#include <nil/algebra/curves/detail/mnt6/basic_policy.hpp>

#include <nil/algebra/fields/detail/element/fp3.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt6_g2 {

                    using policy_type = mnt6_basic_policy<ModulusBits, GeneratorBits>;
                    constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                    typedef typename policy_type::base_field_type::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = policy_type::base_field_bits;
                    typedef typename fields::fp3<typename policy_type::base_field_type>::value_type g2_field_type_value;

                    using underlying_field_type_value = g2_field_type_value;

                    underlying_field_type_value p[3];

                    /*constexpr static */ const underlying_field_type_value x =
                        underlying_field_type_value(0x00, 0x00, 0x00);    //?
                    /*constexpr static */ const underlying_field_type_value y =
                        underlying_field_type_value(0x00, 0x00, 0x00);    //?

                    mnt6_g2() :
                        mnt6_g2(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                underlying_field_type_value::zero()) {};
                    // must be
                    // mnt6_g2() : mnt6_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    // when constexpr fields will be finished

                    mnt6_g2(underlying_field_type_value X,
                            underlying_field_type_value Y,
                            underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    static mnt6_g2 zero() {
                        return mnt6_g2();
                    }

                    static mnt6_g2 one() {
                        return mnt6_g2(
                            underlying_field_type_value(
                                0x34F7320A12B56CE532BCCB3B44902CBAA723CD60035ADA7404B743AD2E644AD76257E4C6813_cppui298,
                                0xCF41620BAA52EEC50E61A70AB5B45F681952E0109340FEC84F1B2890ABA9B15CAC5A0C80FA_cppui296,
                                0x11F99170E10E326433CCCB8032FB48007CA3C4E105CF31B056AC767E2CB01258391BD4917CE_cppui297),
                            underlying_field_type_value(
                                0x3A65968F03CC64D62AD05C79C415E07EBD38B363EC48309487C0B83E1717A582C1B60FECC91_cppui298,
                                0xCA5E8427E5DB1506C1A24CEFC2451AB3ACCAEA5DB82DCB0C7117CC74402FAA5B2C37685C6E_cppui296,
                                0xF75D2DD88302C9A4EF941307629A1B3E197277D83ABB715F647C2E55A27BAF782F5C60E7F7_cppui296),
                            underlying_field_type_value::one());
                        // must be
                        // return mnt6_g2(one_fill[0], one_fill[1], one_fill[2]);
                        // when constexpr fields will be finished
                    }

                    bool operator==(const mnt6_g2 &other) const {
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

                    bool operator!=(const mnt6_g2 &other) const {
                        return !(operator==(other));
                    }

                    bool is_zero() const {
                        return (this->p[0].is_zero() && this->p[2].is_zero());
                    }

                    mnt6_g2 operator-() const {
                        return mnt6_g2(this->p[0], -(this->p[1]), this->p[2]);
                    }

                    mnt6_g2 operator-(const mnt6_g2 &other) const {
                        return (*this) + (-other);
                    }

                    mnt6_g2 operator+(const mnt6_g2 &other) const {
                        // handle special cases having to do with O

                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return (*this);
                        }

                        // no need to handle points of order 2,4
                        // (they cannot exist in a prime-order subgroup)

                        // handle double case
                        if (this->operator==(other)) {
                            return this->doubled();
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

                        const underlying_field_type_value Y1Z2 = (this->p[1]) * (other.p[2]);    // Y1Z2 = Y1*Z2
                        const underlying_field_type_value X1Z2 = (this->p[0]) * (other.p[2]);    // X1Z2 = X1*Z2
                        const underlying_field_type_value Z1Z2 = (this->p[2]) * (other.p[2]);    // Z1Z2 = Z1*Z2
                        const underlying_field_type_value u =
                            (other.p[1]) * (this->p[2]) - Y1Z2;                // u    = Y2*Z1-Y1Z2
                        const underlying_field_type_value uu = u.squared();    // uu   = u^2
                        const underlying_field_type_value v =
                            (other.p[0]) * (this->p[2]) - X1Z2;                // v    = X2*Z1-X1Z2
                        const underlying_field_type_value vv = v.squared();    // vv   = v^2
                        const underlying_field_type_value vvv = v * vv;        // vvv  = v*vv
                        const underlying_field_type_value R = vv * X1Z2;       // R    = vv*X1Z2
                        const underlying_field_type_value A =
                            uu * Z1Z2 - (vvv + R + R);                   // A    = uu*Z1Z2 - vvv - 2*R
                        const underlying_field_type_value X3 = v * A;    // X3   = v*A
                        const underlying_field_type_value Y3 = u * (R - A) - vvv * Y1Z2;    // Y3   = u*(R-A) - vvv*Y1Z2
                        const underlying_field_type_value Z3 = vvv * Z1Z2;                  // Z3   = vvv*Z1Z2

                        return mnt6_g2(X3, Y3, Z3);
                    }

                    mnt6_g2 mixed_add(const mnt6_g2 &other) const {
                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
                        // assert(other.p[2] == underlying_field_type_value::one());

                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return (*this);
                        }

                        const underlying_field_type_value &X1Z2 =
                            (this->p[0]);    // X1Z2 = X1*Z2 (but other is special and not zero)
                        const underlying_field_type_value X2Z1 = (this->p[2]) * (other.p[0]);    // X2Z1 = X2*Z1

                        // (used both in add and double checks)

                        const underlying_field_type_value &Y1Z2 =
                            (this->p[1]);    // Y1Z2 = Y1*Z2 (but other is special and not zero)
                        const underlying_field_type_value Y2Z1 = (this->p[2]) * (other.p[1]);    // Y2Z1 = Y2*Z1

                        if (X1Z2 == X2Z1 && Y1Z2 == Y2Z1) {
                            return this->doubled();
                        }

                        const underlying_field_type_value u = Y2Z1 - this->p[1];                  // u = Y2*Z1-Y1
                        const underlying_field_type_value uu = u.squared();                       // uu = u2
                        const underlying_field_type_value v = X2Z1 - this->p[0];                  // v = X2*Z1-X1
                        const underlying_field_type_value vv = v.squared();                       // vv = v2
                        const underlying_field_type_value vvv = v * vv;                           // vvv = v*vv
                        const underlying_field_type_value R = vv * this->p[0];                    // R = vv*X1
                        const underlying_field_type_value A = uu * this->p[2] - vvv - R - R;      // A = uu*Z1-vvv-2*R
                        const underlying_field_type_value X3 = v * A;                             // X3 = v*A
                        const underlying_field_type_value Y3 = u * (R - A) - vvv * this->p[1];    // Y3 = u*(R-A)-vvv*Y1
                        const underlying_field_type_value Z3 = vvv * this->p[2];                  // Z3 = vvv*Z1

                        return mnt6_g2(X3, Y3, Z3);
                    }

                    mnt6_g2 doubled() const {
                        if (this->is_zero()) {
                            return (*this);
                        } else {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl

                            const underlying_field_type_value XX = (this->p[0]).squared();          // XX  = X1^2
                            const underlying_field_type_value ZZ = (this->p[2]).squared();          // ZZ  = Z1^2
                            const underlying_field_type_value w = mul_by_a(ZZ) + (XX + XX + XX);    // w   = a*ZZ + 3*XX
                            const underlying_field_type_value Y1Z1 = (this->p[1]) * (this->p[2]);
                            const underlying_field_type_value s = Y1Z1 + Y1Z1;         // s   = 2*Y1*Z1
                            const underlying_field_type_value ss = s.squared();        // ss  = s^2
                            const underlying_field_type_value sss = s * ss;            // sss = s*ss
                            const underlying_field_type_value R = (this->p[1]) * s;    // R   = Y1*s
                            const underlying_field_type_value RR = R.squared();        // RR  = R^2
                            const underlying_field_type_value B =
                                ((this->p[0]) + R).squared() - XX - RR;                     // B   = (X1+R)^2 - XX - RR
                            const underlying_field_type_value h = w.squared() - (B + B);    // h   = w^2-2*B
                            const underlying_field_type_value X3 = h * s;                   // X3  = h*s
                            const underlying_field_type_value Y3 = w * (B - h) - (RR + RR);    // Y3  = w*(B-h) - 2*RR
                            const underlying_field_type_value Z3 = sss;                        // Z3  = sss

                            return mnt6_g2(X3, Y3, Z3);
                        }
                    }

                    void to_affine_coordinates() {
                        if (this->is_zero()) {
                            this->p[0] = underlying_field_type_value::zero();
                            this->p[1] = underlying_field_type_value::one();
                            this->p[2] = underlying_field_type_value::zero();
                        } else {
                            const underlying_field_type_value Z_inv = this->p[2].inversed();
                            this->p[0] = this->p[0] * Z_inv;
                            this->p[1] = this->p[1] * Z_inv;
                            this->p[2] = underlying_field_type_value::one();
                        }
                    }

                    void to_special() {
                        this->to_affine_coordinates();
                    }

                    bool is_special() const {
                        return (this->is_zero() || this->p[2] == underlying_field_type_value::one());
                    }

                private:
                    underlying_field_type_value mul_by_a(const underlying_field_type_value &elt) const {
                        return underlying_field_type_value({twist_mul_by_a_c0 * elt.data[1],
                                                            twist_mul_by_a_c1 * elt.data[2],
                                                            twist_mul_by_a_c2 * elt.data[0]});
                    }

                    underlying_field_type_value mul_by_b(const underlying_field_type_value &elt) const {
                        return underlying_field_type_value({twist_mul_by_a_c0 * elt.data[0],
                                                            twist_mul_by_a_c1 * elt.data[1],
                                                            twist_mul_by_a_c2 * elt.data[2]});
                    }

                    /*mnt6_g2 mul_by_q() const {
                        return mnt6_g2(twist_mul_by_q_X * (this->p[0]).Frobenius_map(1),
                                       twist_mul_by_q_Y * (this->p[1]).Frobenius_map(1),
                                       (this->p[2]).Frobenius_map(1));
                    }*/

                    /*constexpr static */ const g1_field_type_value g1_a = g1_field_type_value(policy_type::a);
                    /*constexpr static */ const g1_field_type_value g1_b = g1_field_type_value(policy_type::b);

                    /*constexpr static */ const g2_field_type_value twist = g2_field_type_value(
                        {g2_field_type_value::underlying_type::zero(), g2_field_type_value::underlying_type::one(),
                         g2_field_type_value::underlying_type::zero()});

                    /*constexpr static */ const underlying_field_type_value a =
                        underlying_field_type_value({g2_field_type_value::underlying_type::zero(),
                                                     g2_field_type_value::underlying_type::zero(), g1_a});

                    /*constexpr static */ const underlying_field_type_value b = underlying_field_type_value(
                        {g1_b * twist.non_residue, g2_field_type_value::underlying_type::zero(),
                         g2_field_type_value::underlying_type::zero()});
                    // must be
                    // underlying_field_type_value({g1_b * twist.non_residue,
                    // when constexpr fields will be finished

                    /*constexpr static */ const g2_field_type_value twist_coeff_a = a;
                    /*constexpr static */ const g2_field_type_value twist_coeff_b = b;

                    /*constexpr static */ const g1_field_type_value twist_mul_by_a_c0 = g1_a * twist.non_residue;
                    /*constexpr static */ const g1_field_type_value twist_mul_by_a_c1 = g1_a * twist.non_residue;
                    /*constexpr static */ const g1_field_type_value twist_mul_by_a_c2 = g1_a;
                    /*constexpr static */ const g1_field_type_value twist_mul_by_b_c0 = g1_b * twist.non_residue;
                    /*constexpr static */ const g1_field_type_value twist_mul_by_b_c1 = g1_b * twist.non_residue;
                    /*constexpr static */ const g1_field_type_value twist_mul_by_b_c2 = g1_b * twist.non_residue;

                    /*constexpr static */ const g1_field_type_value twist_mul_by_q_X = g1_field_type_value(
                        0x8696C330D743F33B572CEF4DF62CE7ECB178EE24E48D1A53736E86448E74CB48DAACBB414_cppui298);
                    /*constexpr static */ const g1_field_type_value twist_mul_by_q_Y = g1_field_type_value(
                        0x3BCF7BCD473A266249DA7B0548ECAEEC9635CF44194FB494C07925D6AD3BB4334A400000000_cppui298);

                    /*constexpr static const underlying_field_type_value zero_fill = {
                        underlying_field_type_value::zero(), underlying_field_type_value::one(),
                        underlying_field_type_value::zero()};

                    constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(
                            0x34F7320A12B56CE532BCCB3B44902CBAA723CD60035ADA7404B743AD2E644AD76257E4C6813_cppui298,
                            0xCF41620BAA52EEC50E61A70AB5B45F681952E0109340FEC84F1B2890ABA9B15CAC5A0C80FA_cppui296,
                            0x11F99170E10E326433CCCB8032FB48007CA3C4E105CF31B056AC767E2CB01258391BD4917CE_cppui297),
                        underlying_field_type_value(
                            0x3A65968F03CC64D62AD05C79C415E07EBD38B363EC48309487C0B83E1717A582C1B60FECC91_cppui298,
                            0xCA5E8427E5DB1506C1A24CEFC2451AB3ACCAEA5DB82DCB0C7117CC74402FAA5B2C37685C6E_cppui296,
                            0xF75D2DD88302C9A4EF941307629A1B3E197277D83ABB715F647C2E55A27BAF782F5C60E7F7_cppui296),
                        underlying_field_type_value::one()};*/
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_MNT6_G2_HPP
