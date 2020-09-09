//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_MNT4_G2_HPP
#define ALGEBRA_CURVES_MNT4_G2_HPP

#include <nil/algebra/curves/detail/mnt4/basic_policy.hpp>
#include <nil/algebra/curves/detail/mnt4/g1.hpp>

#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_g2 {

                    using policy_type = mnt4_basic_policy<ModulusBits, GeneratorBits>;
                    constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                    typedef typename policy_type::base_field_type::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = policy_type::base_field_bits;
                    typedef typename fields::fp2<policy_type::base_field_type>::value_type g2_field_type_value;

                    using underlying_field_type_value = g2_field_type_value;

                    underlying_field_type_value p[3];

                    /*constexpr static */ const underlying_field_type_value x =
                        underlying_field_type_value(0x00, 0x00);    //?
                    /*constexpr static */ const underlying_field_type_value y =
                        underlying_field_type_value(0x00, 0x00);    //?

                    mnt4_g2() :
                        mnt4_g2(underlying_field_type_value::zero(), underlying_field_type_value::one(),
                                underlying_field_type_value::zero()) {};
                    // must be
                    // mnt4_g2() : mnt4_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                    // when constexpr fields will be finished

                    mnt4_g2(underlying_field_type_value X,
                            underlying_field_type_value Y,
                            underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    static mnt4_g2 zero() {
                        return mnt4_g2();
                    }

                    static mnt4_g2 one() {
                        return mnt4_g2(
                            underlying_field_type_value(
                                0x371780491C5660571FF542F2EF89001F205151E12A72CB14F01A931E72DBA7903DF6C09A9A4_cppui298,
                                0x4BA59A3F72DA165DEF838081AF697C851F002F576303302BB6C02C712C968BE32C0AE0A989_cppui295),
                            underlying_field_type_value(
                                0x4B471F33FFAAD868A1C47D6605D31E5C4B3B2E0B60EC98F0F610A5AAFD0D9522BCA4E79F22_cppui295,
                                0x355D05A1C69A5031F3F81A5C100CB7D982F78EC9CFC3B5168ED8D75C7C484FB61A3CBF0E0F1_cppui298),
                            underlying_field_type_value::one());
                        // must be
                        // return mnt4_g2(one_fill[0], one_fill[1], one_fill[2]);
                        // when constexpr fields will be finished
                    }

                    bool operator==(const mnt4_g2 &other) const {
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

                    bool operator!=(const mnt4_g2 &other) const {
                        return !(operator==(other));
                    }

                    bool is_zero() const {
                        return (this->p[0].is_zero() && this->p[2].is_zero());
                    }

                    mnt4_g2 operator+(const mnt4_g2 &other) const {
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

                        return mnt4_g2(X3, Y3, Z3);
                    }

                    mnt4_g2 operator-() const {
                        return mnt4_g2(this->p[0], -this->p[1], this->p[2]);
                    }

                    mnt4_g2 operator-(const mnt4_g2 &other) const {
                        return (*this) + (-other);
                    }

                    mnt4_g2 doubled() const {
                        if (this->is_zero()) {
                            return (*this);
                        } else {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl

                            const underlying_field_type_value XX = (this->p[0]).squared();    // XX  = X1^2
                            const underlying_field_type_value ZZ = (this->p[2]).squared();    // ZZ  = Z1^2
                            const underlying_field_type_value w = a * ZZ + (XX + XX + XX);    // w   = a*ZZ + 3*XX
                            const underlying_field_type_value Y1Z1 = (this->p[1]) * (this->p[2]);
                            const underlying_field_type_value s = Y1Z1 + Y1Z1;         // s   = 2*Y1*Z1
                            const underlying_field_type_value ss = s.squared();        // ss  = s^2
                            const underlying_field_type_value sss = s * ss;            // sss = s*ss
                            const underlying_field_type_value R = (this->p[1]) * s;    // R   = Y1*s
                            const underlying_field_type_value RR = R.squared();        // RR  = R^2
                            const underlying_field_type_value B =
                                ((this->p[0]) + R).squared() - XX - RR;    // B   = (X1+R)^2 - XX - RR
                            const underlying_field_type_value h = w.squared() - B.doubled();    // h   = w^2 - 2*B
                            const underlying_field_type_value X3 = h * s;                       // X3  = h*s
                            const underlying_field_type_value Y3 =
                                w * (B - h) - RR.doubled();                // Y3  = w*(B-h) - 2*RR
                            const underlying_field_type_value Z3 = sss;    // Z3  = sss

                            return mnt4_g2(X3, Y3, Z3);
                        }
                    }

                    mnt4_g2 mixed_add(const mnt4_g2 &other) const {
                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

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

                        const underlying_field_type_value u = Y2Z1 - this->p[1];    // u = Y2*Z1-Y1
                        const underlying_field_type_value uu = u.squared();         // uu = u2
                        const underlying_field_type_value v = X2Z1 - this->p[0];    // v = X2*Z1-X1
                        const underlying_field_type_value vv = v.squared();         // vv = v2
                        const underlying_field_type_value vvv = v * vv;             // vvv = v*vv
                        const underlying_field_type_value R = vv * this->p[0];      // R = vv*X1
                        const underlying_field_type_value A =
                            uu * this->p[2] - vvv - R.doubled();                                  // A = uu*Z1-vvv-2*R
                        const underlying_field_type_value X3 = v * A;                             // X3 = v*A
                        const underlying_field_type_value Y3 = u * (R - A) - vvv * this->p[1];    // Y3 = u*(R-A)-vvv*Y1
                        const underlying_field_type_value Z3 = vvv * this->p[2];                  // Z3 = vvv*Z1

                        return mnt4_g2(X3, Y3, Z3);
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
                    /*constexpr static */ const g1_field_type_value g1_a = g1_field_type_value(policy_type::a);
                    /*constexpr static */ const g1_field_type_value g1_b = g1_field_type_value(policy_type::b);

                    /*constexpr static */ const g2_field_type_value twist = g2_field_type_value(
                        {g2_field_type_value::underlying_type::zero(), g2_field_type_value::underlying_type::one()});

                    /*constexpr static */ const underlying_field_type_value a =
                        underlying_field_type_value({g1_a * twist.non_residue, g1_field_type_value::zero()});
                    // must be
                    // underlying_field_type_value(g1_a * underlying_field_type_value::non_residue, 0);
                    // when constexpr fields will be finished

                    /*constexpr static */ const underlying_field_type_value b =
                        underlying_field_type_value({g1_field_type_value::zero(), g1_b *twist.non_residue});
                    // must be
                    // underlying_field_type_value(0, g1_b * underlying_field_type_value::non_residue);
                    // when constexpr fields will be finished

                    /*constexpr static */ const g2_field_type_value twist_coeff_a = a;
                    /*constexpr static */ const g2_field_type_value twist_coeff_b = b;

                    /*constexpr static */ const g1_field_type_value twist_mul_by_a_c0 =
                        g1_a * twist.non_residue;    // we must receive non_residue in a better way, when constexpr
                                                     // fields will be finished
                    /*constexpr static */ const g1_field_type_value twist_mul_by_a_c1 =
                        g1_a * twist.non_residue;    // we must receive non_residue in a better way, when constexpr
                                                     // fields will be finished
                    /*constexpr static */ const g1_field_type_value twist_mul_by_b_c0 =
                        g1_b * twist.non_residue.squared();    // we must receive non_residue in a better way, when
                                                               // constexpr fields will be finished
                    /*constexpr static */ const g1_field_type_value twist_mul_by_b_c1 =
                        g1_b * twist.non_residue;    // we must receive non_residue in a better way, when constexpr
                                                     // fields will be finished
                    /*constexpr static */ const g1_field_type_value twist_mul_by_q_X = g1_field_type_value(
                        0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298);
                    /*constexpr static */ const g1_field_type_value twist_mul_by_q_Y = g1_field_type_value(
                        0xF73779FE09916DFDCC2FD1F968D534BEB17DAF7518CD9FAE5C1F7BDCF94DD5D7DEF6980C4_cppui292);

                    /*constexpr static const underlying_field_type_value zero_fill = {
                        underlying_field_type_value::zero(), underlying_field_type_value::one(),
                        underlying_field_type_value::zero()};

                    constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(
                            0x371780491C5660571FF542F2EF89001F205151E12A72CB14F01A931E72DBA7903DF6C09A9A4_cppui298,
                            0x4BA59A3F72DA165DEF838081AF697C851F002F576303302BB6C02C712C968BE32C0AE0A989_cppui295),
                        underlying_field_type_value(
                            0x4B471F33FFAAD868A1C47D6605D31E5C4B3B2E0B60EC98F0F610A5AAFD0D9522BCA4E79F22_cppui295,
                            0x355D05A1C69A5031F3F81A5C100CB7D982F78EC9CFC3B5168ED8D75C7C484FB61A3CBF0E0F1_cppui298),
                        underlying_field_type_value::one()};*/
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_MNT4_G2_HPP
