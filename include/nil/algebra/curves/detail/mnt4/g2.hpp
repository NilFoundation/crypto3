//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_MNT4_G1_HPP
#define ALGEBRA_CURVES_MNT4_G1_HPP

#include <boost/multiprecision/cpp_int/multiply.hpp>
#include <boost/multiprecision/modular/base_params.hpp>

#include <nil/algebra/curves/detail/element/curve_weierstrass.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template<std::size_t ModulusBits>
                struct mnt4_g2 {

                    using policy_type = mnt4<ModulusBits>;
                    constexpr static const std::size_t g1_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp<
                        fields::detail::arithmetic_params<fields::mnt4_fq<g1_field_bits, CHAR_BIT>>>
                        g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp2<
                        fields::detail::arithmetic_params<fields::mnt4_fq<g2_field_bits, CHAR_BIT>>>
                        g2_field_type_value;

                    using underlying_field_type = g2_field_type_value;

                    mnt4_g2() :
                        mnt4_g2(underlying_field_type::one(),
                                underlying_field_type::one(),
                                underlying_field_type::zero()) {};

                    mnt4_g2(underlying_field_type X, underlying_field_type Y, underlying_field_type Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    static mnt4_g2 zero() {
                        return mnt4_g2(zero_fill[0], zero_fill[1], zero_fill[2]);
                    }

                    static mnt4_g2 one() {
                        return mnt4_g2(one_fill[0], one_fill[1], one_fill[2]);
                    }

                    bool mnt4_g2::operator==(const mnt4_g2 &other) const {
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
                            return this->dbl();
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

                        const underlying_field_type Y1Z2 = (this->p[1]) * (other.p[2]);        // Y1Z2 = Y1*Z2
                        const underlying_field_type X1Z2 = (this->p[0]) * (other.p[2]);        // X1Z2 = X1*Z2
                        const underlying_field_type Z1Z2 = (this->p[2]) * (other.p[2]);        // Z1Z2 = Z1*Z2
                        const underlying_field_type u = (other.p[1]) * (this->p[2]) - Y1Z2;    // u    = Y2*Z1-Y1Z2
                        const underlying_field_type uu = u.squared();                          // uu   = u^2
                        const underlying_field_type v = (other.p[0]) * (this->p[2]) - X1Z2;    // v    = X2*Z1-X1Z2
                        const underlying_field_type vv = v.squared();                          // vv   = v^2
                        const underlying_field_type vvv = v * vv;                              // vvv  = v*vv
                        const underlying_field_type R = vv * X1Z2;                             // R    = vv*X1Z2
                        const underlying_field_type A = uu * Z1Z2 - (vvv + R + R);    // A    = uu*Z1Z2 - vvv - 2*R
                        const underlying_field_type X3 = v * A;                       // X3   = v*A
                        const underlying_field_type Y3 = u * (R - A) - vvv * Y1Z2;    // Y3   = u*(R-A) - vvv*Y1Z2
                        const underlying_field_type Z3 = vvv * Z1Z2;                  // Z3   = vvv*Z1Z2

                        return mnt4_g2(X3, Y3, Z3);
                    }

                    mnt4_g2 operator-() const {
                        return mnt4_g2(this->p[0], -this->p[1], this->p[2]);
                    }

                    mnt4_g2 operator-(const mnt4_g2 &other) const {
                        return (*this) + (-other);
                    }

                    mnt4_g2 dbl() const {
                        if (this->is_zero()) {
                            return (*this);
                        } else {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl

                            const underlying_field_type XX = (this->p[0]).squared();    // XX  = X1^2
                            const underlying_field_type ZZ = (this->p[2]).squared();    // ZZ  = Z1^2
                            const underlying_field_type w =
                                mnt4_g2::coeff_a * ZZ + (XX + XX + XX);    // w   = a*ZZ + 3*XX
                            const underlying_field_type Y1Z1 = (this->p[1]) * (this->p[2]);
                            const underlying_field_type s = Y1Z1 + Y1Z1;         // s   = 2*Y1*Z1
                            const underlying_field_type ss = s.squared();        // ss  = s^2
                            const underlying_field_type sss = s * ss;            // sss = s*ss
                            const underlying_field_type R = (this->p[1]) * s;    // R   = Y1*s
                            const underlying_field_type RR = R.squared();        // RR  = R^2
                            const underlying_field_type B =
                                ((this->p[0]) + R).squared() - XX - RR;                 // B   = (X1+R)^2 - XX - RR
                            const underlying_field_type h = w.squared() - B.dbl();      // h   = w^2 - 2*B
                            const underlying_field_type X3 = h * s;                     // X3  = h*s
                            const underlying_field_type Y3 = w * (B - h) - RR.dbl();    // Y3  = w*(B-h) - 2*RR
                            const underlying_field_type Z3 = sss;                       // Z3  = sss

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

                        const underlying_field_type &X1Z2 =
                            (this->p[0]);    // X1Z2 = X1*Z2 (but other is special and not zero)
                        const underlying_field_type X2Z1 = (this->p[2]) * (other.p[0]);    // X2Z1 = X2*Z1

                        // (used both in add and double checks)

                        const underlying_field_type &Y1Z2 =
                            (this->p[1]);    // Y1Z2 = Y1*Z2 (but other is special and not zero)
                        const underlying_field_type Y2Z1 = (this->p[2]) * (other.p[1]);    // Y2Z1 = Y2*Z1

                        if (X1Z2 == X2Z1 && Y1Z2 == Y2Z1) {
                            return this->dbl();
                        }

                        const underlying_field_type u = Y2Z1 - this->p[1];                  // u = Y2*Z1-Y1
                        const underlying_field_type uu = u.squared();                       // uu = u2
                        const underlying_field_type v = X2Z1 - this->p[0];                  // v = X2*Z1-X1
                        const underlying_field_type vv = v.squared();                       // vv = v2
                        const underlying_field_type vvv = v * vv;                           // vvv = v*vv
                        const underlying_field_type R = vv * this->p[0];                    // R = vv*X1
                        const underlying_field_type A = uu * this->p[2] - vvv - R.dbl();    // A = uu*Z1-vvv-2*R
                        const underlying_field_type X3 = v * A;                             // X3 = v*A
                        const underlying_field_type Y3 = u * (R - A) - vvv * this->p[1];    // Y3 = u*(R-A)-vvv*Y1
                        const underlying_field_type Z3 = vvv * this->p[2];                  // Z3 = vvv*Z1

                        return mnt4_g2(X3, Y3, Z3);
                    }

                private:
                    constexpr static const underlying_field_type zero_fill = {
                        underlying_field_type::zero(), underlying_field_type::one(), underlying_field_type::zero()};

                    constexpr static const underlying_field_type one_fill = {
                        underlying_field_type(
                            0x371780491C5660571FF542F2EF89001F205151E12A72CB14F01A931E72DBA7903DF6C09A9A4_cppui298,
                            0x4BA59A3F72DA165DEF838081AF697C851F002F576303302BB6C02C712C968BE32C0AE0A989_cppui295),
                        underlying_field_type(
                            0x4B471F33FFAAD868A1C47D6605D31E5C4B3B2E0B60EC98F0F610A5AAFD0D9522BCA4E79F22_cppui295,
                            0x355D05A1C69A5031F3F81A5C100CB7D982F78EC9CFC3B5168ED8D75C7C484FB61A3CBF0E0F1_cppui298),
                        underlying_field_type::one()};
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_MNT4_G1_HPP
