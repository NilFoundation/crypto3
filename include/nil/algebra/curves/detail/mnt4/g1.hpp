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
                struct mnt4_g1 {

                    using policy_type = mnt4<ModulusBits>;
                    constexpr static const std::size_t g1_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp<fields::detail::arithmetic_params<fields::mnt4_fq<g1_field_bits, CHAR_BIT>>> g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp2<fields::detail::arithmetic_params<fields::mnt4_fq<g2_field_bits, CHAR_BIT>>> g2_field_type_value;

                    using underlying_field_type = g1_field_type_value;

                    mnt4_g1() : element_type(underlying_field_type::one(), underlying_field_type::one(), underlying_field_type::zero()) {};

                    mnt4_g1(underlying_field_type X, underlying_field_type Y, underlying_field_type Z) : element_type(X, Y, Z) {};

                    static mnt4_g1 zero() {
                        return mnt4_g1(zero_fill[0], zero_fill[1], zero_fill[2]);
                    }

                    static mnt4_g1 one() {
                        return mnt4_g1(one_fill[0], one_fill[1], one_fill[2]);
                    }

                    bool mnt4_g1::operator==(const mnt4_g1 &B) const{
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

                    mnt4_G1 operator+(const mnt4_G1 &B) const{

                        // handle special cases having to do with O
                        if (this->is_zero()){
                            return B;
                        }

                        if (B.is_zero()){
                            return (*this);
                        }

                        // no need to handle points of order 2,4
                        // (they cannot exist in a prime-order subgroup)

                        // handle double case
                        if (*this == B){
                            return this->dbl();
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

                        const underlying_field_type Y1Z2 = (this->p[1]) * (B.p[2]);        // Y1Z2 = Y1*Z2
                        const underlying_field_type X1Z2 = (this->p[0]) * (B.p[2]);        // X1Z2 = X1*Z2
                        const underlying_field_type Z1Z2 = (this->p[2]) * (B.p[2]);        // Z1Z2 = Z1*Z2
                        const underlying_field_type u    = (B.p[1]) * (this->p[2]) - Y1Z2; // u    = Y2*Z1-Y1Z2
                        const underlying_field_type uu   = u.square();                    // uu   = u^2
                        const underlying_field_type v    = (B.p[0]) * (this->p[2]) - X1Z2; // v    = X2*Z1-X1Z2
                        const underlying_field_type vv   = v.square();                    // vv   = v^2
                        const underlying_field_type vvv  = v * vv;                         // vvv  = v*vv
                        const underlying_field_type R    = vv * X1Z2;                      // R    = vv*X1Z2
                        const underlying_field_type A    = uu * Z1Z2 - (vvv + R + R);      // A    = uu*Z1Z2 - vvv - 2*R
                        const underlying_field_type X3   = v * A;                          // X3   = v*A
                        const underlying_field_type Y3   = u * (R-A) - vvv * Y1Z2;         // Y3   = u*(R-A) - vvv*Y1Z2
                        const underlying_field_type Z3   = vvv * Z1Z2;                     // Z3   = vvv*Z1Z2

                        return mnt4_g1(X3, Y3, Z3);
                    }

                    mnt4_g1 operator- () const {
                        return mnt4_g1(this->p[0], -this->p[1], this->p[2]);
                    }

                    mnt4_g1 operator- (const mnt4_g1 &B) const {
                        return (*this) + (-B);
                    }

                    mnt4_g1 dbl() const {

                        if (this->is_zero()) {
                            return (*this);
                        }
                        else {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl

                            const underlying_field_type XX   = (this->p[0]).square();                   // XX  = X1^2
                            const underlying_field_type ZZ   = (this->p[2]).square();                   // ZZ  = Z1^2
                            const underlying_field_type w    = mnt4_G1::coeff_a * ZZ + (XX + XX + XX); // w   = a*ZZ + 3*XX
                            const underlying_field_type Y1Z1 = (this->p[1]) * (this->p[2]);
                            const underlying_field_type s    = Y1Z1 + Y1Z1;                            // s   = 2*Y1*Z1
                            const underlying_field_type ss   = s.square();                            // ss  = s^2
                            const underlying_field_type sss  = s * ss;                                 // sss = s*ss
                            const underlying_field_type R    = (this->p[1]) * s;                         // R   = Y1*s
                            const underlying_field_type RR   = R.square();                            // RR  = R^2
                            const underlying_field_type B    = ((this->p[0])+R).square()-XX-RR;         // B   = (X1+R)^2 - XX - RR
                            const underlying_field_type h    = w.square() - (B+B);                    // h   = w^2 - 2*B
                            const underlying_field_type X3   = h * s;                                  // X3  = h*s
                            const underlying_field_type Y3   = w * (B-h)-(RR+RR);                      // Y3  = w*(B-h) - 2*RR
                            const underlying_field_type Z3   = sss;                                    // Z3  = sss

                            return mnt4_G1(X3, Y3, Z3);
                        }
                    }

                    mnt4_G1 mixed_add(const mnt4_G1 &B) const{
                    
                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

                        if (this->is_zero()) {
                            return B;
                        }

                        if (B.is_zero()) {
                            return (*this);
                        }

                        const underlying_field_type &X1Z2 = (this->p[0]);                    // X1Z2 = X1*Z2 (but B is special and not zero)
                        const underlying_field_type X2Z1 = (this->p[2]) * (B.p[0]);          // X2Z1 = X2*Z1

                        // (used both in add and double checks)

                        const underlying_field_type &Y1Z2 = (this->p[1]);                    // Y1Z2 = Y1*Z2 (but B is special and not zero)
                        const underlying_field_type Y2Z1 = (this->p[2]) * (B.p[1]);          // Y2Z1 = Y2*Z1

                        if (X1Z2 == X2Z1 && Y1Z2 == Y2Z1)
                        {
                            return this->dbl();
                        }

                        const underlying_field_type u = Y2Z1 - this->p[1];                   // u = Y2*Z1-Y1
                        const underlying_field_type uu = u.square();                         // uu = u2
                        const underlying_field_type v = X2Z1 - this->p[0];                   // v = X2*Z1-X1
                        const underlying_field_type vv = v.square();                         // vv = v2
                        const underlying_field_type vvv = v*vv;                              // vvv = v*vv
                        const underlying_field_type R = vv * this->p[0];                     // R = vv*X1
                        const underlying_field_type A = uu * this->p[2] - vvv - R - R;       // A = uu*Z1-vvv-2*R
                        const underlying_field_type X3 = v * A;                              // X3 = v*A
                        const underlying_field_type Y3 = u*(R-A) - vvv * this->p[1];         // Y3 = u*(R-A)-vvv*Y1
                        const underlying_field_type Z3 = vvv * this->p[2];                   // Z3 = vvv*Z1

                        return mnt4_G1(X3, Y3, Z3);
                    }

                private:

                    constexpr static const policy_type::number_type curve_coeff_a = policy_type::a;
                    constexpr static const policy_type::number_type curve_coeff_b = policy_type::b;

                    static const g2_field_type_value mnt4_twist = g2_field_type_value(mnt4_Fq::zero(), mnt4_Fq::one());
                    static const g2_field_type_value mnt4_twist_coeff_a = g2_field_type_value(curve_coeff_a * g2_field_type_value::non_residue, mnt4_Fq::zero());
                    static const g2_field_type_value mnt4_twist_coeff_b = g2_field_type_value(mnt4_Fq::zero(), mnt4_G1::coeff_b * g2_field_type_value::non_residue);

                    static const g1_field_type_value mnt4_twist_mul_by_a_c0 = mnt4_twist_coeff_a * g2_field_type_value::non_residue;
                    static const g1_field_type_value mnt4_twist_mul_by_a_c1 = mnt4_twist_coeff_a * g2_field_type_value::non_residue;
                    static const g1_field_type_value mnt4_twist_mul_by_b_c0 = mnt4_twist_coeff_b * g2_field_type_value::non_residue.square();
                    static const g1_field_type_value mnt4_twist_mul_by_b_c1 = mnt4_twist_coeff_b * g2_field_type_value::non_residue;
                    static const g1_field_type_value mnt4_twist_mul_by_q_X(0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298);
                    static const g1_field_type_value mnt4_twist_mul_by_q_Y(0xF73779FE09916DFDCC2FD1F968D534BEB17DAF7518CD9FAE5C1F7BDCF94DD5D7DEF6980C4_cppui292);

                    constexpr static const underlying_field_type zero_fill = {underlying_field_type::zero(), underlying_field_type::one(), underlying_field_type::zero()};

                    constexpr static const underlying_field_type one_fill = {
                        underlying_field_type(0x7A2CAF82A1BA85213FE6CA3875AEE86ABA8F73D69060C4079492B948DEA216B5B9C8D2AF46_cppui295),
                        underlying_field_type(0x2DB619461CC82672F7F159FEC2E89D0148DCC9862D36778C1AFD96A71E29CBA48E710A48AB2_cppui298),
                        underlying_field_type::one()};
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_MNT4_G1_HPP
