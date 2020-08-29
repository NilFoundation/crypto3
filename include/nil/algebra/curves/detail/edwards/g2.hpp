//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_EDWARDS_G2_HPP
#define ALGEBRA_CURVES_EDWARDS_G2_HPP

#include <boost/multiprecision/cpp_int/multiply.hpp>
#include <boost/multiprecision/modular/base_params.hpp>

#include <nil/algebra/curves/detail/element/curve_weierstrass.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template<typename PairingParams>
                struct edwards_g2 {
                    
                    using policy_type = edwards<ModulusBits>;
                    constexpr static const std::size_t g1_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp<fields::detail::arithmetic_params<fields::edwards_fq<g1_field_bits, CHAR_BIT>>> g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp3<fields::detail::arithmetic_params<fields::edwards_fq<g2_field_bits, CHAR_BIT>>> g2_field_type_value;

                    using underlying_field_type = g2_field_type_value;

                    edwards_g2() : element_type(underlying_field_type::one(), underlying_field_type::one(), underlying_field_type::zero()) {};

                    edwards_g2(underlying_field_type X, underlying_field_type Y, underlying_field_type Z) : element_type(X, Y, Z) {};

                    edwards_g2(underlying_field_type X, underlying_field_type Y, underlying_field_type Z) : element_type(X, Y, X*Y) {};

                    static edwards_g2 zero() {
                        return edwards_g2(zero_fill[0], zero_fill[1], zero_fill[2]);
                    }

                    static edwards_g2 one() {
                        return edwards_g2(one_fill[0], one_fill[1]);    // it's better to precompute also one_fill[2]
                    }

                    edwards_g2 add(const edwards_g2 &B) const {

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-inverted.html#addition-add-2008-bbjlp

                        const underlying_field_type A = (this->p[2]) * (B.p[2]);                   // A = Z1*Z2
                        const underlying_field_type B = this->mul_by_d(this->p[0].square());           // B = d*A^2
                        const underlying_field_type C = (this->p[0]) * (B.p[0]);                       // C = X1*X2
                        const underlying_field_type D = (this->p[1]) * (B.p[1]);                       // D = Y1*Y2
                        const underlying_field_type E = C*D;                                         // E = C*D
                        const underlying_field_type H = C - this->mul_by_a(D);                 // H = C-a*D
                        const underlying_field_type I = (this->p[0]+this->p[1])*(B.p[0]+B.p[1])-C-D;     // I = (X1+Y1)*(X2+Y2)-C-D
                        const underlying_field_type X3 = (E+B)*H;                                    // X3 = (E+B)*H
                        const underlying_field_type Y3 = (E-B)*I;                                    // Y3 = (E-B)*I
                        const underlying_field_type Z3 = A*H*I;                                      // Z3 = A*H*I

                        return edwards_g2(X3, Y3, Z3);
                    }

                    edwards_g2 operator- () const {
                        return edwards_g2(-(this->p[0]), this->p[1], this->p[2]);
                    }

                    edwards_g2 operator- (const edwards_g2 &B) const {
                        return (*this) + (-B);
                    }

                    edwards_g2 dbl() const {
                    
                        if (this->is_zero()) {
                            return (*this);
                        }
                        else {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-inverted.html#doubling-dbl-2008-bbjlp

                            const underlying_field_type A = (this->p[0]).square();                      // A = X1^2
                            const underlying_field_type B = (this->p[1]).square();                      // B = Y1^2
                            const underlying_field_type U = this->mul_by_a(B);                  // U = a*B
                            const underlying_field_type C = A+U;                                      // C = A+U
                            const underlying_field_type D = A-U;                                      // D = A-U
                            const underlying_field_type E = (this->p[0] + this->p[1]).square()-A-B;          // E = (X1+Y1)^2-A-B
                            const underlying_field_type X3 = C*D;                                     // X3 = C*D
                            const underlying_field_type dZZ = this->mul_by_d(this->p[2].square());
                            const underlying_field_type Y3 = E*(C-dZZ-dZZ);                           // Y3 = E*(C-2*d*Z1^2)
                            const underlying_field_type Z3 = D*E;                                     // Z3 = D*E

                            return edwards_g2(X3, Y3, Z3);
                        }
                    }

                    edwards_g2 mixed_add(const edwards_g2 &B) const {
                    
                        // handle special cases having to do with O
                        if (this->is_zero())
                        {
                            return B;
                        }

                        if (B.is_zero())
                        {
                            return *this;
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-madd-2007-lb

                        const underlying_field_type A = this->p[2];                                     // A = Z1*Z2
                        const underlying_field_type B = mul_by_d(A.squared());           // B = d*A^2
                        const underlying_field_type C = (this->p[0]) * (B.p[0]);                       // C = X1*X2
                        const underlying_field_type D = (this->p[1]) * (B.p[1]);                       // D = Y1*Y2
                        const underlying_field_type E = C * D;                                         // E = C*D
                        const underlying_field_type H = C - mul_by_a(D);                 // H = C-a*D
                        const underlying_field_type I = (this->p[0] + this->p[1]) * (B.p[0] + B.p[1]) - C - D;     // I = (X1+Y1)*(X2+Y2)-C-D
                        const underlying_field_type X3 = (E + B) * H;                                    // X3 = (E+B)*H
                        const underlying_field_type Y3 = (E - B) * I;                                    // Y3 = (E-B)*I
                        const underlying_field_type Z3 = A * H * I;                                      // Z3 = A*H*I

                        return edwards_g2(X3, Y3, Z3);
                    }
                    
                    constexpr static const policy_type::number_type curve_coeff_a = policy_type::a;
                    constexpr static const policy_type::number_type curve_coeff_d = policy_type::d;

                    constexpr static const g2_field_type_value edwards_twist (g2_field_type_value::underlying_type::zero(), 
                            g2_field_type_value::underlying_type::one(), g2_field_type_value::underlying_type::zero());
                    constexpr static const g2_field_type_value edwards_twist_coeff_a = edwards_twist.mul_by_Fp(curve_coeff_a);
                    constexpr static const g2_field_type_value edwards_twist_coeff_d = edwards_twist.mul_by_Fp(curve_coeff_d);

                    constexpr static const g1_field_type_value edwards_twist_mul_by_a_c0 = curve_coeff_a * g2_field_type_value::non_residue;
                    constexpr static const g1_field_type_value edwards_twist_mul_by_a_c1 = curve_coeff_a;
                    constexpr static const g1_field_type_value edwards_twist_mul_by_a_c2 = curve_coeff_a;
                    constexpr static const g1_field_type_value edwards_twist_mul_by_d_c0 = curve_coeff_d * g2_field_type_value::non_residue;
                    constexpr static const g1_field_type_value edwards_twist_mul_by_d_c1 = curve_coeff_d;
                    constexpr static const g1_field_type_value edwards_twist_mul_by_d_c2 = curve_coeff_d;
                    constexpr static const g1_field_type_value edwards_twist_mul_by_q_Y (0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);
                    constexpr static const g1_field_type_value edwards_twist_mul_by_q_Z (0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);

                private:

                    constexpr static const underlying_field_type zero_fill = {underlying_field_type::zero(), underlying_field_type::one(), underlying_field_type::zero()};

                    constexpr static const underlying_field_type one_fill = {
                        underlying_field_type(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,
                                                0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,
                                                0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),
                        underlying_field_type(0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,
                                                0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,
                                                0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182)};

                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_EDWARDS_G2_HPP
