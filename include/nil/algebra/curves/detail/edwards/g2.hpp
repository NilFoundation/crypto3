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

#include <nil/algebra/curves/detail/edwards/basic_policy.hpp>

#include <nil/algebra/curves/detail/edwards/g1.hpp>

#include <nil/algebra/fields/edwards/fq.hpp>
#include <nil/algebra/fields/edwards/fr.hpp>
#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp3.hpp>
#include <nil/algebra/fields/detail/params/edwards/fq.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                struct edwards_g2 {

                    using policy_type = edwards_basic_policy<ModulusBits, GeneratorBits>;
                    constexpr static const std::size_t g1_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp<
                        fields::detail::arithmetic_params<fields::edwards_fq<g1_field_bits, CHAR_BIT>>>
                        g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp3<
                        fields::detail::arithmetic_params<fields::edwards_fq<g2_field_bits, CHAR_BIT>>>
                        g2_field_type_value;

                    using underlying_field_type_value = g2_field_type_value;
                    
                    underlying_field_type_value p[3];

                    edwards_g2() : edwards_g2(underlying_field_type_value(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,
                                                    0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,
                                                    0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),
                        underlying_field_type_value(0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,
                                                    0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,
                                                    0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182)) {};
                    // must be
                    // edwards_g2() : edwards_g2(one_fill[0], one_fill[1]) {};
                    // when constexpr fields will be finished

                    edwards_g2(underlying_field_type_value X, underlying_field_type_value Y,
                               underlying_field_type_value Z) {
                        p[0] = X;
                        p[1] = Y;
                        p[2] = Z;
                    };

                    edwards_g2(underlying_field_type_value X, underlying_field_type_value Y) :
                        edwards_g2(X, Y, X * Y) {};

                    static edwards_g2 zero() {
                        return edwards_g2(underlying_field_type_value::zero(), 
                        underlying_field_type_value::one(),
                        underlying_field_type_value::zero());
                        // must be
                        // return edwards_g2(zero_fill[0], zero_fill[1], zero_fill[2]);
                        // when constexpr fields will be finished
                    }

                    static edwards_g2 one() {
                        return edwards_g2(underlying_field_type_value(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,
                                                    0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,
                                                    0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),
                        underlying_field_type_value(0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,
                                                    0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,
                                                    0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182));    // it's better to precompute also one_fill[2]
                        // must be
                        // return edwards_g2(one_fill[0], one_fill[1]);    // it's better to precompute also one_fill[2]
                        // when constexpr fields will be finished
                    }

                    edwards_g2 operator+(const edwards_g2 &other) const {

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-inverted.html#addition-add-2008-bbjlp

                        const underlying_field_type_value A = (this->p[2]) * (other.p[2]);             // A = Z1*Z2
                        const underlying_field_type_value B = this->mul_by_d(this->p[0].squared());    // B = d*A^2
                        const underlying_field_type_value C = (this->p[0]) * (other.p[0]);             // C = X1*X2
                        const underlying_field_type_value D = (this->p[1]) * (other.p[1]);             // D = Y1*Y2
                        const underlying_field_type_value E = C * D;                                   // E = C*D
                        const underlying_field_type_value H = C - this->mul_by_a(D);                   // H = C-a*D
                        const underlying_field_type_value I =
                            (this->p[0] + this->p[1]) * (other.p[0] + other.p[1]) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                        const underlying_field_type_value X3 = (E + B) * H;                   // X3 = (E+B)*H
                        const underlying_field_type_value Y3 = (E - B) * I;                   // Y3 = (E-B)*I
                        const underlying_field_type_value Z3 = A * H * I;                     // Z3 = A*H*I

                        return edwards_g2(X3, Y3, Z3);
                    }

                    edwards_g2 operator-() const {
                        return edwards_g2(-(this->p[0]), this->p[1], this->p[2]);
                    }

                    edwards_g2 operator-(const edwards_g2 &other) const {
                        return (*this) + (-other);
                    }

                    edwards_g2 doubled() const {

                        if (this->is_zero()) {
                            return (*this);
                        } else {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-inverted.html#doubling-dbl-2008-bbjlp

                            const underlying_field_type_value A = (this->p[0]).squared();    // A = X1^2
                            const underlying_field_type_value B = (this->p[1]).squared();    // B = Y1^2
                            const underlying_field_type_value U = this->mul_by_a(B);         // U = a*B
                            const underlying_field_type_value C = A + U;                     // C = A+U
                            const underlying_field_type_value D = A - U;                     // D = A-U
                            const underlying_field_type_value E =
                                (this->p[0] + this->p[1]).squared() - A - B;    // E = (X1+Y1)^2-A-B
                            const underlying_field_type_value X3 = C * D;       // X3 = C*D
                            const underlying_field_type_value dZZ = this->mul_by_d(this->p[2].squared());
                            const underlying_field_type_value Y3 = E * (C - dZZ - dZZ);    // Y3 = E*(C-2*d*Z1^2)
                            const underlying_field_type_value Z3 = D * E;                  // Z3 = D*E

                            return edwards_g2(X3, Y3, Z3);
                        }
                    }

                    edwards_g2 mixed_add(const edwards_g2 &other) const {

                        // handle special cases having to do with O
                        if (this->is_zero()) {
                            return other;
                        }

                        if (other.is_zero()) {
                            return *this;
                        }

                        // NOTE: does not handle O and pts of order 2,4
                        // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-madd-2007-lb

                        const underlying_field_type_value A = this->p[2];                     // A = Z1*Z2
                        const underlying_field_type_value B = mul_by_d(A.squared());          // B = d*A^2
                        const underlying_field_type_value C = (this->p[0]) * (other.p[0]);    // C = X1*X2
                        const underlying_field_type_value D = (this->p[1]) * (other.p[1]);    // D = Y1*Y2
                        const underlying_field_type_value E = C * D;                          // E = C*D
                        const underlying_field_type_value H = C - mul_by_a(D);                // H = C-a*D
                        const underlying_field_type_value I =
                            (this->p[0] + this->p[1]) * (other.p[0] + other.p[1]) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                        const underlying_field_type_value X3 = (E + B) * H;                   // X3 = (E+B)*H
                        const underlying_field_type_value Y3 = (E - B) * I;                   // Y3 = (E-B)*I
                        const underlying_field_type_value Z3 = A * H * I;                     // Z3 = A*H*I

                        return edwards_g2(X3, Y3, Z3);
                    }


                    void to_affine_coordinates() {
                        if (this->is_zero()) {
                            this->p[0] = underlying_field_type_value::zero();
                            this->p[1] = underlying_field_type_value::one();
                            this->p[2] = underlying_field_type_value::one();
                        }
                        else {
                            // go from inverted coordinates to projective coordinates
                            underlying_field_type_value tX = this->p[1] * this->p[2];
                            underlying_field_type_value tY = this->p[0] * this->p[2];
                            underlying_field_type_value tZ = this->p[0] * this->p[1];
                            // go from projective coordinates to affine coordinates
                            underlying_field_type_value tZ_inv = tZ.inverse();
                            this->p[0] = tX * tZ_inv;
                            this->p[1] = tY * tZ_inv;
                            this->p[2] = underlying_field_type_value::one();
                        }
                    }

                    void to_special() {
                        if (this->p[2].is_zero()) {
                            return;
                        }

                        underlying_field_type_value Z_inv = this->p[2].inverse();
                        this->p[0] = this->p[0] * Z_inv;
                        this->p[1] = this->p[1] * Z_inv;
                        this->p[2] = underlying_field_type_value::one();
                    }

                    bool is_special() const {
                        return (this->is_zero() || this->p[2] == underlying_field_type_value::one());
                    }

                    underlying_field_type_value mul_by_a(const underlying_field_type_value &elt) {
                        // should be
                        //  underlying_field_type_value(edwards_twist_mul_by_a_c0 * elt.c2, edwards_twist_mul_by_a_c1 *
                        //  elt.c0, edwards_twist_mul_by_a_c2 * elt.c1)
                        // but optimizing the fact that edwards_twist_mul_by_a_c1 = edwards_twist_mul_by_a_c2 = 1
                        return underlying_field_type_value(twist_mul_by_a_c0 * elt.c2, elt.c0, elt.c1);
                    }

                    underlying_field_type_value mul_by_d(const underlying_field_type_value &elt) {
                        return underlying_field_type_value(twist_mul_by_d_c0 * elt.c2,
                                                           twist_mul_by_d_c1 * elt.c0,
                                                           twist_mul_by_d_c2 * elt.c1);
                    }

                private:

                    constexpr static const typename policy_type::number_type a = policy_type::a;
                    constexpr static const typename policy_type::number_type d = policy_type::d;

                    /*constexpr static */const g2_field_type_value
                        twist = g2_field_type_value(typename g2_field_type_value::underlying_type::zero(),
                                                    typename g2_field_type_value::underlying_type::one(),
                                                    typename g2_field_type_value::underlying_type::zero());
                    /*constexpr static */const g2_field_type_value twist_coeff_a = twist.mul_by_Fp(a);
                    /*constexpr static */const g2_field_type_value twist_coeff_d = twist.mul_by_Fp(d);

                    /*constexpr static */const g1_field_type_value twist_mul_by_a_c0 = a * g2_field_type_value::non_residue;
                    /*constexpr static */const g1_field_type_value twist_mul_by_a_c1 = a;
                    /*constexpr static */const g1_field_type_value twist_mul_by_a_c2 = a;
                    /*constexpr static */const g1_field_type_value twist_mul_by_d_c0 = d * g2_field_type_value::non_residue;
                    /*constexpr static */const g1_field_type_value twist_mul_by_d_c1 = d;
                    /*constexpr static */const g1_field_type_value twist_mul_by_d_c2 = d;
                    /*constexpr static */const g1_field_type_value
                        twist_mul_by_q_Y = g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);
                    /*constexpr static */const g1_field_type_value
                        twist_mul_by_q_Z = g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);

                    /*constexpr static const underlying_field_type_value zero_fill = {
                        underlying_field_type_value::zero(), 
                        underlying_field_type_value::one(),
                        underlying_field_type_value::zero()};

                    constexpr static const underlying_field_type_value one_fill = {
                        underlying_field_type_value(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,
                                                    0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,
                                                    0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),
                        underlying_field_type_value(0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,
                                                    0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,
                                                    0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182)};*/
                };

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_CURVES_EDWARDS_G2_HPP
