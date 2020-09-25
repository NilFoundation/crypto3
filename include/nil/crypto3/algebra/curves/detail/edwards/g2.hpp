//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_G2_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_G2_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/g1.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                    struct edwards_g2 {

                        using policy_type = edwards_basic_policy<ModulusBits, GeneratorBits>;
                        constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_type_value = g2_field_type_value;

                        constexpr static const std::size_t value_bits =  policy_type::g2_field_type::value_bits;

                        underlying_field_type_value X;
                        underlying_field_type_value Y;
                        underlying_field_type_value Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        edwards_g2() :
                            edwards_g2(
                                underlying_field_type_value(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,
                                                            0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,
                                                            0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),
                                underlying_field_type_value(
                                    0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,
                                    0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,
                                    0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182)) {};
                        // must be
                        // edwards_g2() : edwards_g2(one_fill[0], one_fill[1]) {};
                        // when constexpr fields will be finished

                        edwards_g2(underlying_field_type_value in_X, underlying_field_type_value in_Y,
                                   underlying_field_type_value in_Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;

                            // temporary, until fp3 will be literall
                            twist_mul_by_a_c0 = a * X.non_residue;
                            twist_mul_by_d_c0 = d * X.non_residue;
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
                            return edwards_g2(
                                underlying_field_type_value(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,
                                                            0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,
                                                            0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),
                                underlying_field_type_value(
                                    0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,
                                    0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,
                                    0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182));    // it's better to
                                                                                                    // precompute also
                                                                                                    // one_fill[2]
                            // must be
                            // return edwards_g2(one_fill[0], one_fill[1]);    // it's better to precompute also
                            // one_fill[2] when constexpr fields will be finished
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const edwards_g2 &other) const {
                            if (this->is_zero()) {
                                return other.is_zero();
                            }

                            if (other.is_zero()) {
                                return false;
                            }

                            /* now neither is O */

                            // X1/Z1 = X2/Z2 <=> X1*Z2 = X2*Z1
                            if ((this->X * other.Z) != (other.X * this->Z)) {
                                return false;
                            }

                            // Y1/Z1 = Y2/Z2 <=> Y1*Z2 = Y2*Z1
                            if ((this->Y * other.Z) != (other.Y * this->Z)) {
                                return false;
                            }

                            return true;
                        }

                        bool operator!=(const edwards_g2 &other) const {
                            return !(operator==(other));
                        }

                        bool is_zero() const {
                            return (this->Y.is_zero() && this->Z.is_zero());
                        }

                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_type_value::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        edwards_g2 operator=(const edwards_g2 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        edwards_g2 operator+(const edwards_g2 &other) const {
                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return (*this);
                            }

                            if (*this == other) {
                                return this->doubled();
                            }

                            return this->add(other);
                        }

                        edwards_g2 operator-() const {
                            return edwards_g2(-(this->X), this->Y, this->Z);
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

                                const underlying_field_type_value A = (this->X).squared();    // A = X1^2
                                const underlying_field_type_value B = (this->Y).squared();    // B = Y1^2
                                const underlying_field_type_value U = mul_by_a(B);               // U = a*B
                                const underlying_field_type_value C = A + U;                     // C = A+U
                                const underlying_field_type_value D = A - U;                     // D = A-U
                                const underlying_field_type_value E =
                                    (this->X + this->Y).squared() - A - B;    // E = (X1+Y1)^2-A-B
                                const underlying_field_type_value X3 = C * D;       // X3 = C*D
                                const underlying_field_type_value dZZ = mul_by_d(this->Z.squared());
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

                            const underlying_field_type_value A = this->Z;                     // A = Z1*Z2
                            const underlying_field_type_value B = mul_by_d(A.squared());          // B = d*A^2
                            const underlying_field_type_value C = (this->X) * (other.X);    // C = X1*X2
                            const underlying_field_type_value D = (this->Y) * (other.Y);    // D = Y1*Y2
                            const underlying_field_type_value E = C * D;                          // E = C*D
                            const underlying_field_type_value H = C - mul_by_a(D);                // H = C-a*D
                            const underlying_field_type_value I =
                                (this->X + this->Y) * (other.X + other.Y) - C -
                                D;                                                 // I = (X1+Y1)*(X2+Y2)-C-D
                            const underlying_field_type_value X3 = (E + B) * H;    // X3 = (E+B)*H
                            const underlying_field_type_value Y3 = (E - B) * I;    // Y3 = (E-B)*I
                            const underlying_field_type_value Z3 = A * H * I;      // Z3 = A*H*I

                            return edwards_g2(X3, Y3, Z3);
                        }

                    private:

                        edwards_g2 add(const edwards_g2 &other) const {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-inverted.html#addition-add-2008-bbjlp

                            const underlying_field_type_value A = (this->Z) * (other.Z);                       // A = Z1*Z2
                            const underlying_field_type_value B = this->mul_by_d(A.squared());           // B = d*A^2
                            const underlying_field_type_value C = (this->X) * (other.X);                       // C = X1*X2
                            const underlying_field_type_value D = (this->Y) * (other.Y);                       // D = Y1*Y2
                            const underlying_field_type_value E = C*D;                                         // E = C*D
                            const underlying_field_type_value H = C - this->mul_by_a(D);                 // H = C-a*D
                            const underlying_field_type_value I = (this->X+this->Y)*(other.X+other.Y)-C-D;     // I = (X1+Y1)*(X2+Y2)-C-D
                            const underlying_field_type_value X3 = (E+B)*H;                                    // X3 = (E+B)*H
                            const underlying_field_type_value Y3 = (E-B)*I;                                    // Y3 = (E-B)*I
                            const underlying_field_type_value Z3 = A*H*I;                                      // Z3 = A*H*I

                            return edwards_g2(X3, Y3, Z3);
                        }

                    public:

                        /*************************  Extra arithmetic operations  ***********************************/

                        /*inline static */ underlying_field_type_value
                            mul_by_a(const underlying_field_type_value &elt) const {
                            return underlying_field_type_value(twist_mul_by_a_c0 * elt.data[2], elt.data[0],
                                                               elt.data[1]);
                        }

                        /*inline static */ underlying_field_type_value
                            mul_by_d(const underlying_field_type_value &elt) const {
                            return underlying_field_type_value(twist_mul_by_d_c0 * elt.data[2],
                                                               twist_mul_by_d_c1 * elt.data[0],
                                                               twist_mul_by_d_c2 * elt.data[1]);
                        }

                        /*************************  Reducing operations  ***********************************/

                        edwards_g2 to_affine_coordinates() const {
                            underlying_field_type_value p_out[3];

                            if (this->is_zero()) {
                                p_out[0] = underlying_field_type_value::zero();
                                p_out[1] = underlying_field_type_value::one();
                                p_out[2] = underlying_field_type_value::one();
                            } else {
                                // go from inverted coordinates to projective coordinates
                                underlying_field_type_value tX = this->Y * this->Z;
                                underlying_field_type_value tY = this->X * this->Z;
                                underlying_field_type_value tZ = this->X * this->Y;
                                // go from projective coordinates to affine coordinates
                                underlying_field_type_value tZ_inv = tZ.inversed();
                                p_out[0] = tX * tZ_inv;
                                p_out[1] = tY * tZ_inv;
                                p_out[2] = underlying_field_type_value::one();
                            }

                            return edwards_g2(p_out[0], p_out[1], p_out[2]);
                        }

                        edwards_g2 to_special() const {
                            underlying_field_type_value p_out[3];

                            if (this->Z.is_zero()) {
                                return *this;
                            }

                            underlying_field_type_value Z_inv = this->Z.inversed();
                            p_out[0] = this->X * Z_inv;
                            p_out[1] = this->Y * Z_inv;
                            p_out[2] = underlying_field_type_value::one();

                            return edwards_g2(p_out[0], p_out[1], p_out[2]);
                        }

                    private:

                        /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                        /*constexpr static */ const g1_field_type_value d = g1_field_type_value(policy_type::d);

                        /*constexpr static */ const g2_field_type_value twist = g2_field_type_value( 
                                                {g2_field_type_value::underlying_type::zero(), 
                                                 g2_field_type_value::underlying_type::one(),
                                                 g2_field_type_value::underlying_type::zero()});
                        ;
                        /*constexpr static */ const g2_field_type_value twist_coeff_a = a * twist;
                        /*constexpr static */ const g2_field_type_value twist_coeff_d = d * twist;

                        /*constexpr static const*/ g1_field_type_value twist_mul_by_a_c0;
                        /*constexpr static */ const g1_field_type_value twist_mul_by_a_c1 = a;
                        /*constexpr static */ const g1_field_type_value twist_mul_by_a_c2 = a;
                        /*constexpr static const*/ g1_field_type_value twist_mul_by_d_c0;
                        /*constexpr static */ const g1_field_type_value twist_mul_by_d_c1 = d;
                        /*constexpr static */ const g1_field_type_value twist_mul_by_d_c2 = d;
                        /*constexpr static */ const g1_field_type_value twist_mul_by_q_Y =
                            g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);
                        /*constexpr static */ const g1_field_type_value twist_mul_by_q_Z =
                            g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);

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
    }                // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_CURVES_EDWARDS_G2_HPP
