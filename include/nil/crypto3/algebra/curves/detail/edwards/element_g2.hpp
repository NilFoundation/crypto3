//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_G2_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_G2_ELEMENT_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /** @brief A struct representing a group G2 of Edwards curve.
                     *    @tparam ModulusBits size of the base field in bits
                     *
                     */
                    template<std::size_t ModulusBits>
                    struct edwards_g2;
                    /** @brief A struct representing an element from the group G2 of Edwards curve.
                     *    @tparam ModulusBits size of the base field in bits
                     *
                     */
                    template<std::size_t ModulusBits>
                    struct element_edwards_g2 { };
                    /** @brief A struct representing an elememnt from the group G2 of Edwards curve.
                     *
                     * The size of the group G1 in bits equals 181.
                     */
                    template<>
                    struct element_edwards_g2<183> {

                        using group_type = edwards_g2<183>;

                        using policy_type = edwards_basic_policy<183>;
                        constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_value_type = g2_field_type_value;

                        underlying_field_value_type X;
                        underlying_field_value_type Y;
                        underlying_field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/
                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        element_edwards_g2() :
                            element_edwards_g2(underlying_field_value_type::zero(), underlying_field_value_type::one(),
                                               underlying_field_value_type::zero()) {};
                        // must be
                        // element_edwards_g2() : element_edwards_g2(one_fill[0], one_fill[1]) {};
                        // when constexpr fields will be finished

                        /** @brief
                         *    @return the selected point $(X:Y:Z)$ in the projective coordinates
                         *
                         */
                        element_edwards_g2(underlying_field_value_type in_X, underlying_field_value_type in_Y,
                                           underlying_field_value_type in_Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;

                            // temporary, until fp3 will be literall
                            twist_mul_by_a_c0 = a * X.non_residue;
                            twist_mul_by_d_c0 = d * X.non_residue;
                        };
                        /** @brief
                         *    @return the selected point $(X:Y:X*Y)$ in the inverted coordinates
                         *
                         */
                        element_edwards_g2(underlying_field_value_type X, underlying_field_value_type Y) :
                            element_edwards_g2(X, Y, X * Y) {};
                        /** @brief Get the point at infinity
                         *
                         */
                        static element_edwards_g2 zero() {
                            return element_edwards_g2(underlying_field_value_type::zero(),
                                                      underlying_field_value_type::one(),
                                                      underlying_field_value_type::zero());
                            // must be
                            // return element_edwards_g2(zero_fill[0], zero_fill[1], zero_fill[2]);
                            // when constexpr fields will be finished
                        }
                        /** @brief Get the generator of group G2
                         *
                         */
                        static element_edwards_g2 one() {
                            return element_edwards_g2(
                                underlying_field_value_type(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,
                                                            0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,
                                                            0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),
                                underlying_field_value_type(
                                    0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,
                                    0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,
                                    0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182));    // it's better to
                                                                                                    // precompute also
                                                                                                    // one_fill[2]
                            // must be
                            // return element_edwards_g2(one_fill[0], one_fill[1]);    // it's better to precompute also
                            // one_fill[2] when constexpr fields will be finished
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const element_edwards_g2 &other) const {
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

                        bool operator!=(const element_edwards_g2 &other) const {
                            return !(operator==(other));
                        }
                        /** @brief
                         *
                         * @return true if element from group G2 is the point at infinity
                         */
                        bool is_zero() const {
                            return (this->Y.is_zero() && this->Z.is_zero());
                        }
                        /** @brief
                         *
                         * @return true if element from group G2 in affine coordinates
                         */
                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        element_edwards_g2 operator=(const element_edwards_g2 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        element_edwards_g2 operator+(const element_edwards_g2 &other) const {
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

                        element_edwards_g2 operator-() const {
                            return element_edwards_g2(-(this->X), this->Y, this->Z);
                        }

                        element_edwards_g2 operator-(const element_edwards_g2 &other) const {
                            return (*this) + (-other);
                        }
                        /** @brief
                         *
                         * @return doubled element from group G2
                         */
                        element_edwards_g2 doubled() const {

                            if (this->is_zero()) {
                                return (*this);
                            } else {
                                // NOTE: does not handle O and pts of order 2,4
                                // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-inverted.html#doubling-dbl-2008-bbjlp

                                const underlying_field_value_type A = (this->X).squared();    // A = X1^2
                                const underlying_field_value_type B = (this->Y).squared();    // B = Y1^2
                                const underlying_field_value_type U = mul_by_a(B);            // U = a*B
                                const underlying_field_value_type C = A + U;                  // C = A+U
                                const underlying_field_value_type D = A - U;                  // D = A-U
                                const underlying_field_value_type E =
                                    (this->X + this->Y).squared() - A - B;       // E = (X1+Y1)^2-A-B
                                const underlying_field_value_type X3 = C * D;    // X3 = C*D
                                const underlying_field_value_type dZZ = mul_by_d(this->Z.squared());
                                const underlying_field_value_type Y3 = E * (C - dZZ - dZZ);    // Y3 = E*(C-2*d*Z1^2)
                                const underlying_field_value_type Z3 = D * E;                  // Z3 = D*E

                                return element_edwards_g2(X3, Y3, Z3);
                            }
                        }
                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G2
                         */
                        element_edwards_g2 mixed_add(const element_edwards_g2 &other) const {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return *this;
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-madd-2007-lb

                            const underlying_field_value_type A = this->Z;                  // A = Z1*Z2
                            const underlying_field_value_type B = mul_by_d(A.squared());    // B = d*A^2
                            const underlying_field_value_type C = (this->X) * (other.X);    // C = X1*X2
                            const underlying_field_value_type D = (this->Y) * (other.Y);    // D = Y1*Y2
                            const underlying_field_value_type E = C * D;                    // E = C*D
                            const underlying_field_value_type H = C - mul_by_a(D);          // H = C-a*D
                            const underlying_field_value_type I =
                                (this->X + this->Y) * (other.X + other.Y) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                            const underlying_field_value_type X3 = (E + B) * H;       // X3 = (E+B)*H
                            const underlying_field_value_type Y3 = (E - B) * I;       // Y3 = (E-B)*I
                            const underlying_field_value_type Z3 = A * H * I;         // Z3 = A*H*I

                            return element_edwards_g2(X3, Y3, Z3);
                        }

                    private:
                        element_edwards_g2 add(const element_edwards_g2 &other) const {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-inverted.html#addition-add-2008-bbjlp

                            const underlying_field_value_type A = (this->Z) * (other.Z);          // A = Z1*Z2
                            const underlying_field_value_type B = this->mul_by_d(A.squared());    // B = d*A^2
                            const underlying_field_value_type C = (this->X) * (other.X);          // C = X1*X2
                            const underlying_field_value_type D = (this->Y) * (other.Y);          // D = Y1*Y2
                            const underlying_field_value_type E = C * D;                          // E = C*D
                            const underlying_field_value_type H = C - this->mul_by_a(D);          // H = C-a*D
                            const underlying_field_value_type I =
                                (this->X + this->Y) * (other.X + other.Y) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                            const underlying_field_value_type X3 = (E + B) * H;       // X3 = (E+B)*H
                            const underlying_field_value_type Y3 = (E - B) * I;       // Y3 = (E-B)*I
                            const underlying_field_value_type Z3 = A * H * I;         // Z3 = A*H*I

                            return element_edwards_g2(X3, Y3, Z3);
                        }

                    public:
                        /*************************  Extra arithmetic operations  ***********************************/

                        /*inline static */ underlying_field_value_type
                            mul_by_a(const underlying_field_value_type &elt) const {
                            return underlying_field_value_type(twist_mul_by_a_c0 * elt.data[2], elt.data[0],
                                                               elt.data[1]);
                        }

                        /*inline static */ underlying_field_value_type
                            mul_by_d(const underlying_field_value_type &elt) const {
                            return underlying_field_value_type(twist_mul_by_d_c0 * elt.data[2],
                                                               twist_mul_by_d_c1 * elt.data[0],
                                                               twist_mul_by_d_c2 * elt.data[1]);
                        }

                        /*************************  Reducing operations  ***********************************/
                        /** @brief
                         *
                         * @return return the corresponding element from inverted coordinates to affine coordinates
                         */
                        element_edwards_g2 to_affine_coordinates() const {
                            underlying_field_value_type p_out[3];

                            if (this->is_zero()) {
                                p_out[0] = underlying_field_value_type::zero();
                                p_out[1] = underlying_field_value_type::one();
                                p_out[2] = underlying_field_value_type::one();
                            } else {
                                // go from inverted coordinates to projective coordinates
                                underlying_field_value_type tX = this->Y * this->Z;
                                underlying_field_value_type tY = this->X * this->Z;
                                underlying_field_value_type tZ = this->X * this->Y;
                                // go from projective coordinates to affine coordinates
                                underlying_field_value_type tZ_inv = tZ.inversed();
                                p_out[0] = tX * tZ_inv;
                                p_out[1] = tY * tZ_inv;
                                p_out[2] = underlying_field_value_type::one();
                            }

                            return element_edwards_g2(p_out[0], p_out[1], p_out[2]);
                        }
                        /** @brief
                         *
                         * @return return the corresponding element from projective coordinates to affine coordinates
                         */
                        element_edwards_g2 to_special() const {
                            underlying_field_value_type p_out[3];

                            if (this->Z.is_zero()) {
                                return *this;
                            }

                            underlying_field_value_type Z_inv = this->Z.inversed();
                            p_out[0] = this->X * Z_inv;
                            p_out[1] = this->Y * Z_inv;
                            p_out[2] = underlying_field_value_type::one();

                            return element_edwards_g2(p_out[0], p_out[1], p_out[2]);
                        }

                    private:
                        /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                        /*constexpr static */ const g1_field_type_value d = g1_field_type_value(policy_type::d);

                        /*constexpr static */ const g2_field_type_value twist = g2_field_type_value(
                            g2_field_type_value::underlying_type::zero(), g2_field_type_value::underlying_type::one(),
                             g2_field_type_value::underlying_type::zero());
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

                        /*constexpr static const underlying_field_value_type zero_fill = {
                            underlying_field_value_type::zero(),
                            underlying_field_value_type::one(),
                            underlying_field_value_type::zero()};

                        constexpr static const underlying_field_value_type one_fill = {
                            underlying_field_value_type(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,
                                                        0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,
                                                        0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),
                            underlying_field_value_type(0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,
                                                        0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,
                                                        0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182)};*/
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_ELEMENT_HPP
