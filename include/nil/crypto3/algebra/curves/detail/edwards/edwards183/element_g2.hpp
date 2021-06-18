//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#include <nil/crypto3/algebra/curves/detail/edwards/edwards183/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/jubjub/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/babyjubjub/basic_policy.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /** @brief A struct representing a group G2 of Edwards curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct edwards_g2;
                    /** @brief A struct representing an element from the group G2 of Edwards curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct element_edwards_g2 { };
                    /** @brief A struct representing an elememnt from the group G2 of Edwards curve.
                     *
                     */
                    template<>
                    struct element_edwards_g2<183> {

                        using group_type = edwards_g2<183>;

                        using policy_type = edwards_basic_policy<183>;
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
                        constexpr element_edwards_g2() : element_edwards_g2(policy_type::g2_zero_fill[0], policy_type::g2_zero_fill[1], policy_type::g2_zero_fill[2]) {};

                        /** @brief
                         *    @return the selected point $(X:Y:Z)$ in the projective coordinates
                         *
                         */
                        constexpr element_edwards_g2(underlying_field_value_type in_X, underlying_field_value_type in_Y,
                                           underlying_field_value_type in_Z) {
                            this->X = in_X;
                            this->Y = in_Y;
                            this->Z = in_Z;
                        };
                        /** @brief
                         *    @return the selected point $(X:Y:X*Y)$ in the inverted coordinates
                         *
                         */
                        constexpr element_edwards_g2(underlying_field_value_type X, underlying_field_value_type Y) :
                            element_edwards_g2(X, Y, X * Y) {};
                        /** @brief Get the point at infinity
                         *
                         */
                        constexpr static element_edwards_g2 zero() {
                            return element_edwards_g2(policy_type::g2_zero_fill[0], policy_type::g2_zero_fill[1], policy_type::g2_zero_fill[2]);
                        }
                        /** @brief Get the generator of group G2
                         *
                         */
                        constexpr static element_edwards_g2 one() {
                            return element_edwards_g2(policy_type::g2_one_fill[0], policy_type::g2_one_fill[1]);    // it's better to precompute also
                            // policy_type::g2_one_fill[2] 
                        }

                        /*************************  Comparison operations  ***********************************/

                        constexpr bool operator==(const element_edwards_g2 &other) const {
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

                        constexpr bool operator!=(const element_edwards_g2 &other) const {
                            return !(operator==(other));
                        }
                        /** @brief
                         *
                         * @return true if element from group G2 is the point at infinity
                         */
                        constexpr bool is_zero() const {
                            return (this->Y.is_zero() && this->Z.is_zero());
                        }
                        /** @brief
                         *
                         * @return true if element from group G2 in affine coordinates
                         */
                        constexpr bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr element_edwards_g2 operator=(const element_edwards_g2 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        constexpr element_edwards_g2 operator+(const element_edwards_g2 &other) const {
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

                        constexpr element_edwards_g2 operator-() const {
                            return element_edwards_g2(-(this->X), this->Y, this->Z);
                        }

                        constexpr element_edwards_g2 operator-(const element_edwards_g2 &other) const {
                            return (*this) + (-other);
                        }
                        /** @brief
                         *
                         * @return doubled element from group G2
                         */
                        constexpr element_edwards_g2 doubled() const {

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
                        constexpr element_edwards_g2 mixed_add(const element_edwards_g2 &other) const {

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
                        constexpr element_edwards_g2 add(const element_edwards_g2 &other) const {
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

                        constexpr inline static underlying_field_value_type
                            mul_by_a(const underlying_field_value_type &elt) {
                            return underlying_field_value_type(twist_mul_by_a_c0 * elt.data[2], elt.data[0],
                                                               elt.data[1]);
                        }

                        constexpr inline static underlying_field_value_type
                            mul_by_d(const underlying_field_value_type &elt) {
                            return underlying_field_value_type(twist_mul_by_d_c0 * elt.data[2],
                                                               twist_mul_by_d_c1 * elt.data[0],
                                                               twist_mul_by_d_c2 * elt.data[1]);
                        }

                        /*************************  Reducing operations  ***********************************/
                        /** @brief
                         *
                         * @return return the corresponding element from inverted coordinates to affine coordinates
                         */
                        constexpr element_edwards_g2 to_affine() const {
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
                        constexpr element_edwards_g2 to_projective() const {
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

                        constexpr static const g2_field_type_value twist = g2_field_type_value(
                            g2_field_type_value::underlying_type::zero(), g2_field_type_value::underlying_type::one(),
                            g2_field_type_value::underlying_type::zero());

                    private:
                        constexpr static const g1_field_type_value a = policy_type::a;
                        constexpr static const g1_field_type_value d = policy_type::d;

                        constexpr static const g2_field_type_value twist_coeff_a = a * twist;
                        constexpr static const g2_field_type_value twist_coeff_d = d * twist;

                        constexpr static g1_field_type_value twist_mul_by_a_c0 = a * g2_field_type_value::non_residue;
                        constexpr static const g1_field_type_value twist_mul_by_a_c1 = a;
                        constexpr static const g1_field_type_value twist_mul_by_a_c2 = a;
                        constexpr static g1_field_type_value twist_mul_by_d_c0 = d * g2_field_type_value::non_residue;
                        constexpr static const g1_field_type_value twist_mul_by_d_c1 = d;
                        constexpr static const g1_field_type_value twist_mul_by_d_c2 = d;
                        constexpr static const g1_field_type_value twist_mul_by_q_Y =
                            g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);
                        constexpr static const g1_field_type_value twist_mul_by_q_Z =
                            g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);

                    };

                    constexpr typename element_edwards_g2<183>::g1_field_type_value const element_edwards_g2<183>::a;
                    constexpr typename element_edwards_g2<183>::g1_field_type_value const element_edwards_g2<183>::d;

                    constexpr typename element_edwards_g2<183>::g2_field_type_value const
                        element_edwards_g2<183>::twist_coeff_a;
                    constexpr typename element_edwards_g2<183>::g2_field_type_value const
                        element_edwards_g2<183>::twist_coeff_d;

                    constexpr typename element_edwards_g2<183>::g1_field_type_value const
                        element_edwards_g2<183>::twist_mul_by_a_c1;
                    constexpr typename element_edwards_g2<183>::g1_field_type_value const
                        element_edwards_g2<183>::twist_mul_by_a_c2;

                    constexpr typename element_edwards_g2<183>::g1_field_type_value const
                        element_edwards_g2<183>::twist_mul_by_d_c1;
                    constexpr typename element_edwards_g2<183>::g1_field_type_value const
                        element_edwards_g2<183>::twist_mul_by_d_c2;

                    constexpr typename element_edwards_g2<183>::g1_field_type_value const
                        element_edwards_g2<183>::twist_mul_by_q_Y;
                    constexpr typename element_edwards_g2<183>::g1_field_type_value const
                        element_edwards_g2<183>::twist_mul_by_q_Z;

                    constexpr typename element_edwards_g2<183>::g1_field_type_value element_edwards_g2<183>::twist_mul_by_a_c0;
                    constexpr typename element_edwards_g2<183>::g1_field_type_value element_edwards_g2<183>::twist_mul_by_d_c0;
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_ELEMENT_HPP
