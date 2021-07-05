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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_G1_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_G1_ELEMENT_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/edwards183/basic_policy.hpp>

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /** @brief A struct representing a group G1 of Edwards curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct edwards_g1;
                    /** @brief A struct representing an element from the group G1 of edwards curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct element_edwards_g1 { };
                    /** @brief A struct representing an element from the group G1 of edwards curve.
                     *
                     */
                    template<>
                    struct element_edwards_g1<183> {
                        constexpr static const std::size_t version = 183;

                        using group_type = edwards_g1<version>;

                        using policy_type = edwards_basic_policy<version>;
                        using underlying_field_type = typename policy_type::g1_field_type;

                        using g1_field_type_value = typename policy_type::g1_field_type::value_type;
                        // must be removed later

                        typedef typename underlying_field_type::value_type underlying_field_value_type;

                        underlying_field_value_type X;
                        underlying_field_value_type Y;
                        underlying_field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/
                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr element_edwards_g1() : element_edwards_g1(policy_type::g1_zero_fill[0], 
                            policy_type::g1_zero_fill[1], policy_type::g1_zero_fill[2]) {};

                        /** @brief
                         *    @return the selected point $(X:Y:Z)$ in the projective coordinates
                         *
                         */
                        constexpr element_edwards_g1(underlying_field_value_type in_X, underlying_field_value_type in_Y,
                                           underlying_field_value_type in_Z) {
                            this->X = in_X;
                            this->Y = in_Y;
                            this->Z = in_Z;
                        };
                        /** @brief
                         *    @return the selected point $(X:Y:X*Y)$ in the inverted coordinates
                         *
                         */
                        constexpr element_edwards_g1(underlying_field_value_type X, underlying_field_value_type Y) :
                            element_edwards_g1(Y, X, X * Y) {};

                        /** @brief Get the point at infinity
                         *
                         */
                        static element_edwards_g1 zero() {
                            return element_edwards_g1();
                        }
                        /** @brief Get the generator of group G1
                         *
                         */
                        static element_edwards_g1 one() {
                            return element_edwards_g1(policy_type::g1_one_fill[0], policy_type::g1_one_fill[1], 
                                policy_type::g1_one_fill[2]);
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const element_edwards_g1 &other) const {
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

                        bool operator!=(const element_edwards_g1 &other) const {
                            return !(operator==(other));
                        }
                        /** @brief
                         *
                         * @return true if element from group G1 is the point at infinity
                         */
                        bool is_zero() const {
                            return (this->Y.is_zero() && this->Z.is_zero());
                        }
                        /** @brief
                         *
                         * @return true if element from group G1 in affine coordinates
                         */
                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        element_edwards_g1 operator=(const element_edwards_g1 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        element_edwards_g1 operator+(const element_edwards_g1 &other) const {
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

                        element_edwards_g1 operator-() const {
                            return element_edwards_g1(-(this->X), this->Y, this->Z);
                        }

                        element_edwards_g1 operator-(const element_edwards_g1 &B) const {
                            return (*this) + (-B);
                        }
                        /** @brief
                         *
                         * @return doubled element from group G1
                         */
                        element_edwards_g1 doubled() const {

                            if (this->is_zero()) {
                                return (*this);
                            } else {
                                // NOTE: does not handle O and pts of order 2,4
                                // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#doubling-dbl-2007-bl

                                underlying_field_value_type A = (this->X).squared();                  // A = X1^2
                                underlying_field_value_type B = (this->Y).squared();                  // B = Y1^2
                                underlying_field_value_type C = A + B;                                // C = A+B
                                underlying_field_value_type D = A - B;                                // D = A-B
                                underlying_field_value_type E = (this->X + this->Y).squared() - C;    // E = (X1+Y1)^2-C
                                underlying_field_value_type X3 = C * D;                               // X3 = C*D
                                underlying_field_value_type dZZ = d * this->Z.squared();
                                underlying_field_value_type Y3 = E * (C - dZZ - dZZ);    // Y3 = E*(C-2*d*Z1^2)
                                underlying_field_value_type Z3 = D * E;                  // Z3 = D*E

                                return element_edwards_g1(X3, Y3, Z3);
                            }
                        }
                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G1
                         */
                        element_edwards_g1 mixed_add(const element_edwards_g1 &other) const {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return *this;
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-madd-2007-lb

                            underlying_field_value_type A = this->Z;                  // A = Z1
                            underlying_field_value_type B = d * A.squared();          // B = d*A^2
                            underlying_field_value_type C = (this->X) * (other.X);    // C = X1*X2
                            underlying_field_value_type D = (this->Y) * (other.Y);    // D = Y1*Y2
                            underlying_field_value_type E = C * D;                    // E = C*D
                            underlying_field_value_type H = C - D;                    // H = C-D
                            underlying_field_value_type I =
                                (this->X + this->Y) * (other.X + other.Y) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                            underlying_field_value_type X3 = (E + B) * H;             // X3 = c*(E+B)*H
                            underlying_field_value_type Y3 = (E - B) * I;             // Y3 = c*(E-B)*I
                            underlying_field_value_type Z3 = A * H * I;               // Z3 = A*H*I

                            return element_edwards_g1(X3, Y3, Z3);
                        }

                    private:
                        element_edwards_g1 add(const element_edwards_g1 &other) const {

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-add-2007-bl

                            underlying_field_value_type A = (this->Z) * (other.Z);    // A = Z1*Z2
                            underlying_field_value_type B = d * A.squared();          // B = d*A^2
                            underlying_field_value_type C = (this->X) * (other.X);    // C = X1*X2
                            underlying_field_value_type D = (this->Y) * (other.Y);    // D = Y1*Y2
                            underlying_field_value_type E = C * D;                    // E = C*D
                            underlying_field_value_type H = C - D;                    // H = C-D
                            underlying_field_value_type I =
                                (this->X + this->Y) * (other.X + other.Y) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                            underlying_field_value_type X3 = (E + B) * H;             // X3 = c*(E+B)*H
                            underlying_field_value_type Y3 = (E - B) * I;             // Y3 = c*(E-B)*I
                            underlying_field_value_type Z3 = A * H * I;               // Z3 = A*H*I

                            return element_edwards_g1(X3, Y3, Z3);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/
                        /** @brief
                         *
                         * @return return the corresponding element from inverted coordinates to affine coordinates
                         */
                        element_edwards_g1 to_affine() const {
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

                            return element_edwards_g1(p_out[0], p_out[1], p_out[2]);
                        }
                        /** @brief
                         *
                         * @return return the corresponding element from projective coordinates to affine coordinates
                         */
                        element_edwards_g1 to_projective() const {
                            underlying_field_value_type p_out[3];

                            if (this->Z.is_zero()) {
                                return *this;
                            }

                            underlying_field_value_type Z_inv = this->Z.inversed();
                            p_out[0] = this->X * Z_inv;
                            p_out[1] = this->Y * Z_inv;
                            p_out[2] = underlying_field_value_type::one();

                            return element_edwards_g1(p_out[0], p_out[1], p_out[2]);
                        }

                    private:
                        constexpr static const g1_field_type_value a = policy_type::a;
                        constexpr static const g1_field_type_value d = policy_type::d;
                    };

                    constexpr typename element_edwards_g1<183>::g1_field_type_value const element_edwards_g1<183>::a;
                    
                    constexpr typename element_edwards_g1<183>::g1_field_type_value const element_edwards_g1<183>::d;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_G1_ELEMENT_HPP
