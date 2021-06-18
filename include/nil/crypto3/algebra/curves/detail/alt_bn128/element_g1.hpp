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

#ifndef CRYPTO3_ALGEBRA_CURVES_ALT_BN128_G1_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_CURVES_ALT_BN128_G1_ELEMENT_HPP

#include <nil/crypto3/algebra/curves/detail/alt_bn128/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing a group G1 of Barreto-Naehrig curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct alt_bn128_g1;

                    /** @brief A struct representing an element from the group G1 of Barreto-Naehrig curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct element_alt_bn128_g1 { };

                    /** @brief A struct representing an element from the group G1 of Barreto-Naehrig curve.
                     *
                     * The size of the group G1 in bits equals 254.
                     */
                    template<>
                    struct element_alt_bn128_g1<254> {

                        using group_type = alt_bn128_g1<254>;

                        using policy_type = alt_bn128_basic_policy<254>;
                        
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_value_type = g1_field_type_value;

                        underlying_field_value_type X;
                        underlying_field_value_type Y;
                        underlying_field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr element_alt_bn128_g1() : element_alt_bn128_g1(policy_type::g1_zero_fill[0], 
                            policy_type::g1_zero_fill[1], policy_type::g1_zero_fill[2]) {};

                        /** @brief
                         *    @return the selected point (X:Y:Z)
                         *
                         */
                        constexpr element_alt_bn128_g1(underlying_field_value_type in_X, underlying_field_value_type in_Y,
                                             underlying_field_value_type in_Z) {
                            this->X = in_X;
                            this->Y = in_Y;
                            this->Z = in_Z;
                        };

                        /** @brief Get the point at infinity
                         *
                         */
                        constexpr static element_alt_bn128_g1 zero() {
                            return element_alt_bn128_g1();
                        }

                        /** @brief Get the generator of group G1
                         *
                         */
                        constexpr static element_alt_bn128_g1 one() {
                            return element_alt_bn128_g1(policy_type::g1_one_fill[0], policy_type::g1_one_fill[1], 
                                policy_type::g1_one_fill[2]);
                        }

                        constexpr bool operator==(const element_alt_bn128_g1 &other) const {
                            if (this->is_zero()) {
                                return other.is_zero();
                            }

                            if (other.is_zero()) {
                                return false;
                            }

                            /* now neither is O */

                            // using Jacobian coordinates so:
                            // (X1:Y1:Z1) = (X2:Y2:Z2)
                            // iff
                            // X1/Z1^2 == X2/Z2^2 and Y1/Z1^3 == Y2/Z2^3
                            // iff
                            // X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3

                            underlying_field_value_type Z1_squared = (this->Z).squared();
                            underlying_field_value_type Z2_squared = (other.Z).squared();

                            if ((this->X * Z2_squared) != (other.X * Z1_squared)) {
                                return false;
                            }

                            underlying_field_value_type Z1_cubed = (this->Z) * Z1_squared;
                            underlying_field_value_type Z2_cubed = (other.Z) * Z2_squared;

                            if ((this->Y * Z2_cubed) != (other.Y * Z1_cubed)) {
                                return false;
                            }

                            return true;
                        }

                        constexpr bool operator!=(const element_alt_bn128_g1 &other) const {
                            return !(operator==(other));
                        }
                        /** @brief
                         *
                         * @return true if element from group G1 is the point at infinity
                         */
                        constexpr bool is_zero() const {
                            return (this->Z.is_zero());
                        }
                        /** @brief
                         *
                         * @return true if element from group G1 in affine coordinates
                         */
                        constexpr bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr element_alt_bn128_g1 operator=(const element_alt_bn128_g1 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        constexpr element_alt_bn128_g1 operator+(const element_alt_bn128_g1 &other) const {
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

                        constexpr element_alt_bn128_g1 operator-() const {
                            return element_alt_bn128_g1(this->X, -(this->Y), this->Z);
                        }

                        constexpr element_alt_bn128_g1 operator-(const element_alt_bn128_g1 &other) const {
                            return (*this) + (-other);
                        }
                        /** @brief
                         *
                         * @return doubled element from group G1
                         */
                        constexpr element_alt_bn128_g1 doubled() const {

                            // handle point at infinity
                            if (this->is_zero()) {
                                return (*this);
                            }

                            // no need to handle points of order 2,4
                            // (they cannot exist in a prime-order subgroup)

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

                            underlying_field_value_type A = (this->X).squared();    // A = X1^2
                            underlying_field_value_type B = (this->Y).squared();    // B = Y1^2
                            underlying_field_value_type C = B.squared();            // C = B^2
                            underlying_field_value_type D = (this->X + B).squared() - A - C;
                            D = D + D;                                           // D = 2 * ((X1 + B)^2 - A - C)
                            underlying_field_value_type E = A.doubled() + A;     // E = 3 * A
                            underlying_field_value_type F = E.squared();         // F = E^2
                            underlying_field_value_type X3 = F - D.doubled();    // X3 = F - 2 D
                            underlying_field_value_type eightC = C.doubled().doubled().doubled();
                            underlying_field_value_type Y3 = E * (D - X3) - eightC;    // Y3 = E * (D - X3) - 8 * C
                            underlying_field_value_type Y1Z1 = (this->Y) * (this->Z);
                            underlying_field_value_type Z3 = Y1Z1 + Y1Z1;    // Z3 = 2 * Y1 * Z1

                            return element_alt_bn128_g1(X3, Y3, Z3);
                        }

                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G1
                         */
                        constexpr element_alt_bn128_g1 mixed_add(const element_alt_bn128_g1 &other) const {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return *this;
                            }

                            // no need to handle points of order 2,4
                            // (they cannot exist in a prime-order subgroup)

                            // check for doubling case

                            // using Jacobian coordinates so:
                            // (X1:Y1:Z1) = (X2:Y2:Z2)
                            // iff
                            // X1/Z1^2 == X2/Z2^2 and Y1/Z1^3 == Y2/Z2^3
                            // iff
                            // X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3

                            // we know that Z2 = 1

                            const underlying_field_value_type Z1Z1 = (this->Z).squared();

                            const underlying_field_value_type &U1 = this->X;
                            const underlying_field_value_type U2 = other.X * Z1Z1;

                            const underlying_field_value_type Z1_cubed = (this->Z) * Z1Z1;

                            const underlying_field_value_type &S1 = (this->Y);              // S1 = Y1 * Z2 * Z2Z2
                            const underlying_field_value_type S2 = (other.Y) * Z1_cubed;    // S2 = Y2 * Z1 * Z1Z1

                            if (U1 == U2 && S1 == S2) {
                                // dbl case; nothing of above can be reused
                                return this->doubled();
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
                            underlying_field_value_type H = U2 - (this->X);    // H = U2-X1
                            underlying_field_value_type HH = H.squared();      // HH = H&2
                            underlying_field_value_type I = HH + HH;           // I = 4*HH
                            I = I + I;
                            underlying_field_value_type J = H * I;             // J = H*I
                            underlying_field_value_type r = S2 - (this->Y);    // r = 2*(S2-Y1)
                            r = r + r;
                            underlying_field_value_type V = (this->X) * I;               // V = X1*I
                            underlying_field_value_type X3 = r.squared() - J - V - V;    // X3 = r^2-J-2*V
                            underlying_field_value_type Y3 = (this->Y) * J;              // Y3 = r*(V-X3)-2*Y1*J
                            Y3 = r * (V - X3) - Y3 - Y3;
                            underlying_field_value_type Z3 =
                                ((this->Z) + H).squared() - Z1Z1 - HH;    // Z3 = (Z1+H)^2-Z1Z1-HH

                            return element_alt_bn128_g1(X3, Y3, Z3);
                        }

                    private:
                        constexpr element_alt_bn128_g1 add(const element_alt_bn128_g1 &other) const {

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl

                            underlying_field_value_type Z1Z1 = (this->Z).squared();           // Z1Z1 = Z1^2
                            underlying_field_value_type Z2Z2 = (other.Z).squared();           // Z2Z2 = Z2^2
                            underlying_field_value_type U1 = (this->X) * Z2Z2;                // U1 = X1 * Z2Z2
                            underlying_field_value_type U2 = (other.X) * Z1Z1;                // U2 = X2 * Z1Z1
                            underlying_field_value_type S1 = (this->Y) * (other.Z) * Z2Z2;    // S1 = Y1 * Z2 * Z2Z2
                            underlying_field_value_type S2 = (other.Y) * (this->Z) * Z1Z1;    // S2 = Y2 * Z1 * Z1Z1
                            underlying_field_value_type H = U2 - U1;                          // H = U2-U1
                            underlying_field_value_type S2_minus_S1 = S2 - S1;
                            underlying_field_value_type I = H.doubled().squared();             // I = (2 * H)^2
                            underlying_field_value_type J = H * I;                             // J = H * I
                            underlying_field_value_type r = S2_minus_S1.doubled();             // r = 2 * (S2-S1)
                            underlying_field_value_type V = U1 * I;                            // V = U1 * I
                            underlying_field_value_type X3 = r.squared() - J - V.doubled();    // X3 = r^2 - J - 2 * V
                            underlying_field_value_type S1_J = S1 * J;
                            underlying_field_value_type Y3 = r * (V - X3) - S1_J.doubled();    // Y3 = r * (V-X3)-2 S1 J
                            underlying_field_value_type Z3 =
                                ((this->Z + other.Z).squared() - Z1Z1 - Z2Z2) * H;    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2) * H

                            return element_alt_bn128_g1(X3, Y3, Z3);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/

                        /** @brief
                         *
                         * @return return the corresponding element from group G1 in affine coordinates
                         */
                        constexpr element_alt_bn128_g1 to_affine() {
                            underlying_field_value_type p_out[3];

                            if (this->is_zero()) {
                                p_out[0] = underlying_field_value_type::zero();
                                p_out[1] = underlying_field_value_type::one();
                                p_out[2] = underlying_field_value_type::zero();
                            } else {
                                underlying_field_value_type Z_inv = this->Z.inversed();
                                underlying_field_value_type Z2_inv = Z_inv.squared();
                                underlying_field_value_type Z3_inv = Z2_inv * Z_inv;
                                p_out[0] = this->X * Z2_inv;
                                p_out[1] = this->Y * Z3_inv;
                                p_out[2] = underlying_field_value_type::one();
                            }

                            return element_alt_bn128_g1(p_out[0], p_out[1], p_out[2]);
                        }

                        /** @brief
                         *
                         * @return return the corresponding element from group G1 in affine coordinates
                         */
                        constexpr element_alt_bn128_g1 to_projective() {
                            return this->to_affine();
                        }
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_ALT_BN128_G1_ELEMENT_HPP
