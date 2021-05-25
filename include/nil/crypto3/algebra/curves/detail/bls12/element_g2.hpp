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

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_G2_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_G2_ELEMENT_HPP

#include <nil/crypto3/algebra/curves/detail/bls12/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    /** @brief A struct representing a group G2 of BLS12- curve.
                     *    @tparam Version size of the base field in bits
                     *
                     */
                    template<std::size_t Version>
                    struct bls12_g2;

                    /** @brief A struct representing an element from the group G2 of BLS12 curve.
                     *    @tparam Version size of the base field in bits
                     *
                     */
                    template<std::size_t Version>
                    struct element_bls12_g2 { };

                    /** @brief A struct representing an elememnt from the group G2 of BLS12-381 curve.
                     *
                     * The size of the group G1 in bits equals 255.
                     */
                    template<>
                    struct element_bls12_g2<381> {

                        typedef bls12_g2<381> group_type;

                        typedef bls12_basic_policy<381> policy_type;
                        
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_type = typename policy_type::g2_field_type;
                        using underlying_field_value_type = underlying_field_type::value_type;

                        underlying_field_value_type X;
                        underlying_field_value_type Y;
                        underlying_field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/
                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr element_bls12_g2() : element_bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};

                        /** @brief
                         *    @return the selected point $(X:Y:Z)$
                         *
                         */
                        constexpr element_bls12_g2(underlying_field_value_type X,
                                                   underlying_field_value_type Y,
                                                   underlying_field_value_type Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };
                        /** @brief Get the point at infinity
                         *
                         */
                        constexpr static element_bls12_g2 zero() {
                            return element_bls12_g2();
                        }
                        /** @brief Get the generator of group G2
                         *
                         */
                        constexpr static element_bls12_g2 one() {
                            return element_bls12_g2(one_fill[0], one_fill[1], one_fill[2]);
                        }

                        /*************************  Comparison operations  ***********************************/

                        constexpr bool operator==(const element_bls12_g2 &other) const {
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

                        constexpr bool operator!=(const element_bls12_g2 &other) const {
                            return !(operator==(other));
                        }
                        /** @brief
                         *
                         * @return true if element from group G2 is the point at infinity
                         */
                        constexpr bool is_zero() const {
                            return (this->Z.is_zero());
                        }
                        /** @brief
                         *
                         * @return true if element from group G2 in affine coordinates
                         */
                        constexpr bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }
                        /** @brief
                         *
                         * @return true if element from group G2 lies on the elliptic curve
                         */
                        constexpr bool is_well_formed() const {
                            if (this->is_zero()) {
                                return true;
                            } else {
                                /*
                                  y^2 = x^3 + b

                                  We are using Jacobian coordinates, so equation we need to check is actually

                                  (y/z^3)^2 = (x/z^2)^3 + b
                                  y^2 / z^6 = x^3 / z^6 + b
                                  y^2 = x^3 + b z^6
                                */
                                underlying_field_value_type X2 = this->X.squared();
                                underlying_field_value_type Y2 = this->Y.squared();
                                underlying_field_value_type Z2 = this->Z.squared();

                                underlying_field_value_type X3 = this->X * X2;
                                underlying_field_value_type Z3 = this->Z * Z2;
                                underlying_field_value_type Z6 = Z3.squared();

                                return (Y2 == X3 + twist_coeff_b * Z6);
                            }
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr element_bls12_g2 operator=(const element_bls12_g2 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        constexpr element_bls12_g2 operator+(const element_bls12_g2 &other) const {
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

                        constexpr element_bls12_g2 operator-() const {
                            return element_bls12_g2(this->X, -(this->Y), this->Z);
                        }

                        constexpr element_bls12_g2 operator-(const element_bls12_g2 &other) const {
                            return (*this) + (-other);
                        }
                        /** @brief
                         *
                         * @return doubled element from group G2
                         */
                        constexpr element_bls12_g2 doubled() const {
                            // handle point at infinity
                            if (this->is_zero()) {
                                return (*this);
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl

                            underlying_field_value_type A = (this->X).squared();    // A = X1^2
                            underlying_field_value_type B = (this->Y).squared();    // B = Y1^2
                            underlying_field_value_type C = B.squared();            // C = B^2
                            underlying_field_value_type D = (this->X + B).squared() - A - C;
                            D = D + D;                                       // D = 2 * ((X1 + B)^2 - A - C)
                            underlying_field_value_type E = A + A + A;       // E = 3 * A
                            underlying_field_value_type F = E.squared();     // F = E^2
                            underlying_field_value_type X3 = F - (D + D);    // X3 = F - 2 D
                            underlying_field_value_type eightC = C + C;
                            eightC = eightC + eightC;
                            eightC = eightC + eightC;
                            underlying_field_value_type Y3 = E * (D - X3) - eightC;    // Y3 = E * (D - X3) - 8 * C
                            underlying_field_value_type Y1Z1 = (this->Y) * (this->Z);
                            underlying_field_value_type Z3 = Y1Z1 + Y1Z1;    // Z3 = 2 * Y1 * Z1

                            return element_bls12_g2(X3, Y3, Z3);
                        }

                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G2
                         */
                        constexpr element_bls12_g2 mixed_add(const element_bls12_g2 &other) const {

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

                            return element_bls12_g2(X3, Y3, Z3);
                        }

                    private:
                        constexpr element_bls12_g2 add(const element_bls12_g2 &other) const {

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

                            underlying_field_value_type Z1Z1 = (this->Z).squared();           // Z1Z1 = Z1^2
                            underlying_field_value_type Z2Z2 = (other.Z).squared();           // Z2Z2 = Z2^2
                            underlying_field_value_type U1 = (this->X) * Z2Z2;                // U1 = X1 * Z2Z2
                            underlying_field_value_type U2 = (other.X) * Z1Z1;                // U2 = X2 * Z1Z1
                            underlying_field_value_type S1 = (this->Y) * (other.Z) * Z2Z2;    // S1 = Y1 * Z2 * Z2Z2
                            underlying_field_value_type S2 = (other.Y) * (this->Z) * Z1Z1;    // S2 = Y2 * Z1 * Z1Z1
                            underlying_field_value_type H = U2 - U1;                          // H = U2-U1
                            underlying_field_value_type S2_minus_S1 = S2 - S1;
                            underlying_field_value_type I = (H + H).squared();             // I = (2 * H)^2
                            underlying_field_value_type J = H * I;                         // J = H * I
                            underlying_field_value_type r = S2_minus_S1 + S2_minus_S1;     // r = 2 * (S2-S1)
                            underlying_field_value_type V = U1 * I;                        // V = U1 * I
                            underlying_field_value_type X3 = r.squared() - J - (V + V);    // X3 = r^2 - J - 2 * V
                            underlying_field_value_type S1_J = S1 * J;
                            underlying_field_value_type Y3 = r * (V - X3) - (S1_J + S1_J);    // Y3 = r * (V-X3)-2 S1 J
                            underlying_field_value_type Z3 =
                                ((this->Z + other.Z).squared() - Z1Z1 - Z2Z2) * H;    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2) * H

                            return element_bls12_g2(X3, Y3, Z3);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/
                        /** @brief
                         *
                         * @return return the corresponding element from group G2 in affine coordinates
                         */
                        constexpr element_bls12_g2 to_affine() const {
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

                            return element_bls12_g2(p_out[0], p_out[1], p_out[2]);
                        }
                        /** @brief
                         *
                         * @return return the corresponding element from group G2 in affine coordinates
                         */
                        constexpr element_bls12_g2 to_projective() const {
                            return this->to_affine();
                        }

                        constexpr static const g1_field_type_value b = policy_type::b;

                        constexpr static const g2_field_type_value twist =
                            g2_field_type_value(g2_field_type_value::underlying_type::one(),
                                                g2_field_type_value::underlying_type::one());

                        constexpr static const g2_field_type_value twist_coeff_b = b * twist;

                    private:
                        constexpr static const std::array<underlying_field_value_type, 3> zero_fill = {
                            underlying_field_value_type::zero(), underlying_field_value_type::one(),
                            underlying_field_value_type::zero()};

                        constexpr static const std::array<underlying_field_value_type, 3> one_fill = {
                            underlying_field_value_type(
                                0x24AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8_cppui378,
                                0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E_cppui381),
                            underlying_field_value_type(
                                0xCE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801_cppui380,
                                0x606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE_cppui379),
                            underlying_field_value_type::one()};
                    };
                    /** @brief A struct representing an elememnt from the group G2 of BLS12-377 curve.
                     *
                     * The size of the group G2 in bits equals 253.
                     */
                    template<>
                    struct element_bls12_g2<377> {

                        using group_type = bls12_g2<377>;

                        using policy_type = bls12_basic_policy<377>;
                        
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_type = typename policy_type::g2_field_type;
                        using underlying_field_value_type = underlying_field_type::value_type;

                        underlying_field_value_type X;
                        underlying_field_value_type Y;
                        underlying_field_value_type Z;

                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr element_bls12_g2() : element_bls12_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};

                        /** @brief
                         *    @return the selected point $(X:Y:Z)$
                         *
                         */
                        constexpr element_bls12_g2(underlying_field_value_type X,
                                         underlying_field_value_type Y,
                                         underlying_field_value_type Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };

                        /** @brief Get the point at infinity
                         *
                         */
                        constexpr static element_bls12_g2 zero() {
                            return element_bls12_g2();
                        }

                        /** @brief Get the generator of group G2
                         *
                         */
                        constexpr static element_bls12_g2 one() {
                            return element_bls12_g2(one_fill[0], one_fill[1], one_fill[2]);
                        }

                        /*************************  Comparison operations  ***********************************/

                        constexpr bool operator==(const element_bls12_g2 &other) const {
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

                        constexpr bool operator!=(const element_bls12_g2 &other) const {
                            return !(operator==(other));
                        }

                        /** @brief
                         *
                         * @return true if element from group G2 is the point at infinity
                         */
                        constexpr bool is_zero() const {
                            return (this->Z.is_zero());
                        }
                        /** @brief
                         *
                         * @return true if element from group G2 in affine coordinates
                         */
                        constexpr bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }

                        /** @brief
                         *
                         * @return true if element from group G2 lies on the elliptic curve
                         */
                        constexpr bool is_well_formed() const {
                            if (this->is_zero()) {
                                return true;
                            } else {
                                /*
                                  y^2 = x^3 + b

                                  We are using Jacobian coordinates, so equation we need to check is actually

                                  (y/z^3)^2 = (x/z^2)^3 + b
                                  y^2 / z^6 = x^3 / z^6 + b
                                  y^2 = x^3 + b z^6
                                */
                                underlying_field_value_type X2 = this->X.squared();
                                underlying_field_value_type Y2 = this->Y.squared();
                                underlying_field_value_type Z2 = this->Z.squared();

                                underlying_field_value_type X3 = this->X * X2;
                                underlying_field_value_type Z3 = this->Z * Z2;
                                underlying_field_value_type Z6 = Z3.squared();

                                return (Y2 == X3 + twist_coeff_b * Z6);
                            }
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr element_bls12_g2 operator=(const element_bls12_g2 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        constexpr element_bls12_g2 operator+(const element_bls12_g2 &other) const {
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

                        constexpr element_bls12_g2 operator-() const {
                            return element_bls12_g2(this->X, -(this->Y), this->Z);
                        }

                        constexpr element_bls12_g2 operator-(const element_bls12_g2 &other) const {
                            return (*this) + (-other);
                        }

                        /** @brief
                         *
                         * @return doubled element from group G2
                         */
                        constexpr element_bls12_g2 doubled() const {
                            // handle point at infinity
                            if (this->is_zero()) {
                                return (*this);
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl

                            underlying_field_value_type A = (this->X).squared();    // A = X1^2
                            underlying_field_value_type B = (this->Y).squared();    // B = Y1^2
                            underlying_field_value_type C = B.squared();            // C = B^2
                            underlying_field_value_type D = (this->X + B).squared() - A - C;
                            D = D + D;                                       // D = 2 * ((X1 + B)^2 - A - C)
                            underlying_field_value_type E = A + A + A;       // E = 3 * A
                            underlying_field_value_type F = E.squared();     // F = E^2
                            underlying_field_value_type X3 = F - (D + D);    // X3 = F - 2 D
                            underlying_field_value_type eightC = C + C;
                            eightC = eightC + eightC;
                            eightC = eightC + eightC;
                            underlying_field_value_type Y3 = E * (D - X3) - eightC;    // Y3 = E * (D - X3) - 8 * C
                            underlying_field_value_type Y1Z1 = (this->Y) * (this->Z);
                            underlying_field_value_type Z3 = Y1Z1 + Y1Z1;    // Z3 = 2 * Y1 * Z1

                            return element_bls12_g2(X3, Y3, Z3);
                        }
                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G2
                         */
                        constexpr element_bls12_g2 mixed_add(const element_bls12_g2 &other) const {

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

                            return element_bls12_g2(X3, Y3, Z3);
                        }

                    private:
                        constexpr element_bls12_g2 add(const element_bls12_g2 &other) const {

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

                            underlying_field_value_type Z1Z1 = (this->Z).squared();           // Z1Z1 = Z1^2
                            underlying_field_value_type Z2Z2 = (other.Z).squared();           // Z2Z2 = Z2^2
                            underlying_field_value_type U1 = (this->X) * Z2Z2;                // U1 = X1 * Z2Z2
                            underlying_field_value_type U2 = (other.X) * Z1Z1;                // U2 = X2 * Z1Z1
                            underlying_field_value_type S1 = (this->Y) * (other.Z) * Z2Z2;    // S1 = Y1 * Z2 * Z2Z2
                            underlying_field_value_type S2 = (other.Y) * (this->Z) * Z1Z1;    // S2 = Y2 * Z1 * Z1Z1
                            underlying_field_value_type H = U2 - U1;                          // H = U2-U1
                            underlying_field_value_type S2_minus_S1 = S2 - S1;
                            underlying_field_value_type I = (H + H).squared();             // I = (2 * H)^2
                            underlying_field_value_type J = H * I;                         // J = H * I
                            underlying_field_value_type r = S2_minus_S1 + S2_minus_S1;     // r = 2 * (S2-S1)
                            underlying_field_value_type V = U1 * I;                        // V = U1 * I
                            underlying_field_value_type X3 = r.squared() - J - (V + V);    // X3 = r^2 - J - 2 * V
                            underlying_field_value_type S1_J = S1 * J;
                            underlying_field_value_type Y3 = r * (V - X3) - (S1_J + S1_J);    // Y3 = r * (V-X3)-2 S1 J
                            underlying_field_value_type Z3 =
                                ((this->Z + other.Z).squared() - Z1Z1 - Z2Z2) * H;    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2) * H

                            return element_bls12_g2(X3, Y3, Z3);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/
                        /** @brief
                         *
                         * @return return the corresponding element from group G2 in affine coordinates
                         */
                        constexpr element_bls12_g2 to_affine() const {
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

                            return element_bls12_g2(p_out[0], p_out[1], p_out[2]);
                        }
                        /** @brief
                         *
                         * @return return the corresponding element from group G2 in affine coordinates
                         */
                        constexpr element_bls12_g2 to_projective() const {
                            return this->to_affine();
                        }

                        constexpr static const g1_field_type_value b = policy_type::b;

                        constexpr static const g2_field_type_value twist =
                            g2_field_type_value(g2_field_type_value::underlying_type::zero(),
                                                g2_field_type_value::underlying_type::one());

                        constexpr static const g2_field_type_value twist_coeff_b = b * twist.inversed();

                    private:
                        constexpr static const std::array<underlying_field_value_type, 3> zero_fill = {
                            underlying_field_value_type::zero(), underlying_field_value_type::one(),
                            underlying_field_value_type::zero()};

                        constexpr static const std::array<underlying_field_value_type, 3> one_fill = {
                            underlying_field_value_type(
                                0xB997FEF930828FE1B9E6A1707B8AA508A3DBFD7FE2246499C709226A0A6FEF49F85B3A375363F4F8F6EA3FBD159F8A_cppui376,
                                0xD6AC33B84947D9845F81A57A136BFA326E915FABC8CD6A57FF133B42D00F62E4E1AF460228CD5184DEAE976FA62596_cppui376),
                            underlying_field_value_type(
                                0x118DD509B2E9A13744A507D515A595DBB7E3B63DF568866473790184BDF83636C94DF2B7A962CB2AF4337F07CB7E622_cppui377,
                                0x185067C6CA76D992F064A432BD9F9BE832B0CAC2D824D0518F77D39E76C3E146AFB825F2092218D038867D7F337A010_cppui377),
                            underlying_field_value_type::one()};
                    };

                    constexpr std::array<typename element_bls12_g2<377>::underlying_field_value_type, 3> const
                        element_bls12_g2<377>::zero_fill;
                    constexpr std::array<typename element_bls12_g2<381>::underlying_field_value_type, 3> const
                        element_bls12_g2<381>::zero_fill;

                    constexpr std::array<typename element_bls12_g2<377>::underlying_field_value_type, 3> const
                        element_bls12_g2<377>::one_fill;
                    constexpr std::array<typename element_bls12_g2<381>::underlying_field_value_type, 3> const
                        element_bls12_g2<381>::one_fill;

                    constexpr typename element_bls12_g2<377>::g1_field_type_value const element_bls12_g2<377>::b;
                    constexpr typename element_bls12_g2<381>::g1_field_type_value const element_bls12_g2<381>::b;

                    constexpr typename element_bls12_g2<377>::g2_field_type_value const element_bls12_g2<377>::twist;
                    constexpr typename element_bls12_g2<381>::g2_field_type_value const element_bls12_g2<381>::twist;

                    constexpr
                        typename element_bls12_g2<377>::g2_field_type_value const element_bls12_g2<377>::twist_coeff_b;
                    constexpr
                        typename element_bls12_g2<381>::g2_field_type_value const element_bls12_g2<381>::twist_coeff_b;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_BLS12_G2_ELEMENT_HPP
