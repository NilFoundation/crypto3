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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_0_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_0_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/detail/forms.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/jacobian_with_a4_0/add_2007_bl.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/jacobian_with_a4_0/dbl_2009_l.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /** @brief A struct representing a group G1 of elliptic curve. 
                     *    @tparam CurveParams Parameters of the group 
                     *    @tparam Form Form of the curve 
                     *    @tparam Coordinates Representation coordinates of the group element 
                     */
                    // template<typename CurveParams, 
                    //          forms Form, 
                    //          short_weierstrass_coordinates Coordinates>
                    // struct short_weierstrass_element_g1;

                    /** @brief A struct representing an element from the group G1 of short Weierstrass curve of 
                     *  jacobian_with_a4_0 coordinates representation.
                     *  Description: http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
                     *
                     */
                    template<typename CurveParams, 
                             typename Adder = short_weierstrass_element_g1_jacobian_with_a4_0_add_2007_bl, 
                             typename Doubler = short_weierstrass_element_g1_jacobian_with_a4_0_dbl_2009_l>
                    struct short_weierstrass_element_g1_jacobian_with_a4_0 {

                        using params_type = CurveParams;
                        using field_type = typename params_type::field_type;
                    private:
                        using field_value_type = typename field_type::value_type;
                    public:
                        using group_type = typename params_type::group_type;

                        constexpr static const forms form = 
                            forms::short_weierstrass;
                        constexpr static const 
                            short_weierstrass_coordinates coordinates = 
                            short_weierstrass_coordinates::jacobian_with_a4_0;

                        field_value_type X;
                        field_value_type Y;
                        field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr short_weierstrass_element_g1_jacobian_with_a4_0() : short_weierstrass_element_g1_jacobian_with_a4_0(
                            params_type::zero_fill[0], 
                            params_type::zero_fill[1], 
                            params_type::zero_fill[2]) {};

                        /** @brief
                         *    @return the selected point (X:Y:Z)
                         *
                         */
                        constexpr short_weierstrass_element_g1_jacobian_with_a4_0(field_value_type X,
                                                  field_value_type Y,
                                                  field_value_type Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };

                        /** @brief Get the point at infinity
                         *
                         */
                        constexpr static short_weierstrass_element_g1_jacobian_with_a4_0 zero() {
                            return short_weierstrass_element_g1_jacobian_with_a4_0();
                        }

                        /** @brief Get the generator of group G1
                         *
                         */
                        constexpr static short_weierstrass_element_g1_jacobian_with_a4_0 one() {
                            return short_weierstrass_element_g1_jacobian_with_a4_0(params_type::one_fill[0], params_type::one_fill[1], 
                                params_type::one_fill[2]);
                        }

                        /*************************  Comparison operations  ***********************************/

                        constexpr bool operator==(const short_weierstrass_element_g1_jacobian_with_a4_0 &other) const {
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

                            field_value_type Z1_squared = (this->Z).squared();
                            field_value_type Z2_squared = (other.Z).squared();

                            if ((this->X * Z2_squared) != (other.X * Z1_squared)) {
                                return false;
                            }

                            field_value_type Z1_cubed = (this->Z) * Z1_squared;
                            field_value_type Z2_cubed = (other.Z) * Z2_squared;

                            if ((this->Y * Z2_cubed) != (other.Y * Z1_cubed)) {
                                return false;
                            }

                            return true;
                        }

                        constexpr bool operator!=(const short_weierstrass_element_g1_jacobian_with_a4_0 &other) const {
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
                         * @return true if element from group G1 lies on the elliptic curve
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
                                field_value_type X2 = this->X.squared();
                                field_value_type Y2 = this->Y.squared();
                                field_value_type Z2 = this->Z.squared();

                                field_value_type X3 = this->X * X2;
                                field_value_type Z3 = this->Z * Z2;
                                field_value_type Z6 = Z3.squared();

                                return (Y2 == X3 + params_type::b * Z6);
                            }
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr short_weierstrass_element_g1_jacobian_with_a4_0 operator=(const short_weierstrass_element_g1_jacobian_with_a4_0 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        constexpr short_weierstrass_element_g1_jacobian_with_a4_0 operator+(const short_weierstrass_element_g1_jacobian_with_a4_0 &other) const {
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

                            return Adder::process(*this, other);
                        }

                        constexpr short_weierstrass_element_g1_jacobian_with_a4_0 operator-() const {
                            return short_weierstrass_element_g1_jacobian_with_a4_0(this->X, -(this->Y), this->Z);
                        }

                        constexpr short_weierstrass_element_g1_jacobian_with_a4_0 operator-(const short_weierstrass_element_g1_jacobian_with_a4_0 &other) const {
                            return (*this) + (-other);
                        }
                        
                        /** @brief
                         *
                         * @return doubled element from group G1
                         */
                        constexpr short_weierstrass_element_g1_jacobian_with_a4_0 doubled() const {
                            return Doubler::process(*this);
                        }

                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G1
                         */
                        constexpr short_weierstrass_element_g1_jacobian_with_a4_0 mixed_add(const short_weierstrass_element_g1_jacobian_with_a4_0 &other) const {

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

                            const field_value_type Z1Z1 = (this->Z).squared();

                            const field_value_type &U1 = this->X;
                            const field_value_type U2 = other.X * Z1Z1;

                            const field_value_type Z1_cubed = (this->Z) * Z1Z1;

                            const field_value_type &S1 = (this->Y);              // S1 = Y1 * Z2 * Z2Z2
                            const field_value_type S2 = (other.Y) * Z1_cubed;    // S2 = Y2 * Z1 * Z1Z1

                            if (U1 == U2 && S1 == S2) {
                                // dbl case; nothing of above can be reused
                                return this->doubled();
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
                            field_value_type H = U2 - (this->X);    // H = U2-X1
                            field_value_type HH = H.squared();      // HH = H&2
                            field_value_type I = HH + HH;           // I = 4*HH
                            I = I + I;
                            field_value_type J = H * I;             // J = H*I
                            field_value_type r = S2 - (this->Y);    // r = 2*(S2-Y1)
                            r = r + r;
                            field_value_type V = (this->X) * I;               // V = X1*I
                            field_value_type X3 = r.squared() - J - V - V;    // X3 = r^2-J-2*V
                            field_value_type Y3 = (this->Y) * J;              // Y3 = r*(V-X3)-2*Y1*J
                            Y3 = r * (V - X3) - Y3 - Y3;
                            field_value_type Z3 =
                                ((this->Z) + H).squared() - Z1Z1 - HH;    // Z3 = (Z1+H)^2-Z1Z1-HH

                            return short_weierstrass_element_g1_jacobian_with_a4_0(X3, Y3, Z3);
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_WITH_A4_0_HPP
