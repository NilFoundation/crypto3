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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/detail/forms.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/projective/add_1998_cmo_2.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/projective/dbl_2007_bl.hpp>

#include <nil/crypto3/detail/literals.hpp>

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
                    template<typename CurveParams, 
                             algebra::curves::detail::forms Form, 
                             typename Coordinates>
                    struct element_g1;

                    /** @brief A struct representing an element from the group G1 of short Weierstrass curve.
                     *  Description: https://hyperelliptic.org/EFD/g1p/auto-shortw.html
                     *
                     */
                    template<typename CurveParams, 
                             typename Adder = add_1998_cmo_2, 
                             typename Doubler = dbl_2007_bl>
                    struct element_g1<algebra::curves::detail::forms::short_weierstrass, 
                                      algebra::curves::detail::short_weierstrass_coordinates::projective> {

                        using field_type = typename CurveParams::g1_field_type;
                    private:
                        using params_type = CurveParams;
                        using field_value_type = typename field_type::value_type;
                    public:
                        using group_type = typename params_type::group_type;

                        constexpr static const algebra::curves::detail::forms form = 
                            algebra::curves::detail::forms::short_weierstrass;
                        constexpr static const 
                            algebra::curves::detail::short_weierstrass_coordinates coordinates = 
                            algebra::curves::detail::short_weierstrass_coordinates::projective;

                        field_value_type X;
                        field_value_type Y;

                        /*************************  Constructors and zero/one  ***********************************/

                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr element_g1() : element_g1(params_type::g1_zero_fill[0], 
                            params_type::g1_zero_fill[1]) {};

                        /** @brief
                         *    @return the selected point $(X:Y)$ in the affine coordinates
                         *
                         */
                        constexpr element_g1(field_value_type in_X, field_value_type in_Y) {
                            this->X = in_X;
                            this->Y = in_Y;
                        };

                        constexpr element_g1(element_g1<params_type, form, 
                            algebra::curves::detail::twisted_edwards_coordinates::projective> other) {

                            if (other.Z.is_zero()) {
                                *this = this->zero();
                            }

                            field_value_type Z_inv = other.Z.inversed();
                            X[0] = other.X * Z_inv;
                            Y[1] = other.Y * Z_inv;
                        };

                        /** @brief Get the point at infinity
                         *
                         */
                        constexpr static element_g1 zero() {
                            return element_g1();
                        }

                        /** @brief Get the generator of group G1
                         *
                         */
                        constexpr static element_g1 one() {
                            return element_g1(params_type::g1_one_fill[0], params_type::g1_one_fill[1]);
                        }

                        /*************************  Comparison operations  ***********************************/

                        constexpr static bool operator==(const element_g1 &other) const {
                            if (this->is_zero()) {
                                return other.is_zero();
                            }

                            if (other.is_zero()) {
                                return false;
                            }

                            /* now neither is O */

                            if (this->X != other.X) {
                                return false;
                            }

                            if (this->Y  != other.Y) {
                                return false;
                            }

                            return true;
                        }

                        constexpr bool operator!=(const element_g1 &other) const {
                            return !(operator==(other));
                        }

                        /** @brief
                         *
                         * @return true if element from group G1 is the point at infinity
                         */
                        constexpr bool is_zero() const {
                            return (*this) == element_g1::zero();
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr element_g1 operator=(const element_g1 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;

                            return *this;
                        }

                        constexpr element_g1 operator+(const element_g1 &other) const {
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

                        constexpr element_g1 operator-() const {
                            return element_g1(this->X, -this->Y);
                        }

                        constexpr element_g1 operator-(const element_g1 &other) const {
                            return (*this) + (-other);
                        }

                        /** @brief
                         * Affine doubling formulas: 2(x1,y1)=(x3,y3) where
                         * x3 = (3*x12+a)2/(2*y1)2-x1-x1
                         * y3 = (2*x1+x1)*(3*x12+a)/(2*y1)-(3*x12+a)3/(2*y1)3-y1
                         * @return doubled element from group G1
                         */
                        constexpr element_g1 doubled() const {

                            if (this->is_zero()) {
                                return (*this);
                            } else {
                                field_value_type Xsquared = X.squared();
                                field_value_type Xsquared3pa = Xsquared.doubled() + Xsquared + params_type::a;
                                field_value_type Xsquared3pasquared = Xsquared3pa.squared();
                                field_value_type Y2squared = Y.doubled().squared();
                                
                                field_value_type X3 = Xsquared3pasquared * 
                                    Y2squared.inversed() - X - X;
                                field_value_type Y3 = (X.doubled() + X) * Xsquared3pa * 
                                    Y.doubled().inversed() - Xsquared3pasquared*Xsquared3pa * 
                                    Y2squared*(Y.doubled()) - Y;
                            }
                        }

                    private:
                        /** @brief
                         * Affine addition formulas: (x1,y1)+(x2,y2)=(x3,y3) where 
                         * x3 = (y2-y1)2/(x2-x1)2-x1-x2
                         * y3 = (2*x1+x2)*(y2-y1)/(x2-x1)-(y2-y1)3/(x2-x1)3-y1
                         */
                        element_g1 add(const element_g1 &other) const {
                            field_value_type Y2mY1 = other.Y - this->Y;
                            field_value_type Y2mY1squared = Y2mY1.squared();
                            field_value_type X2mX1 = other.X - this->X;
                            field_value_type X2mX1squared = X2mX1.squared();

                            field_value_type X3 = Y2mY1squared * X2mX1squared.inversed() - 
                                this->X - other.X;
                            field_value_type Y3 = ((this-X).doubled() + other.X) * Y2mY1 * 
                                X2mX1.inversed() - Y2mY1*Y2mY1squared * (X2mX1*X2mX1squared).inversed() - 
                                this->Y;

                            return element_g1(X3, Y3);
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_PROJECTIVE_HPP
