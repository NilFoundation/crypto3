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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/forms.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>

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
                    template<typename CurveParams, typename Form, typename Coordinates>
                    class curve_element;

                    /** @brief A struct representing an element from the group G1 of short Weierstrass curve of
                     *  affine coordinates representation.
                     *  Description: https://hyperelliptic.org/EFD/g1p/auto-shortw.html
                     *
                     */
                    template<typename CurveParams>
                    class curve_element<CurveParams, forms::short_weierstrass, coordinates::affine> {
                    public:

                        using field_type = typename CurveParams::field_type;

                    private:
                        using params_type = CurveParams;
                        using field_value_type = typename field_type::value_type;

                    public:
                        using form = forms::short_weierstrass;
                        using coordinates = coordinates::affine;

                        using group_type = typename params_type::template group_type<coordinates>;

                        field_value_type X;
                        field_value_type Y;

                        /*************************  Constructors and zero/one  ***********************************/

                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr curve_element() :
                            curve_element(params_type::zero_fill[0], params_type::zero_fill[1]) {}

                        /** @brief
                         *    @return the selected point $(X:Y)$ in the affine coordinates
                         *
                         */
                        constexpr curve_element(const field_value_type& X, const field_value_type& Y) 
                            : X(X), Y(Y){
                        }

                        template<typename Backend,
                                 multiprecision::expression_template_option ExpressionTemplates>
                        explicit constexpr curve_element(
                                  const multiprecision::number<Backend, ExpressionTemplates> &value) {
                            *this = one() * value;
                        }

                        /** @brief Get the point at infinity
                         *
                         */
                        constexpr static curve_element zero() {
                            return curve_element();
                        }

                        /** @brief Get the generator of group G1
                         *
                         */
                        constexpr static curve_element one() {
                            return curve_element(params_type::one_fill[0], params_type::one_fill[1]);
                        }

                        /*************************  Comparison operations  ***********************************/

                        constexpr bool operator==(const curve_element &other) const {
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

                            if (this->Y != other.Y) {
                                return false;
                            }

                            return true;
                        }

                        constexpr bool operator!=(const curve_element &other) const {
                            return !(operator==(other));
                        }

                        /** @brief
                         *
                         * @return true if element from group G1 is the point at infinity
                         */
                        constexpr bool is_zero() const {
                            return X == params_type::zero_fill[0] && Y == params_type::zero_fill[1];
                        }

                        /*************************  Reducing operations  ***********************************/

                        /** @brief
                         *
                         * @return return the corresponding element from affine coordinates to
                         * projective coordinates
                         */
                        constexpr curve_element<params_type, form, typename curves::coordinates::projective>
                            to_projective() const {

                            using result_type =
                                curve_element<params_type, form, typename curves::coordinates::projective>;

                            if (is_zero()) {
                                return result_type::zero();
                            }

                            return result_type(X, Y,
                                               result_type::field_type::value_type::one());    // X = x, Y = y, Z = 1
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr curve_element operator=(const curve_element &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;

                            return *this;
                        }

                        template<typename Backend,
                                 multiprecision::expression_template_option ExpressionTemplates>
                        constexpr const curve_element& operator=(
                                  const multiprecision::number<Backend, ExpressionTemplates> &value) {
                            *this = one() * value;
                            return *this;
                        }

                        constexpr curve_element operator+(const curve_element &other) const {
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

                        constexpr curve_element& operator+=(const curve_element &other) {
                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                *this = other;
                            } else if (other.is_zero()) {
                                // Do nothing.
                            } else if (*this == other) {
                                *this = this->doubled();
                            } else {
                                *this = this->add(other);
                            }
                            return *this;
                        }


                        constexpr curve_element operator-() const {
                            return curve_element(this->X, -this->Y);
                        }

                        constexpr curve_element operator-(const curve_element &other) const {
                            return (*this) + (-other);
                        }

                        constexpr curve_element& operator-=(const curve_element &other) {
                            return (*this) += (-other);
                        }

                        template<typename Backend,
                             multiprecision::expression_template_option ExpressionTemplates>
                        constexpr curve_element& operator*=(const multiprecision::number<Backend, ExpressionTemplates> &right) {
                            (*this) = (*this) * right;
                            return *this;
                        }

                        template<typename FieldValueType>
                        typename std::enable_if<is_field<typename FieldValueType::field_type>::value &&
                                                !is_extended_field<typename FieldValueType::field_type>::value,
                                                curve_element>::type
                            operator*=(const FieldValueType &right) {
                                return (*this) *= right.data;
                        }

                        /** @brief
                         * Affine doubling formulas: 2(x1,y1)=(x3,y3) where
                         * x3 = (3*x12+a)2/(2*y1)2-x1-x1
                         * y3 = (2*x1+x1)*(3*x12+a)/(2*y1)-(3*x12+a)3/(2*y1)3-y1
                         * @return doubled element from group G1
                         */
                        constexpr curve_element doubled() const {

                            if (this->is_zero()) {
                                return (*this);
                            } else {
                                field_value_type Xsquared3pa = 3 * X.squared() + params_type::a;
                                field_value_type Y2squared = Y.doubled().squared();

                                field_value_type X3 = Xsquared3pa.squared() / Y2squared - X - X;
                                field_value_type Y3 = (X.doubled() + X) * Xsquared3pa / Y.doubled() -
                                                      Xsquared3pa.pow(3) / (Y.doubled()).pow(3) - Y;

                                return curve_element(X3, Y3);
                            }
                        }

                    private:
                        /** @brief
                         * Affine addition formulas: (x1,y1)+(x2,y2)=(x3,y3) where
                         * x3 = (y2-y1)2/(x2-x1)2-x1-x2
                         * y3 = (2*x1+x2)*(y2-y1)/(x2-x1)-(y2-y1)3/(x2-x1)3-y1
                         */
                        curve_element add(const curve_element &other) const {
                            if(*this == - other){
                                return curve_element();
                            }
                            field_value_type Y2mY1 = other.Y - Y;
                            field_value_type X2mX1 = other.X - X;

                            field_value_type X3 = Y2mY1.squared() / X2mX1.squared() - X - other.X;
                            field_value_type Y3 = (2 * X + other.X) * Y2mY1 / X2mX1 -
                                                  (Y2mY1.pow(3)) / (X2mX1.pow(3)) - Y;

                            return curve_element(X3, Y3);
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_HPP
