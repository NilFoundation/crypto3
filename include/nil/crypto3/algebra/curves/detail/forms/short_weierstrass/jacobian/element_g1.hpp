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

#ifndef CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_HPP
#define CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/forms.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/jacobian/add_2007_bl.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/jacobian/dbl_2007_bl.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/jacobian/madd_2007_bl.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/element_g1_affine.hpp>

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
                     *  jacobian coordinates representation.
                     *  Description: http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html
                     *
                     */
                    template<typename CurveParams>
                    class curve_element<CurveParams, forms::short_weierstrass, coordinates::jacobian> {
                    public:

                        using params_type = CurveParams;
                        using field_type = typename params_type::field_type;

                    private:
                        using field_value_type = typename field_type::value_type;

                        using common_addition_processor = short_weierstrass_element_g1_jacobian_add_2007_bl;
                        using common_doubling_processor = short_weierstrass_element_g1_jacobian_dbl_2007_bl;
                        using mixed_addition_processor = short_weierstrass_element_g1_jacobian_madd_2007_bl;

                    public:
                        using form = forms::short_weierstrass;
                        using coordinates = coordinates::jacobian;

                        using group_type = typename params_type::template group_type<coordinates>;

                        field_value_type X;
                        field_value_type Y;
                        field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr curve_element() :
                            curve_element(params_type::zero_fill[0],
                                          params_type::zero_fill[1],
                                          field_value_type::zero()) {};

                        /** @brief
                         *    @return the selected point (X:Y:Z)
                         *
                         */
                        constexpr curve_element(const field_value_type& X, const field_value_type& Y, const field_value_type& Z) 
                            : X(X), Y(Y), Z(Z)
                        {
                        };

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
                            return curve_element(params_type::one_fill[0], params_type::one_fill[1],
                                                 field_value_type::one());
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

                        constexpr bool operator!=(const curve_element &other) const {
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
                                  y^2 = x^3 + a x + b

                                  We are using Jacobian coordinates, so equation we need to check is actually

                                  (y/z^3)^2 = (x/z^2)^3 + a(x/z^2) + b
                                  y^2 / z^6 = x^3 / z^6 + a*x/z^2 + b
                                  y^2 = x^3 + a*x*z^4 + b*z^6
                                */
                                field_value_type X2 = this->X.squared();
                                field_value_type Y2 = this->Y.squared();
                                field_value_type Z2 = this->Z.squared();

                                field_value_type X3 = this->X * X2;
                                field_value_type Z3 = this->Z * Z2;
                                field_value_type Z4 = Z2.squared();
                                field_value_type Z6 = Z3.squared();

                                return (Y2 == X3 + params_type::a * this->X * Z4 + params_type::b * Z6);
                            }
                        }

                        /*************************  Reducing operations  ***********************************/

                        /** @brief
                         *
                         * @return return the corresponding element from jacobian coordinates to
                         * affine coordinates
                         */
                        constexpr curve_element<params_type, form, typename curves::coordinates::affine>
                            to_affine() const {

                            using result_type = curve_element<params_type, form, typename curves::coordinates::affine>;

                            if (is_zero()) {
                                return result_type::zero();
                            }

                            return result_type(X / Z.squared(), Y / (Z * Z.squared()));    //  x=X/Z^2, y=Y/Z^3
                        }

                        /** @brief
                         *
                         * @return return the corresponding element from jacobian coordinates to
                         * projective coordinates
                         */
                        constexpr curve_element<params_type, form, typename curves::coordinates::projective>
                            to_projective() const {

                            using result_type =
                                curve_element<params_type, form, typename curves::coordinates::projective>;

                            if (is_zero()) {
                                return result_type::zero();
                            }

                            return result_type(X / Z, Y / Z.squared(),
                                               Z);    // X = X/Z, Y = Y/Z^2, Z = Z
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr curve_element& operator=(const curve_element &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

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

                            return common_addition_processor::process(*this, other);
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
                                *this = common_addition_processor::process(*this, other);
                            }
                            return *this;
                        }

                        constexpr curve_element operator-() const {
                            return curve_element(this->X, -(this->Y), this->Z);
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

                        constexpr curve_element operator-(const curve_element &other) const {
                            return (*this) + (-other);
                        }

                        /** @brief
                         *
                         * @return doubled element from group G1
                         */
                        constexpr curve_element doubled() const {
                            return common_doubling_processor::process(*this);
                        }

                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G1
                         */
                        constexpr curve_element mixed_add(const curve_element &other) const {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return *this;
                            }

                            return mixed_addition_processor::process(*this, other);
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_SHORT_WEIERSTRASS_G1_ELEMENT_JACOBIAN_HPP
