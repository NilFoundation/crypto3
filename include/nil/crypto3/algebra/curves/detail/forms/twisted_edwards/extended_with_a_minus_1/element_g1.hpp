//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_HPP
#define CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/forms.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/extended_with_a_minus_1/add_2008_hwcd_3.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/extended_with_a_minus_1/dbl_2008_hwcd.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/extended_with_a_minus_1/madd_2008_hwcd_2.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/element_g1_affine.hpp>

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

                    /** @brief A struct representing an element from the group G1 of twisted Edwards curve of
                     *  extended coordinates with a=-1 coordinates representation.
                     *  Description: https://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
                     *
                     */
                    template<typename CurveParams>
                    class curve_element<CurveParams, forms::twisted_edwards, coordinates::extended_with_a_minus_1> {
                    public:

                        using params_type = CurveParams;
                        using field_type = typename params_type::field_type;

                    private:
                        using field_value_type = typename field_type::value_type;

                        using common_addition_processor =
                            twisted_edwards_element_g1_extended_with_a_minus_1_add_2008_hwcd_3;
                        using common_doubling_processor =
                            twisted_edwards_element_g1_extended_with_a_minus_1_dbl_2008_hwcd;
                        using mixed_addition_processor =
                            twisted_edwards_element_g1_extended_with_a_minus_1_madd_2008_hwcd_2;

                    public:
                        using form = forms::twisted_edwards;
                        using coordinates = coordinates::extended_with_a_minus_1;

                        using group_type = typename params_type::template group_type<coordinates>;

                        field_value_type X;
                        field_value_type Y;
                        field_value_type T;
                        field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr curve_element() :
                            curve_element(params_type::zero_fill[0],
                                          params_type::zero_fill[1],
                                          field_value_type::zero(),
                                          field_value_type::one()) {}

                        /** @brief
                         *    @return the selected point (X:Y:Z)
                         *
                         */
                        constexpr curve_element(const field_value_type& X, const field_value_type& Y, const field_value_type& T, const field_value_type& Z) 
                            : X(X), Y(Y), T(T), Z(Z) 
                        { }

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
                            return curve_element(params_type::one_fill[0],
                                                 params_type::one_fill[1],
                                                 params_type::one_fill[0] * params_type::one_fill[1],
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

                            // X1/Z1 = X2/Z2 <=> X1*Z2 = X2*Z1
                            if ((this->X * other.Z) != (other.X * this->Z)) {
                                return false;
                            }

                            // Y1/Z1 = Y2/Z2 <=> Y1*Z2 = Y2*Z1
                            if ((this->Y * other.Z) != (other.Y * this->Z)) {
                                return false;
                            }

                            // T1/Z1 = T2/Z2 <=> T1*Z2 = T2*Z1
                            if ((this->T * other.Z) != (other.T * this->Z)) {
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
                            return (this->X.is_zero() && this->T.is_zero() && this->Z.is_zero());
                        }

                        /** @brief
                         *
                         * @return true if element from group G1 lies on the elliptic curve
                         */
                        constexpr bool is_well_formed() const {
                            assert(false && "Not implemented yet.");
                            return true;
                        }

                        /*************************  Reducing operations  ***********************************/

                        /** @brief
                         *
                         * @return return the corresponding element from extended coordinates with a=-1 coordinates to
                         * affine coordinates
                         */
                        constexpr curve_element<params_type, form, curves::coordinates::affine> to_affine() const {

                            using result_type = curve_element<params_type, form, curves::coordinates::affine>;

                            if (is_zero()) {
                                return result_type::zero();
                            }

                            // assert((X/Z)*(Y/Z) == (T/Z));
                            return result_type(X / Z, Y / Z);    //  x=X/Z, y=Y/Z
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr curve_element operator=(const curve_element &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->T = other.T;
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
                            return curve_element(-X, Y, -T, Z);
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
                        curve_element mixed_add(const curve_element &other) const {

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
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_EXTENDED_WITH_A_MINUS_1_HPP
