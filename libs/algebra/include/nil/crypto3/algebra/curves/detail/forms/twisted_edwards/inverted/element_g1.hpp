//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_INVERTED_HPP
#define CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_INVERTED_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/forms.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/inverted/add_2008_bbjlp.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/inverted/dbl_2008_bbjlp.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/inverted/madd_2008_bbjlp.hpp>
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
                     *  inverted coordinates representation.
                     *  Description: http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html
                     *
                     */
                    template<typename CurveParams>
                    class curve_element<CurveParams, forms::twisted_edwards, coordinates::inverted> {
                    public:

                        using params_type = CurveParams;
                        using field_type = typename params_type::field_type;

                    private:
                        using field_value_type = typename field_type::value_type;

                        using common_addition_processor = twisted_edwards_element_g1_inverted_add_2008_bbjlp;
                        using common_doubling_processor = twisted_edwards_element_g1_inverted_dbl_2008_bbjlp;
                        using mixed_addition_processor = twisted_edwards_element_g1_inverted_madd_2008_bbjlp;

                    public:
                        using form = forms::twisted_edwards;
                        using coordinates = coordinates::inverted;

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
                            curve_element(params_type::zero_fill[1],
                                          params_type::zero_fill[0],
                                          field_value_type::zero()) {}

                        /** @brief
                         *    @return the selected point (X:Y:Z)
                         *
                         */
                        constexpr curve_element(const field_value_type& X, const field_value_type& Y, const field_value_type& Z)
                            : X(X), Y(Y), Z(Z)
                        { }

                        /** @brief constructor from affine coordinates
                         *
                         */
                        constexpr curve_element(const field_value_type& X, const field_value_type& Y)
                            : X(X.inversed()), Y(Y.inversed()), Z(field_value_type::one())
                        { }


                        template<typename Backend,
                                 boost::multiprecision::expression_template_option ExpressionTemplates>
                        explicit constexpr curve_element(
                                  const boost::multiprecision::number<Backend, ExpressionTemplates> &value) {
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
                            return curve_element(params_type::one_fill[0].inversed(),
                                                 params_type::one_fill[1].inversed(),
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
                            return (this->Y.is_zero() && this->Z.is_zero());
                        }


                        /** @brief
                         *
                         * @return true if element from group G2 lies on the elliptic curve
                         * a*x^2 + y^2 = 1 + d*x^2*y^2
                         * x = Z/X, y = Z/Y
                         * a * Z^2/X^2 + Z^2/Y^2 == 1 + d * Z^4 / X^2 / Y^2
                         * a * Z^2 * Y^2 + Z^2 * X^2 == X^2 * Y^2 + d * Z^4
                         */
                        constexpr bool is_well_formed() const {
                            if (this->is_zero()) {
                                return true;
                            } else {

                                const auto X2 = this->X.squared();
                                const auto Y2 = this->Y.squared();
                                const auto Z2 = this->Z.squared();

                                return (params_type::a * Z2*Y2 + Z2*X2 == X2*Y2 + params_type::d * Z2*Z2);
                            }
                        }

                        /*************************  Reducing operations  ***********************************/

                        /** @brief
                         *
                         * @return return the corresponding element from inverted coordinates to
                         * affine coordinates
                         */
                        constexpr curve_element<params_type, form, typename curves::coordinates::affine>
                            to_affine() const {

                            using result_type = curve_element<params_type, form, typename curves::coordinates::affine>;

                            if (is_zero()) {
                                return result_type::zero();
                            }

                            //  x=Z/X, y=Z/Y
                            return result_type(Z * X.inversed(), Z * Y.inversed());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr curve_element operator=(const curve_element &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        template<typename Backend,
                                 boost::multiprecision::expression_template_option ExpressionTemplates>
                        constexpr const curve_element& operator=(
                                  const boost::multiprecision::number<Backend, ExpressionTemplates> &value) {
                            *this = one() * value;
                            return *this;
                        }

                        constexpr curve_element operator+(const curve_element &other) const {
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return (*this);
                            }

                            curve_element result = *this;

                            if (*this == other) {
                                result.double_inplace();
                                return result;
                            }

                            common_addition_processor::process(result, other);
                            return result;
                        }

                        constexpr curve_element& operator+=(const curve_element &other) {
                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                *this = other;
                            } else if (other.is_zero()) {
                                // Do nothing.
                            } else if (*this == other) {
                                common_doubling_processor::process(*this);
                            } else {
                                common_addition_processor::process(*this, other);
                            }
                            return *this;
                        }

                        constexpr curve_element operator-() const {
                            return curve_element(-(this->X), this->Y, this->Z);
                        }

                        constexpr curve_element operator-(const curve_element &other) const {
                            return (*this) + (-other);
                        }

                        constexpr curve_element& operator-=(const curve_element &other) {
                            return (*this) += (-other);
                        }

                        /** @brief
                         *
                         * @return doubled element from group G1
                         */
                        constexpr void double_inplace() {
                            common_doubling_processor::process(*this);
                        }

                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G1
                         */
                        void mixed_add(const curve_element &other) {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                *this = other;
                                return;
                            }

                            if (other.is_zero()) {
                                return;
                            }

                            mixed_addition_processor::process(*this, other);
                        }
                    };

                    template<typename CurveParams>
                    std::ostream& operator<<(std::ostream& os, curve_element<CurveParams, forms::twisted_edwards, coordinates::inverted> const& e)
                    {
                        os << "{\"X\":" << e.X << ",\"Y\":" << e.Y << ",\"Z\":" << e.Z << "}";
                        return os;
                    }
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_INVERTED_HPP
