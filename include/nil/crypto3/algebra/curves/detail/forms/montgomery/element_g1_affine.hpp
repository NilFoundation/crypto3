//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_MONTGOMERY_G1_ELEMENT_AFFINE_HPP
#define CRYPTO3_ALGEBRA_CURVES_MONTGOMERY_G1_ELEMENT_AFFINE_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/montgomery/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /**
                     * @brief A struct representing a group G1 of elliptic curve.
                     *    @tparam CurveParams Parameters of the group
                     *    @tparam Form Form of the curve
                     *    @tparam Coordinates Representation coordinates of the group element
                     */
                    template<typename CurveParams, typename Form, typename Coordinates>
                    class curve_element;

                    /**
                     * @brief A struct representing an element from the group G1 of Montgomery curve of
                     *  affine coordinates representation.
                     *  Description: https://hyperelliptic.org/EFD/g1p/auto-montgom.html
                     *
                     */
                    template<typename CurveParams>
                    class curve_element<CurveParams, forms::montgomery, coordinates::affine> {
                    public:
                        using field_type = typename CurveParams::field_type;

                    private:
                        using params_type = CurveParams;
                        using field_value_type = typename field_type::value_type;

                        bool is_inf_point;

                    public:
                        using form = forms::montgomery;
                        using coordinates = coordinates::affine;

                        using group_type = typename params_type::template group_type<coordinates>;

                        field_value_type X;
                        field_value_type Y;

                        /*************************  Constructors and zero/one  ***********************************/
                        /**
                         * @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr curve_element() : is_inf_point(true) {};

                        /**
                         * @brief
                         *    @return the selected point $(X:Y:Z)$ in the projective coordinates
                         */
                        constexpr curve_element(const field_value_type &in_X, const field_value_type &in_Y) :
                            is_inf_point(false), X(in_X), Y(in_Y) {};

                        template<typename Backend,
                                 multiprecision::expression_template_option ExpressionTemplates>
                        explicit constexpr curve_element(
                                  const multiprecision::number<Backend, ExpressionTemplates> &value) {
                            *this = one() * value;
                        }

                        /**
                         * @brief Get the point at infinity
                         */
                        static curve_element zero() {
                            return curve_element();
                        }

                        /**
                         * @brief Get the generator of group G1
                         */
                        static curve_element one() {
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

                        /**
                         * @brief
                         *
                         * @return true if element from group G1 is the point at infinity
                         */
                        constexpr bool is_zero() const {
                            return this->is_inf_point;
                        }

                        /**
                         * @brief Check that point coordinates satisfy curve equitation: b*y^2 = x^3 + a*x^2 + x
                         *
                         * @return true if element from group G1 lies on the elliptic curve
                         */
                        constexpr bool is_well_formed() const {
                            if (this->is_zero()) {
                                return true;
                            } else {
                                field_value_type XX = this->X.squared();
                                field_value_type YY = this->Y.squared();

                                return (field_value_type(params_type::B) * YY) ==
                                       (XX * this->X + field_value_type(params_type::A) * XX + this->X);
                            }
                        }

                        /*************************  Reducing operations  ***********************************/

                        // /** @brief
                        //  *
                        //  * See https://eprint.iacr.org/2017/212.pdf, p. 7, par. 3.
                        //  *
                        //  * @return return the corresponding element from affine coordinates to
                        //  xz coordinates
                        //  */
                        // constexpr curve_element<params_type, form, typename curves::coordinates::xz> to_xz() const {
                        //     using result_type = curve_element<params_type, form, typename curves::coordinates::xz>;
                        //
                        //     return this->is_zero() ? result_type(result_type::field_type::value_type::one(),
                        //                                          result_type::field_type::value_type::zero()) :
                        //                              result_type(this->X,
                        //                              result_type::field_type::value_type::one());
                        // }

                        /**
                         * @brief
                         *
                         * @return return the corresponding element from affine coordinates to affine coordinates. Just
                         * for compatibility.
                         */
                        constexpr curve_element to_affine() const {
                            return *this;
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr curve_element operator=(const curve_element &other) {
                            this->is_inf_point = other.is_inf_point;

                            if (!other.is_zero()) {
                                this->X = other.X;
                                this->Y = other.Y;
                            }

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

                        /**
                         * @brief Affine negation formulas: -(x1,y1)=(x1,-y1).
                         *
                         * @return negative element from group G1
                         */
                        constexpr curve_element operator-() const {
                            return curve_element(this->X, -(this->Y));
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

                        /**
                         * @brief Affine doubling formulas: 2(x1,y1)=(x3,y3) where
                         *
                         * x3 = b*(3*x1^2+2*a*x1+1)^2/(2*b*y1)^2-a-x1-x1
                         * y3 = (2*x1+x1+a)*(3*x1^2+2*a*x1+1)/(2*b*y1)-b*(3*x1^2+2*a*x1+1)^3/(2*b*y1)^3-y1
                         *
                         * See https://hyperelliptic.org/EFD/g1p/auto-montgom.html
                         *
                         * @return doubled element from group G1
                         */
                        constexpr curve_element doubled() const {
                            if (this->is_zero()) {
                                return (*this);
                            } else {
                                const field_value_type two(2);
                                const field_value_type three(3);
                                const field_value_type A(params_type::A);
                                const field_value_type B(params_type::B);

                                const field_value_type temp1 = two * B * this->Y;
                                const field_value_type temp2 =
                                    three * this->X.squared() + two * A * this->X + field_value_type::one();
                                const field_value_type temp1_sqr = temp1.squared();
                                const field_value_type temp2_sqr = temp2.squared();

                                return curve_element((B * temp2_sqr) / temp1_sqr - A - this->X - this->X,
                                                     ((three * this->X + A) * temp2) / temp1 -
                                                         (B * temp2 * temp2_sqr) / (temp1 * temp1_sqr) - this->Y);
                            }
                        }

                    private:
                        /**
                         * @brief Affine addition formulas: (x1,y1)+(x2,y2)=(x3,y3) where
                         *
                         * x3 = b*(y2-y1)^2/(x2-x1)^2-a-x1-x2
                         * y3 = (2*x1+x2+a)*(y2-y1)/(x2-x1)-b*(y2-y1)^3/(x2-x1)^3-y1
                         *
                         * See https://hyperelliptic.org/EFD/g1p/auto-montgom.html
                         *
                         * @return addition of two elements from group G1
                         */
                        constexpr curve_element add(const curve_element &other) const {
                            const field_value_type two(2);
                            const field_value_type A(params_type::A);
                            const field_value_type B(params_type::B);

                            const field_value_type temp1 = (other.Y) - (this->Y);
                            const field_value_type temp2 = (other.X) - (this->X);
                            const field_value_type temp1_sqr = temp1.squared();
                            const field_value_type temp2_sqr = temp2.squared();

                            return curve_element((B * temp1_sqr) / temp2_sqr - A - this->X - other.X,
                                                 ((two * this->X + other.X + A) * temp1) / temp2 -
                                                     (B * temp1 * temp1_sqr) / (temp2 * temp2_sqr) - this->Y);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/

                        /**
                         * @brief Convert point coordinates into twisted Edwards form according to birational
                         * equivalence map:
                         *
                         * - Montgomery(A', B') -–> Twisted Edwards(a, d)
                         *             (u', v') --> (x, y)
                         *   where
                         *   A' = 2 * (a + d) / (a - d)
                         *   B' = 4 / (a - d)
                         *
                         *   x = u' / v'
                         *   y = (u' - 1) / (u' + 1)
                         *
                         * - Montgomery(A', B') -–> Montgomery(A, B)
                         *             (u', v') --> (u, v)
                         *   where
                         *   A == A'
                         *   B = s^2 * B' (mod p) <=> s = (B / B').sqrt() (mod p)
                         *
                         *   u = u'
                         *   s * v = v'
                         *
                         * - Montgomery(A, B) -–> Twisted Edwards(a, d)
                         *             (u, v) --> (x, y)
                         *
                         *   x = u' / v' = u / (s * v)
                         *   y = (u - 1) / (u + 1)
                         *
                         * See
                         * https://math.stackexchange.com/questions/1391732/birational-equvalence-of-twisted-edwards-and-montgomery-curves
                         * See
                         * https://math.stackexchange.com/questions/1392277/point-conversion-between-twisted-edwards-and-montgomery-curves
                         *
                         * @return point in affine coordinates of twisted Edwards form
                         */
                        constexpr auto to_twisted_edwards() const {
                            using result_params =
                                typename group_type::curve_type::template g1_type<curves::coordinates::affine,
                                                                                  forms::twisted_edwards>::params_type;
                            using result_type =
                                typename group_type::curve_type::template g1_type<curves::coordinates::affine,
                                                                                  forms::twisted_edwards>::value_type;

                            if (this->is_zero()) {
                                return result_type();
                            }

                            assert(static_cast<field_value_type>(params_type::A) ==
                                   static_cast<field_value_type>(2) *
                                       (static_cast<field_value_type>(result_params::a) +
                                        static_cast<field_value_type>(result_params::d)) /
                                       (static_cast<field_value_type>(result_params::a) -
                                        static_cast<field_value_type>(result_params::d)));

                            field_value_type s_inv = field_value_type::one();
                            field_value_type B_ =
                                static_cast<field_value_type>(4) / (static_cast<field_value_type>(result_params::a) -
                                                                    static_cast<field_value_type>(result_params::d));
                            if (static_cast<field_value_type>(params_type::B) != B_) {
                                s_inv = (B_ / static_cast<field_value_type>(params_type::B)).sqrt();
                            }

                            return result_type(s_inv * this->X / this->Y,
                                               (this->X - field_value_type::one()) /
                                                   (this->X + field_value_type::one()));
                        }
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_MONTGOMERY_G1_ELEMENT_AFFINE_HPP
