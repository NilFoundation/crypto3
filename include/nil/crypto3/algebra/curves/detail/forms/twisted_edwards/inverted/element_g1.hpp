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
#include <nil/crypto3/algebra/curves/detail/forms.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/inverted/add_2008_bbjlp.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/inverted/dbl_2008_bbjlp.hpp>

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
                    //          inverted_coordinates Coordinates>
                    // struct inverted_element_g1;

                    /** @brief A struct representing an element from the group G1 of twisted Edwards curve of 
                     *  inverted coordinates representation.
                     *  Description: http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html
                     *
                     */
                    template<typename CurveParams, 
                             typename Adder = twisted_edwards_element_g1_inverted_add_2008_bbjlp, 
                             typename Doubler = twisted_edwards_element_g1_inverted_dbl_2008_bbjlp>
                    struct twisted_edwards_element_g1_inverted {

                        using params_type = CurveParams;
                        using field_type = typename params_type::field_type;
                    private:
                        using field_value_type = typename field_type::value_type;
                    public:
                        using group_type = typename params_type::group_type;

                        constexpr static const forms form = 
                            forms::edwards;
                        constexpr static const 
                            edwards_coordinates coordinates = 
                            edwards_coordinates::inverted;

                        field_value_type X;
                        field_value_type Y;
                        field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr twisted_edwards_element_g1_inverted() : twisted_edwards_element_g1_inverted(
                            params_type::zero_fill[0], 
                            params_type::zero_fill[1], 
                            params_type::zero_fill[2]) {};

                        /** @brief
                         *    @return the selected point (X:Y:Z)
                         *
                         */
                        constexpr twisted_edwards_element_g1_inverted(field_value_type X,
                                                  field_value_type Y,
                                                  field_value_type Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };

                        /** @brief Get the point at infinity
                         *
                         */
                        constexpr static twisted_edwards_element_g1_inverted zero() {
                            return twisted_edwards_element_g1_inverted();
                        }

                        /** @brief Get the generator of group G1
                         *
                         */
                        constexpr static twisted_edwards_element_g1_inverted one() {
                            return twisted_edwards_element_g1_inverted(params_type::one_fill[0], params_type::one_fill[1], 
                                params_type::one_fill[2]);
                        }

                        /*************************  Comparison operations  ***********************************/

                        constexpr bool operator==(const twisted_edwards_element_g1_inverted &other) const {
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

                        constexpr bool operator!=(const twisted_edwards_element_g1_inverted &other) const {
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
                         * @return true if element from group G1 lies on the elliptic curve
                         */
                        constexpr bool is_well_formed() const {
                            assert(false && "Not implemented yet.");
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr twisted_edwards_element_g1_inverted operator=(const twisted_edwards_element_g1_inverted &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        constexpr twisted_edwards_element_g1_inverted operator+(const twisted_edwards_element_g1_inverted &other) const {
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

                        constexpr twisted_edwards_element_g1_inverted operator-() const {
                            return twisted_edwards_element_g1_inverted(-(this->X), this->Y, this->Z);
                        }

                        constexpr twisted_edwards_element_g1_inverted operator-(const twisted_edwards_element_g1_inverted &other) const {
                            return (*this) + (-other);
                        }
                        
                        /** @brief
                         *
                         * @return doubled element from group G1
                         */
                        constexpr twisted_edwards_element_g1_inverted doubled() const {
                            return Doubler::process(*this);
                        }

                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G1
                         */
                        twisted_edwards_element_g1_inverted mixed_add(const twisted_edwards_element_g1_inverted &other) const {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return *this;
                            }

                            assert(other.Z == field_value_type::one());

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-twisted-inverted.html#addition-madd-2008-bbjlp

                            field_value_type B = params_type::d * (this->Z).squared();          // B = d*Z1^2
                            field_value_type C = (this->X) * (other.X);    // C = X1*X2
                            field_value_type D = (this->Y) * (other.Y);    // D = Y1*Y2
                            field_value_type E = C * D;                    // E = C*D
                            field_value_type H = C - params_type::a * D;                    // H = C-a*D
                            field_value_type I =
                                (this->X + this->Y) * (other.X + other.Y) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                            field_value_type X3 = (E + B) * H;             // X3 = (E+B)*H
                            field_value_type Y3 = (E - B) * I;             // Y3 = (E-B)*I
                            field_value_type Z3 = Z1 * H * I;               // Z3 = Z1*H*I

                            return twisted_edwards_element_g1_inverted(X3, Y3, Z3);
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_INVERTED_HPP
