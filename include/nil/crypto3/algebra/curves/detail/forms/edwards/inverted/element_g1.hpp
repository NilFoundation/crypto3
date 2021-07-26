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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_ELEMENT_INVERTED_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_ELEMENT_INVERTED_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/detail/forms.hpp>

#include <nil/crypto3/algebra/curves/detail/forms/edwards/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/edwards/inverted/add_2007_bl.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/edwards/inverted/dbl_2007_bl.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/edwards/inverted/madd_2007_bl.hpp>

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

                    /** @brief A struct representing an element from the group G1 of Edwards curve of 
                     *  inverted coordinates representation.
                     *  Description: http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html
                     *
                     */
                    template<typename CurveParams, 
                             typename Adder = edwards_element_g1_inverted_add_2007_bl, 
                             typename Doubler = edwards_element_g1_inverted_dbl_2007_bl, 
                             typename MixAdd = edwards_element_g1_inverted_madd_2007_bl>
                    struct edwards_element_g1_inverted {

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
                        constexpr edwards_element_g1_inverted() : edwards_element_g1_inverted(
                            params_type::zero_fill[0], 
                            params_type::zero_fill[1], 
                            params_type::zero_fill[2]) {};

                        /** @brief
                         *    @return the selected point (X:Y:Z)
                         *
                         */
                        constexpr edwards_element_g1_inverted(field_value_type X,
                                                  field_value_type Y,
                                                  field_value_type Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };

                        /** @brief Get the point at infinity
                         *
                         */
                        constexpr static edwards_element_g1_inverted zero() {
                            return edwards_element_g1_inverted();
                        }

                        /** @brief Get the generator of group G1
                         *
                         */
                        constexpr static edwards_element_g1_inverted one() {
                            return edwards_element_g1_inverted(params_type::one_fill[0], params_type::one_fill[1], 
                                params_type::one_fill[2]);
                        }

                        /*************************  Comparison operations  ***********************************/

                        constexpr bool operator==(const edwards_element_g1_inverted &other) const {
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

                        constexpr bool operator!=(const edwards_element_g1_inverted &other) const {
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

                        constexpr edwards_element_g1_inverted operator=(const edwards_element_g1_inverted &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        constexpr edwards_element_g1_inverted operator+(const edwards_element_g1_inverted &other) const {
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

                        constexpr edwards_element_g1_inverted operator-() const {
                            return edwards_element_g1_inverted(-(this->X), this->Y, this->Z);
                        }

                        constexpr edwards_element_g1_inverted operator-(const edwards_element_g1_inverted &other) const {
                            return (*this) + (-other);
                        }
                        
                        /** @brief
                         *
                         * @return doubled element from group G1
                         */
                        constexpr edwards_element_g1_inverted doubled() const {
                            return Doubler::process(*this);
                        }

                        /** @brief
                         *
                         * “Mixed addition” refers to the case Z2 known to be 1.
                         * @return addition of two elements from group G1
                         */
                        edwards_element_g1_inverted mixed_add(const edwards_element_g1_inverted &other) const {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return *this;
                            }

                            return MixAdd::process(*this, other);
                        }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_ELEMENT_INVERTED_HPP
