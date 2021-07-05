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

#ifndef CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/jubjub/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/babyjubjub/basic_policy.hpp>

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /** @brief A struct representing a group G1 of Edwards curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct edwards_g1;
                    
                    /** @brief A struct representing an element from the group G1 of edwards curve.
                     *
                     */
                    template<std::size_t Version>
                    struct element_twisted_edwards_g1 {
                        constexpr static const std::size_t version = Version;

                        using group_type = edwards_g1<version>;

                        using policy_type = edwards_basic_policy<version>;
                        using underlying_field_type = typename policy_type::g1_field_type;

                        using g1_field_type_value = typename policy_type::g1_field_type::value_type;
                        // must be removed later

                        typedef typename underlying_field_type::value_type underlying_field_value_type;

                        underlying_field_value_type X;
                        underlying_field_value_type Y;
                        underlying_field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/
                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr element_twisted_edwards_g1() : element_twisted_edwards_g1(policy_type::g1_zero_fill[0], 
                            policy_type::g1_zero_fill[1], policy_type::g1_zero_fill[2]) {};

                        /** @brief
                         *    @return the selected point $(X:Y:Z)$ in the projective coordinates
                         *
                         */
                        constexpr element_twisted_edwards_g1(underlying_field_value_type in_X, underlying_field_value_type in_Y,
                                           underlying_field_value_type in_Z = underlying_field_value_type::one()) {
                            this->X = in_X;
                            this->Y = in_Y;
                            this->Z = in_Z;
                        };

                        /** @brief Get the point at infinity
                         *
                         */
                        static element_twisted_edwards_g1 zero() {
                            return element_twisted_edwards_g1();
                        }
                        /** @brief Get the generator of group G1
                         *
                         */
                        static element_twisted_edwards_g1 one() {
                            return element_twisted_edwards_g1(policy_type::g1_one_fill[0], policy_type::g1_one_fill[1],
                                                              policy_type::g1_one_fill[2]);
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const element_twisted_edwards_g1 &other) const {
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

                        bool operator!=(const element_twisted_edwards_g1 &other) const {
                            return !(operator==(other));
                        }
                        /** @brief
                         *
                         * @return true if element from group G1 is the point at infinity
                         */
                        bool is_zero() const {
                            return (this->X.is_zero() && this->Y.is_one() && this->Z.is_zero());
                        }
                        /** @brief
                         *
                         * @return true if element from group G1 in affine coordinates
                         */
                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }

                        /** @brief
                         *
                         * @return true if element from group G1 lies on the elliptic curve
                         * 
                         * A check, that a*X*X + Y*Y = 1 + d*X*X*Y*Y
                         */
                        constexpr bool is_well_formed() const {
                            if (this->is_zero()) {
                                return true;
                            } else {
                                
                                underlying_field_value_type XX = this->X.squared();
                                underlying_field_value_type YY = this->Y.squared();

                                return (underlying_field_value_type(policy_type::a)*XX + YY == 
                                    underlying_field_value_type::one() + 
                                    underlying_field_value_type(policy_type::d)*XX*YY);
                            }
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        element_twisted_edwards_g1 operator=(const element_twisted_edwards_g1 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        element_twisted_edwards_g1 operator+(const element_twisted_edwards_g1 &other) const {
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

                        element_twisted_edwards_g1 operator-() const {
                            return element_twisted_edwards_g1(-(this->X), this->Y, this->Z);
                        }

                        element_twisted_edwards_g1 operator-(const element_twisted_edwards_g1 &B) const {
                            return (*this) + (-B);
                        }
                        /** @brief
                         *
                         * @return doubled element from group G1
                         */
                        element_twisted_edwards_g1 doubled() const {

                            if (this->is_zero()) {
                                return (*this);
                            } else {
                                
                                return this->add(*this); // Temporary intil we find something more efficient
                            }
                        }

                    private:

                        element_twisted_edwards_g1 add(const element_twisted_edwards_g1 &other) const {
                            underlying_field_value_type XX = (this->X)*(other.X);
                            underlying_field_value_type YY = (this->Y)*(other.Y);
                            underlying_field_value_type XY = (this->X)*(other.Y);
                            underlying_field_value_type YX = (this->Y)*(other.X);

                            underlying_field_value_type lambda = d * XX * YY;
                            underlying_field_value_type X3 = (XY + YX) * 
                                (underlying_field_value_type::one() + lambda).inversed();
                            underlying_field_value_type Y3 = (YY - a * XX) * 
                                (underlying_field_value_type::one() - lambda).inversed();

                            return element_twisted_edwards_g1(X3, Y3);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/
                        /** @brief
                         *
                         * @return return the corresponding element from inverted coordinates to affine coordinates
                         */
                        element_twisted_edwards_g1 to_affine() const {
                            underlying_field_value_type p_out[3];

                            if (this->is_zero()) {
                                p_out[0] = underlying_field_value_type::zero();
                                p_out[1] = underlying_field_value_type::one();
                                p_out[2] = underlying_field_value_type::one();
                            } else {
                                // go from inverted coordinates to projective coordinates
                                underlying_field_value_type tX = this->Y * this->Z;
                                underlying_field_value_type tY = this->X * this->Z;
                                underlying_field_value_type tZ = this->X * this->Y;
                                // go from projective coordinates to affine coordinates
                                underlying_field_value_type tZ_inv = tZ.inversed();
                                p_out[0] = tX * tZ_inv;
                                p_out[1] = tY * tZ_inv;
                                p_out[2] = underlying_field_value_type::one();
                            }

                            return element_twisted_edwards_g1(p_out[0], p_out[1], p_out[2]);
                        }
                        /** @brief
                         *
                         * @return return the corresponding element from projective coordinates to affine coordinates
                         */
                        element_twisted_edwards_g1 to_projective() const {
                            underlying_field_value_type p_out[3];

                            if (this->Z.is_zero()) {
                                return *this;
                            }

                            underlying_field_value_type Z_inv = this->Z.inversed();
                            p_out[0] = this->X * Z_inv;
                            p_out[1] = this->Y * Z_inv;
                            p_out[2] = underlying_field_value_type::one();

                            return element_twisted_edwards_g1(p_out[0], p_out[1], p_out[2]);
                        }

                    private:
                        constexpr static const g1_field_type_value a = policy_type::a;
                        constexpr static const g1_field_type_value d = policy_type::d;
                    };

                    template <std::size_t Version>
                    constexpr typename element_twisted_edwards_g1<Version>::g1_field_type_value const 
                        element_twisted_edwards_g1<Version>::a;
                    
                    template <std::size_t Version>
                    constexpr typename element_twisted_edwards_g1<Version>::g1_field_type_value const 
                        element_twisted_edwards_g1<Version>::d;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_HPP
