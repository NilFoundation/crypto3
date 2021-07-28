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

#ifndef CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_AFFINE_HPP
#define CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_AFFINE_HPP

#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>
#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>

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
                             typename Form, 
                             typename Coordinates>
                    struct curve_element;
                    
                    /** @brief A struct representing an element from the group G1 of twisted Edwards curve of 
                     *  affine coordinates representation. 
                     *  Twisted Edwards curves introduced on https://eprint.iacr.org/2008/013.pdf
                     *  Description: https://hyperelliptic.org/EFD/g1p/auto-twisted.html
                     *
                     */
                    template<typename CurveParams>
                    struct curve_element<CurveParams, 
                                   forms::twisted_edwards, 
                                   coordinates::affine> {

                        using field_type = typename CurveParams::field_type;
                    private:
                        using params_type = CurveParams;
                        using field_value_type = typename field_type::value_type;
                    public:
                        using group_type = typename params_type::group_type;

                        using form = forms::twisted_edwards;
                        using coordinates = coordinates::affine;

                        field_value_type X;
                        field_value_type Y;

                        /*************************  Constructors and zero/one  ***********************************/
                        /** @brief
                         *    @return the point at infinity by default
                         *
                         */
                        constexpr curve_element() : curve_element(params_type::zero_fill[0], 
                            params_type::zero_fill[1]) {};

                        /** @brief
                         *    @return the selected point $(X:Y:Z)$ in the projective coordinates
                         *
                         */
                        constexpr curve_element(field_value_type in_X, field_value_type in_Y) {
                            this->X = in_X;
                            this->Y = in_Y;
                        };

                        // constexpr curve_element(twisted_edwards_element_g1_projective<params_type> other) {

                        //     if (other.Z.is_zero()) {
                        //         *this = this->zero();
                        //     }

                        //     field_value_type Z_inv = other.Z.inversed();
                        //     X[0] = other.X * Z_inv;
                        //     Y[1] = other.Y * Z_inv;
                        // };

                        /** @brief Get the point at infinity
                         *
                         */
                        static curve_element zero() {
                            return curve_element();
                        }
                        /** @brief Get the generator of group G1
                         *
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
                        /** @brief
                         *
                         * @return true if element from group G1 is the point at infinity
                         */
                        constexpr bool is_zero() const {
                            return X == params_type::zero_fill[0] && Y == params_type::zero_fill[0];
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
                                
                                field_value_type XX = this->X.squared();
                                field_value_type YY = this->Y.squared();

                                return (field_value_type(params_type::a)*XX + YY == 
                                    field_value_type::one() + 
                                    field_value_type(params_type::d)*XX*YY);
                            }
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        constexpr curve_element operator=(const curve_element &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;

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

                        constexpr curve_element operator-() const {
                            return curve_element(-(this->X), this->Y);
                        }

                        constexpr curve_element operator-(const curve_element &B) const {
                            return (*this) + (-B);
                        }
                        /** @brief
                         *
                         * @return doubled element from group G1
                         */
                        constexpr curve_element doubled() const {

                            if (this->is_zero()) {
                                return (*this);
                            } else {
                                
                                return this->add(*this); // Temporary intil we find something more efficient
                            }
                        }

                    private:
                        /** @brief
                         * Affine addition formulas: (x1,y1)+(x2,y2)=(x3,y3) where 
                         *   x3 = (x1*y2+y1*x2)/(1+d*x1*x2*y1*y2)
                         *   y3 = (y1*y2-a*x1*x2)/(1-d*x1*x2*y1*y2)
                         */
                        curve_element add(const curve_element &other) const {
                            field_value_type XX = (this->X)*(other.X);
                            field_value_type YY = (this->Y)*(other.Y);
                            field_value_type XY = (this->X)*(other.Y);
                            field_value_type YX = (this->Y)*(other.X);

                            field_value_type lambda = params_type::d * XX * YY;
                            field_value_type X3 = (XY + YX) * 
                                (field_value_type::one() + lambda).inversed();
                            field_value_type Y3 = (YY - params_type::a * XX) * 
                                (field_value_type::one() - lambda).inversed();

                            return curve_element(X3, Y3);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/

                        // /** @brief
                        //  *
                        //  * @return return the corresponding element from twisted edwards form and 
                        //  * affine coordinates to montgomery form and affine coordinates
                        //  */
                        // // This should be moved to montgomery form element constructor
                        // curve_element<params_type, 
                        //     forms::montgomery, coordinates> to_montgomery() const {
                        //     field_value_type p_out[3];

                        //     // The only points on the curve with x=0 or y=1 (for which birational equivalence is not valid), 
                        //     // are (0,1) and (0,-1), both of which are of low order, and should therefore not occur.
                        //     assert(!(this->X.is_zero()) && this->Y != field_value_type::one());
                            
                        //     // (x, y) -> (u, v) where
                        //     //      u = (1 + y) / (1 - y)
                        //     //      v = u / x
                        //     field_value_type u = 
                        //         (field_value_type::one() + this->Y) * 
                        //         (field_value_type::one() - this->Y).inversed();
                        //     return curve_element<params_type, 
                        //         forms::montgomery, coordinates>{u, 
                        //             params_type::scale * u * this->X.inversed()};
                        // }
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_TWISTED_EDWARDS_G1_ELEMENT_AFFINE_HPP
