//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_ELEMENT_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/g2.hpp>
#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<std::size_t ModulusBits>
                    struct edwards_g1;

                    template<std::size_t ModulusBits>
                    struct element_edwards_g1 { };

                    template<>
                    struct element_edwards_g1<183> {

                        using group_type = edwards_g1<183>;

                        using policy_type = edwards_basic_policy<183>;
                        using underlying_field_type = typename policy_type::g1_field_type;

                        using g1_field_type_value = typename policy_type::g1_field_type::value_type;
                        // must be removed later

                        typedef typename underlying_field_type::value_type underlying_field_value_type;

                        underlying_field_value_type X;
                        underlying_field_value_type Y;
                        underlying_field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        element_edwards_g1() :
                            element_edwards_g1(underlying_field_value_type::zero(),
                                               underlying_field_value_type::one(),
                                               underlying_field_value_type::zero()) {};
                        // must be
                        // element_edwards_g1() : element_edwards_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished

                        element_edwards_g1(underlying_field_value_type in_X, underlying_field_value_type in_Y,
                                           underlying_field_value_type in_Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };

                        element_edwards_g1(underlying_field_value_type X, underlying_field_value_type Y) :
                            element_edwards_g1(X, Y, X * Y) {};

                        static element_edwards_g1 zero() {
                            return element_edwards_g1();
                        }

                        static element_edwards_g1 one() {
                            return element_edwards_g1(
                                underlying_field_value_type(0x26C5DF4587AA6A5D345EFC9F2D47F8B1656517EF618F7A_cppui182),
                                underlying_field_value_type(
                                    0x32D83D8AAA0C500F57B15FDA90B1AD111067F812C7DD27_cppui182));    // it's better to
                                                                                                    // precompute also
                                                                                                    // one_fill[2]
                            // must be
                            // return element_edwards_g1(one_fill[0], one_fill[1]);    // it's better to precompute also
                            // one_fill[2] when constexpr fields will be finished
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const element_edwards_g1 &other) const {
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

                        bool operator!=(const element_edwards_g1 &other) const {
                            return !(operator==(other));
                        }

                        bool is_zero() const {
                            return (this->Y.is_zero() && this->Z.is_zero());
                        }

                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        element_edwards_g1 operator=(const element_edwards_g1 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        element_edwards_g1 operator+(const element_edwards_g1 &other) const {
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

                        element_edwards_g1 operator-() const {
                            return element_edwards_g1(-(this->X), this->Y, this->Z);
                        }

                        element_edwards_g1 operator-(const element_edwards_g1 &B) const {
                            return (*this) + (-B);
                        }

                        element_edwards_g1 doubled() const {

                            if (this->is_zero()) {
                                return (*this);
                            } else {
                                // NOTE: does not handle O and pts of order 2,4
                                // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#doubling-dbl-2007-bl

                                underlying_field_value_type A = (this->X).squared();                  // A = X1^2
                                underlying_field_value_type B = (this->Y).squared();                  // B = Y1^2
                                underlying_field_value_type C = A + B;                                // C = A+B
                                underlying_field_value_type D = A - B;                                // D = A-B
                                underlying_field_value_type E = (this->X + this->Y).squared() - C;    // E = (X1+Y1)^2-C
                                underlying_field_value_type X3 = C * D;                               // X3 = C*D
                                underlying_field_value_type dZZ = d * this->Z.squared();
                                underlying_field_value_type Y3 = E * (C - dZZ - dZZ);    // Y3 = E*(C-2*d*Z1^2)
                                underlying_field_value_type Z3 = D * E;                  // Z3 = D*E

                                return element_edwards_g1(X3, Y3, Z3);
                            }
                        }

                        element_edwards_g1 mixed_add(const element_edwards_g1 &other) const {

                            // handle special cases having to do with O
                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return *this;
                            }

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-madd-2007-lb

                            underlying_field_value_type A = this->Z;                  // A = Z1
                            underlying_field_value_type B = d * A.squared();          // B = d*A^2
                            underlying_field_value_type C = (this->X) * (other.X);    // C = X1*X2
                            underlying_field_value_type D = (this->Y) * (other.Y);    // D = Y1*Y2
                            underlying_field_value_type E = C * D;                    // E = C*D
                            underlying_field_value_type H = C - D;                    // H = C-D
                            underlying_field_value_type I =
                                (this->X + this->Y) * (other.X + other.Y) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                            underlying_field_value_type X3 = (E + B) * H;             // X3 = c*(E+B)*H
                            underlying_field_value_type Y3 = (E - B) * I;             // Y3 = c*(E-B)*I
                            underlying_field_value_type Z3 = A * H * I;               // Z3 = A*H*I

                            return element_edwards_g1(X3, Y3, Z3);
                        }

                    private:
                        element_edwards_g1 add(const element_edwards_g1 &other) const {

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-edwards-inverted.html#addition-add-2007-bl

                            underlying_field_value_type A = (this->Z) * (other.Z);    // A = Z1*Z2
                            underlying_field_value_type B = d * A.squared();          // B = d*A^2
                            underlying_field_value_type C = (this->X) * (other.X);    // C = X1*X2
                            underlying_field_value_type D = (this->Y) * (other.Y);    // D = Y1*Y2
                            underlying_field_value_type E = C * D;                    // E = C*D
                            underlying_field_value_type H = C - D;                    // H = C-D
                            underlying_field_value_type I =
                                (this->X + this->Y) * (other.X + other.Y) - C - D;    // I = (X1+Y1)*(X2+Y2)-C-D
                            underlying_field_value_type X3 = (E + B) * H;             // X3 = c*(E+B)*H
                            underlying_field_value_type Y3 = (E - B) * I;             // Y3 = c*(E-B)*I
                            underlying_field_value_type Z3 = A * H * I;               // Z3 = A*H*I

                            return element_edwards_g1(X3, Y3, Z3);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/

                        element_edwards_g1 to_affine_coordinates() const {
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

                            return element_edwards_g1(p_out[0], p_out[1], p_out[2]);
                        }

                        element_edwards_g1 to_special() const {
                            underlying_field_value_type p_out[3];

                            if (this->Z.is_zero()) {
                                return *this;
                            }

                            underlying_field_value_type Z_inv = this->Z.inversed();
                            p_out[0] = this->X * Z_inv;
                            p_out[1] = this->Y * Z_inv;
                            p_out[2] = underlying_field_value_type::one();

                            return element_edwards_g1(p_out[0], p_out[1], p_out[2]);
                        }

                    private:
                        /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                        /*constexpr static */ const g1_field_type_value d = g1_field_type_value(policy_type::d);

                        /*constexpr static const underlying_field_value_type zero_fill = {
                            underlying_field_value_type::zero(), underlying_field_value_type::one(),
                            underlying_field_value_type::zero()};

                        constexpr static const underlying_field_value_type one_fill = {
                            underlying_field_value_type(0x26C5DF4587AA6A5D345EFC9F2D47F8B1656517EF618F7A_cppui182),
                            underlying_field_value_type(0x32D83D8AAA0C500F57B15FDA90B1AD111067F812C7DD27_cppui182)};*/
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_G1_ELEMENT_HPP
