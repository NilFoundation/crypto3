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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT6_G1_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT6_G1_ELEMENT_HPP

#include <nil/crypto3/algebra/curves/detail/mnt6/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>

#include <nil/crypto3/detail/type_traits.hpp>
#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<std::size_t ModulusBits = 298>
                    struct element_mnt6_g1 {

                        using policy_type = mnt6_basic_policy<ModulusBits>;
                        constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_value_type = g1_field_type_value;

                        underlying_field_value_type X;
                        underlying_field_value_type Y;
                        underlying_field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        /*constexpr static */ const underlying_field_value_type x =
                            underlying_field_value_type(0x00);    //?
                        /*constexpr static */ const underlying_field_value_type y =
                            underlying_field_value_type(0x00);    //?

                        element_mnt6_g1() :
                            element_mnt6_g1(underlying_field_value_type::zero(), underlying_field_value_type::one(),
                                            underlying_field_value_type::zero()) {};
                        // must be
                        // element_mnt6_g1() : element_mnt6_g1(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished

                        element_mnt6_g1(underlying_field_value_type X,
                                        underlying_field_value_type Y,
                                        underlying_field_value_type Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };

                        static element_mnt6_g1 zero() {
                            return element_mnt6_g1();
                        }

                        static element_mnt6_g1 one() {
                            return element_mnt6_g1(
                                underlying_field_value_type(
                                    0x2A4FEEE24FD2C69D1D90471B2BA61ED56F9BAD79B57E0B4C671392584BDADEBC01ABBC0447D_cppui298),
                                underlying_field_value_type(
                                    0x32986C245F6DB2F82F4E037BF7AFD69CBFCBFF07FC25D71E9C75E1B97208A333D73D91D3028_cppui298),
                                underlying_field_value_type::one());
                            // must be
                            // return element_mnt6_g1(one_fill[0], one_fill[1], one_fill[2]);
                            // when constexpr fields will be finished
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const element_mnt6_g1 &other) const {
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

                        bool operator!=(const element_mnt6_g1 &other) const {
                            return !(operator==(other));
                        }

                        bool is_zero() const {
                            return (this->X.is_zero() && this->Z.is_zero());
                        }

                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        element_mnt6_g1 operator=(const element_mnt6_g1 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        element_mnt6_g1 operator+(const element_mnt6_g1 &other) const {
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

                        element_mnt6_g1 operator-() const {
                            return element_mnt6_g1(this->X, -(this->Y), this->Z);
                        }

                        element_mnt6_g1 operator-(const element_mnt6_g1 &other) const {
                            return (*this) + (-other);
                        }

                        element_mnt6_g1 doubled() const {
                            if (this->is_zero()) {
                                return (*this);
                            } else {
                                // NOTE: does not handle O and pts of order 2,4
                                // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#doubling-dbl-2007-bl

                                const underlying_field_value_type XX = (this->X).squared();       // XX  = X1^2
                                const underlying_field_value_type ZZ = (this->Z).squared();       // ZZ  = Z1^2
                                const underlying_field_value_type w = a * ZZ + (XX + XX + XX);    // w   = a*ZZ + 3*XX
                                const underlying_field_value_type Y1Z1 = (this->Y) * (this->Z);
                                const underlying_field_value_type s = Y1Z1 + Y1Z1;      // s   = 2*Y1*Z1
                                const underlying_field_value_type ss = s.squared();     // ss  = s^2
                                const underlying_field_value_type sss = s * ss;         // sss = s*ss
                                const underlying_field_value_type R = (this->Y) * s;    // R   = Y1*s
                                const underlying_field_value_type RR = R.squared();     // RR  = R^2
                                const underlying_field_value_type B =
                                    ((this->X) + R).squared() - XX - RR;    // B   = (X1+R)^2 - XX - RR
                                const underlying_field_value_type h = w.squared() - (B + B);    // h   = w^2 - 2*B
                                const underlying_field_value_type X3 = h * s;                   // X3  = h*s
                                const underlying_field_value_type Y3 =
                                    w * (B - h) - (RR + RR);                   // Y3  = w*(B-h) - 2*RR
                                const underlying_field_value_type Z3 = sss;    // Z3  = sss

                                return element_mnt6_g1(X3, Y3, Z3);
                            }
                        }

                        element_mnt6_g1 mixed_add(const element_mnt6_g1 &other) const {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2
                            // assert(other.Z == underlying_field_value_type::one());

                            if (this->is_zero()) {
                                return other;
                            }

                            if (other.is_zero()) {
                                return (*this);
                            }

                            const underlying_field_value_type &X1Z2 =
                                (this->X);    // X1Z2 = X1*Z2 (but other is special and not zero)
                            const underlying_field_value_type X2Z1 = (this->Z) * (other.X);    // X2Z1 = X2*Z1

                            // (used both in add and double checks)

                            const underlying_field_value_type &Y1Z2 =
                                (this->Y);    // Y1Z2 = Y1*Z2 (but other is special and not zero)
                            const underlying_field_value_type Y2Z1 = (this->Z) * (other.Y);    // Y2Z1 = Y2*Z1

                            if (X1Z2 == X2Z1 && Y1Z2 == Y2Z1) {
                                return this->doubled();
                            }

                            underlying_field_value_type u = Y2Z1 - this->Y;                  // u = Y2*Z1-Y1
                            underlying_field_value_type uu = u.squared();                    // uu = u2
                            underlying_field_value_type v = X2Z1 - this->X;                  // v = X2*Z1-X1
                            underlying_field_value_type vv = v.squared();                    // vv = v2
                            underlying_field_value_type vvv = v * vv;                        // vvv = v*vv
                            underlying_field_value_type R = vv * this->X;                    // R = vv*X1
                            underlying_field_value_type A = uu * this->Z - vvv - R - R;      // A = uu*Z1-vvv-2*R
                            underlying_field_value_type X3 = v * A;                          // X3 = v*A
                            underlying_field_value_type Y3 = u * (R - A) - vvv * this->Y;    // Y3 = u*(R-A)-vvv*Y1
                            underlying_field_value_type Z3 = vvv * this->Z;                  // Z3 = vvv*Z1

                            return element_mnt6_g1(X3, Y3, Z3);
                        }

                    private:
                        element_mnt6_g1 add(const element_mnt6_g1 &other) const {

                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

                            const underlying_field_value_type Y1Z2 = (this->Y) * (other.Z);        // Y1Z2 = Y1*Z2
                            const underlying_field_value_type X1Z2 = (this->X) * (other.Z);        // X1Z2 = X1*Z2
                            const underlying_field_value_type Z1Z2 = (this->Z) * (other.Z);        // Z1Z2 = Z1*Z2
                            const underlying_field_value_type u = (other.Y) * (this->Z) - Y1Z2;    // u    = Y2*Z1-Y1Z2
                            const underlying_field_value_type uu = u.squared();                    // uu   = u^2
                            const underlying_field_value_type v = (other.X) * (this->Z) - X1Z2;    // v    = X2*Z1-X1Z2
                            const underlying_field_value_type vv = v.squared();                    // vv   = v^2
                            const underlying_field_value_type vvv = v * vv;                        // vvv  = v*vv
                            const underlying_field_value_type R = vv * X1Z2;                       // R    = vv*X1Z2
                            const underlying_field_value_type A =
                                uu * Z1Z2 - (vvv + R + R);                   // A    = uu*Z1Z2 - vvv - 2*R
                            const underlying_field_value_type X3 = v * A;    // X3   = v*A
                            const underlying_field_value_type Y3 =
                                u * (R - A) - vvv * Y1Z2;                         // Y3   = u*(R-A) - vvv*Y1Z2
                            const underlying_field_value_type Z3 = vvv * Z1Z2;    // Z3   = vvv*Z1Z2

                            return element_mnt6_g1(X3, Y3, Z3);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/

                        element_mnt6_g1 to_affine_coordinates() const {
                            underlying_field_value_type p_out[3];

                            if (this->is_zero()) {
                                p_out[0] = underlying_field_value_type::zero();
                                p_out[1] = underlying_field_value_type::one();
                                p_out[2] = underlying_field_value_type::zero();
                            } else {
                                const underlying_field_value_type Z_inv = this->Z.inversed();
                                p_out[0] = this->X * Z_inv;
                                p_out[1] = this->Y * Z_inv;
                                p_out[2] = underlying_field_value_type::one();
                            }

                            return element_mnt6_g1(p_out[0], p_out[1], p_out[2]);
                        }

                        element_mnt6_g1 to_special() const {
                            return this->to_affine_coordinates();
                        }

                    private:
                        /*constexpr static */ const g1_field_type_value a = g1_field_type_value(policy_type::a);
                        /*constexpr static */ const g1_field_type_value b = g1_field_type_value(policy_type::b);

                        /*constexpr static const g2_field_type_value twist =
                            g2_field_type_value(typename g2_field_type_value::underlying_type::zero(),
                                                typename g2_field_type_value::underlying_type::one(),
                                                typename g2_field_type_value::underlying_type::zero());

                        static const g2_field_type_value twist_coeff_a = mnt6_g2<ModulusBits>::a;
                        static const g2_field_type_value twist_coeff_b = mnt6_g2<ModulusBits>::b;

                        static const g1_field_type_value twist_mul_by_a_c0 =
                            element_mnt6_g1<ModulusBits>::a * g2_field_type_value::non_residue;
                        static const g1_field_type_value twist_mul_by_a_c1 =
                            element_mnt6_g1<ModulusBits>::a * g2_field_type_value::non_residue;
                        static const g1_field_type_value twist_mul_by_a_c2 = 
                            element_mnt6_g1<ModulusBits>::a; static const g1_field_type_value twist_mul_by_b_c0 =
                            element_mnt6_g1<ModulusBits>::b * g2_field_type_value::non_residue;
                        static const g1_field_type_value twist_mul_by_b_c1 =
                            element_mnt6_g1<ModulusBits>::b * g2_field_type_value::non_residue;
                        static const g1_field_type_value twist_mul_by_b_c2 =
                            element_mnt6_g1<ModulusBits>::b * g2_field_type_value::non_residue;

                        static const g1_field_type_value twist_mul_by_q_X(
                            0x8696C330D743F33B572CEF4DF62CE7ECB178EE24E48D1A53736E86448E74CB48DAACBB414_cppui298);
                        static const g1_field_type_value twist_mul_by_q_Y(
                            0x3BCF7BCD473A266249DA7B0548ECAEEC9635CF44194FB494C07925D6AD3BB4334A400000000_cppui298);*/

                        /*constexpr static const underlying_field_value_type zero_fill = {
                            underlying_field_value_type::zero(), underlying_field_value_type::one(),
                            underlying_field_value_type::zero()};

                        constexpr static const underlying_field_value_type one_fill = {
                            underlying_field_value_type(
                                0x2A4FEEE24FD2C69D1D90471B2BA61ED56F9BAD79B57E0B4C671392584BDADEBC01ABBC0447D_cppui298),
                            underlying_field_value_type(
                                0x32986C245F6DB2F82F4E037BF7AFD69CBFCBFF07FC25D71E9C75E1B97208A333D73D91D3028_cppui298),
                            underlying_field_value_type::one()};*/
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_MNT6_G1_ELEMENT_HPP
