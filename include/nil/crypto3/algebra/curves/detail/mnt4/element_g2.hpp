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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT4_G2_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT4_G2_ELEMENT_HPP

#include <nil/crypto3/algebra/curves/detail/mnt4/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt4/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/scalar_mul.hpp>

#include <nil/crypto3/algebra/detail/type_traits.hpp>
#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                    struct element_mnt4_g2 {

                        using policy_type = mnt4_basic_policy<ModulusBits, GeneratorBits>;
                        constexpr static const std::size_t g1_field_bits = policy_type::base_field_bits;
                        typedef typename policy_type::g1_field_type::value_type g1_field_type_value;
                        typedef typename policy_type::g2_field_type::value_type g2_field_type_value;

                        using underlying_field_value_type = g2_field_type_value;

                        underlying_field_value_type X;
                        underlying_field_value_type Y;
                        underlying_field_value_type Z;

                        /*************************  Constructors and zero/one  ***********************************/

                        /*constexpr static */ const underlying_field_value_type x =
                            underlying_field_value_type(0x00, 0x00);    //?
                        /*constexpr static */ const underlying_field_value_type y =
                            underlying_field_value_type(0x00, 0x00);    //?

                        element_mnt4_g2() :
                            element_mnt4_g2(underlying_field_value_type::zero(), underlying_field_value_type::one(),
                                            underlying_field_value_type::zero()) {};
                        // must be
                        // element_mnt4_g2() : element_mnt4_g2(zero_fill[0], zero_fill[1], zero_fill[2]) {};
                        // when constexpr fields will be finished

                        element_mnt4_g2(underlying_field_value_type X,
                                        underlying_field_value_type Y,
                                        underlying_field_value_type Z) {
                            this->X = X;
                            this->Y = Y;
                            this->Z = Z;
                        };

                        static element_mnt4_g2 zero() {
                            return element_mnt4_g2();
                        }

                        static element_mnt4_g2 one() {
                            return element_mnt4_g2(
                                underlying_field_value_type(
                                    0x371780491C5660571FF542F2EF89001F205151E12A72CB14F01A931E72DBA7903DF6C09A9A4_cppui298,
                                    0x4BA59A3F72DA165DEF838081AF697C851F002F576303302BB6C02C712C968BE32C0AE0A989_cppui295),
                                underlying_field_value_type(
                                    0x4B471F33FFAAD868A1C47D6605D31E5C4B3B2E0B60EC98F0F610A5AAFD0D9522BCA4E79F22_cppui295,
                                    0x355D05A1C69A5031F3F81A5C100CB7D982F78EC9CFC3B5168ED8D75C7C484FB61A3CBF0E0F1_cppui298),
                                underlying_field_value_type::one());
                            // must be
                            // return element_mnt4_g2(one_fill[0], one_fill[1], one_fill[2]);
                            // when constexpr fields will be finished
                        }

                        /*************************  Comparison operations  ***********************************/

                        bool operator==(const element_mnt4_g2 &other) const {
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

                        bool operator!=(const element_mnt4_g2 &other) const {
                            return !(operator==(other));
                        }

                        bool is_zero() const {
                            return (this->X.is_zero() && this->Z.is_zero());
                        }

                        bool is_special() const {
                            return (this->is_zero() || this->Z == underlying_field_value_type::one());
                        }

                        /*************************  Arithmetic operations  ***********************************/

                        element_mnt4_g2 operator=(const element_mnt4_g2 &other) {
                            // handle special cases having to do with O
                            this->X = other.X;
                            this->Y = other.Y;
                            this->Z = other.Z;

                            return *this;
                        }

                        element_mnt4_g2 operator+(const element_mnt4_g2 &other) const {
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

                        element_mnt4_g2 operator-() const {
                            return element_mnt4_g2(this->X, -this->Y, this->Z);
                        }

                        element_mnt4_g2 operator-(const element_mnt4_g2 &other) const {
                            return (*this) + (-other);
                        }

                        element_mnt4_g2 doubled() const {
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
                                const underlying_field_value_type h = w.squared() - B.doubled();    // h   = w^2 - 2*B
                                const underlying_field_value_type X3 = h * s;                       // X3  = h*s
                                const underlying_field_value_type Y3 =
                                    w * (B - h) - RR.doubled();                // Y3  = w*(B-h) - 2*RR
                                const underlying_field_value_type Z3 = sss;    // Z3  = sss

                                return element_mnt4_g2(X3, Y3, Z3);
                            }
                        }

                        element_mnt4_g2 mixed_add(const element_mnt4_g2 &other) const {
                            // NOTE: does not handle O and pts of order 2,4
                            // http://www.hyperelliptic.org/EFD/g1p/auto-shortw-projective.html#addition-add-1998-cmo-2

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

                            const underlying_field_value_type u = Y2Z1 - this->Y;    // u = Y2*Z1-Y1
                            const underlying_field_value_type uu = u.squared();      // uu = u2
                            const underlying_field_value_type v = X2Z1 - this->X;    // v = X2*Z1-X1
                            const underlying_field_value_type vv = v.squared();      // vv = v2
                            const underlying_field_value_type vvv = v * vv;          // vvv = v*vv
                            const underlying_field_value_type R = vv * this->X;      // R = vv*X1
                            const underlying_field_value_type A =
                                uu * this->Z - vvv - R.doubled();            // A = uu*Z1-vvv-2*R
                            const underlying_field_value_type X3 = v * A;    // X3 = v*A
                            const underlying_field_value_type Y3 =
                                u * (R - A) - vvv * this->Y;                         // Y3 = u*(R-A)-vvv*Y1
                            const underlying_field_value_type Z3 = vvv * this->Z;    // Z3 = vvv*Z1

                            return element_mnt4_g2(X3, Y3, Z3);
                        }

                    private:
                        element_mnt4_g2 add(const element_mnt4_g2 &other) const {

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

                            return element_mnt4_g2(X3, Y3, Z3);
                        }

                    public:
                        /*************************  Reducing operations  ***********************************/

                        element_mnt4_g2 to_affine_coordinates() const {
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

                            return element_mnt4_g2(p_out[0], p_out[1], p_out[2]);
                        }

                        element_mnt4_g2 to_special() const {
                            return this->to_affine_coordinates();
                        }

                        /*constexpr static */ const g1_field_type_value g1_a = g1_field_type_value(policy_type::a);
                        /*constexpr static */ const g1_field_type_value g1_b = g1_field_type_value(policy_type::b);

                        /*constexpr static */ const g2_field_type_value twist =
                            g2_field_type_value({g2_field_type_value::underlying_type::zero(),
                                                 g2_field_type_value::underlying_type::one()});

                        /*constexpr static */ const underlying_field_value_type a =
                            underlying_field_value_type(g1_a * twist.non_residue, g1_field_type_value::zero());
                        // must be
                        // underlying_field_value_type(g1_a * underlying_field_value_type::non_residue, 0);
                        // when constexpr fields will be finished

                        /*constexpr static */ const underlying_field_value_type b =
                            underlying_field_value_type(g1_field_type_value::zero(), g1_b *twist.non_residue);
                        // must be
                        // underlying_field_value_type(0, g1_b * underlying_field_value_type::non_residue);
                        // when constexpr fields will be finished

                        /*constexpr static */ const g2_field_type_value twist_coeff_a = a;
                        /*constexpr static */ const g2_field_type_value twist_coeff_b = b;

                    private:
                        /*constexpr static */ const g1_field_type_value twist_mul_by_a_c0 =
                            g1_a * twist.non_residue;    // we must receive non_residue in a better way, when constexpr
                                                         // fields will be finished
                        /*constexpr static */ const g1_field_type_value twist_mul_by_a_c1 =
                            g1_a * twist.non_residue;    // we must receive non_residue in a better way, when constexpr
                                                         // fields will be finished
                        /*constexpr static */ const g1_field_type_value twist_mul_by_b_c0 =
                            g1_b * twist.non_residue.squared();    // we must receive non_residue in a better way, when
                                                                   // constexpr fields will be finished
                        /*constexpr static */ const g1_field_type_value twist_mul_by_b_c1 =
                            g1_b * twist.non_residue;    // we must receive non_residue in a better way, when constexpr
                                                         // fields will be finished
                        /*constexpr static */ const g1_field_type_value twist_mul_by_q_X = g1_field_type_value(
                            0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298);
                        /*constexpr static */ const g1_field_type_value twist_mul_by_q_Y = g1_field_type_value(
                            0xF73779FE09916DFDCC2FD1F968D534BEB17DAF7518CD9FAE5C1F7BDCF94DD5D7DEF6980C4_cppui292);

                        /*constexpr static const underlying_field_value_type zero_fill = {
                            underlying_field_value_type::zero(), underlying_field_value_type::one(),
                            underlying_field_value_type::zero()};

                        constexpr static const underlying_field_value_type one_fill = {
                            underlying_field_value_type(
                                0x371780491C5660571FF542F2EF89001F205151E12A72CB14F01A931E72DBA7903DF6C09A9A4_cppui298,
                                0x4BA59A3F72DA165DEF838081AF697C851F002F576303302BB6C02C712C968BE32C0AE0A989_cppui295),
                            underlying_field_value_type(
                                0x4B471F33FFAAD868A1C47D6605D31E5C4B3B2E0B60EC98F0F610A5AAFD0D9522BCA4E79F22_cppui295,
                                0x355D05A1C69A5031F3F81A5C100CB7D982F78EC9CFC3B5168ED8D75C7C484FB61A3CBF0E0F1_cppui298),
                            underlying_field_value_type::one()};*/
                    };

                    template<std::size_t ModulusBits, std::size_t GeneratorBits, typename NumberType>
                    element_mnt4_g2<ModulusBits, GeneratorBits> operator*(const element_mnt4_g2<ModulusBits, GeneratorBits> &left, 
                        const NumberType &right) {

                        return scalar_mul(left, right);
                    }

                    template<std::size_t ModulusBits, std::size_t GeneratorBits, typename NumberType>
                    element_mnt4_g2<ModulusBits, GeneratorBits> operator*(const NumberType &left,
                        const element_mnt4_g2<ModulusBits, GeneratorBits> &right) {

                        return right * left;
                    }

                    template<std::size_t ModulusBits, std::size_t GeneratorBits, typename FieldType, typename = 
                        typename std::enable_if<::nil::crypto3::algebra::detail::is_fp_field<FieldType>::value>::type>
                    element_mnt4_g2<ModulusBits, GeneratorBits> operator*(const element_mnt4_g2<ModulusBits, GeneratorBits> &left, 
                        const typename FieldType::value_type &right) {

                        return left * right.data;
                    }

                    template<std::size_t ModulusBits, std::size_t GeneratorBits, typename FieldType, typename = 
                        typename std::enable_if<::nil::crypto3::algebra::detail::is_fp_field<FieldType>::value>::type>
                    element_mnt4_g2<ModulusBits, GeneratorBits> operator*(const typename FieldType::value_type &left, 
                        const element_mnt4_g2<ModulusBits, GeneratorBits> &right) {

                        return right * left;
                    }

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_MNT4_G2_ELEMENT_HPP
