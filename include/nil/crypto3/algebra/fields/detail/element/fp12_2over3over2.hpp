//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP

#include <nil/crypto3/algebra/fields/detail/exponentiation.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<typename FieldParams>
                    class element_fp12_2over3over2 {
                        typedef FieldParams policy_type;

                    public:
                        typedef typename policy_type::non_residue_type non_residue_type;
                        constexpr static const non_residue_type non_residue = policy_type::non_residue;

                        typedef typename policy_type::underlying_type underlying_type;

                        using data_type = std::array<underlying_type, 2>;

                        data_type data;

                        element_fp12_2over3over2() {
                            data = data_type({underlying_type::zero(), underlying_type::zero()});
                        }

                        element_fp12_2over3over2(underlying_type in_data0, underlying_type in_data1) {
                            data = data_type({in_data0, in_data1});
                        }

                        element_fp12_2over3over2(const data_type &in_data) {
                            data = data_type({in_data[0], in_data[1]});
                        };

                        element_fp12_2over3over2(const element_fp12_2over3over2 &B) : data {B.data} {};

                        inline static element_fp12_2over3over2 zero() {
                            return element_fp12_2over3over2(underlying_type::zero(), underlying_type::zero());
                        }

                        inline static element_fp12_2over3over2 one() {
                            return element_fp12_2over3over2(underlying_type::one(), underlying_type::zero());
                        }

                        bool operator==(const element_fp12_2over3over2 &B) const {
                            return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                        }

                        bool operator!=(const element_fp12_2over3over2 &B) const {
                            return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                        }

                        element_fp12_2over3over2 &operator=(const element_fp12_2over3over2 &B) {
                            data[0] = B.data[0];
                            data[1] = B.data[1];

                            return *this;
                        }

                        element_fp12_2over3over2 operator+(const element_fp12_2over3over2 &B) const {
                            return element_fp12_2over3over2(data[0] + B.data[0], data[1] + B.data[1]);
                        }

                        element_fp12_2over3over2 doubled() const {
                            return element_fp12_2over3over2(data[0].doubled(), data[1].doubled());
                        }

                        element_fp12_2over3over2 operator-(const element_fp12_2over3over2 &B) const {
                            return element_fp12_2over3over2(data[0] - B.data[0], data[1] - B.data[1]);
                        }

                        element_fp12_2over3over2 &operator-=(const element_fp12_2over3over2 &B) {
                            data[0] -= B.data[0];
                            data[1] -= B.data[1];

                            return *this;
                        }

                        element_fp12_2over3over2 &operator+=(const element_fp12_2over3over2 &B) {
                            data[0] += B.data[0];
                            data[1] += B.data[1];

                            return *this;
                        }

                        element_fp12_2over3over2 operator-() const {
                            return zero() - *this;
                        }

                        element_fp12_2over3over2 operator*(const element_fp12_2over3over2 &B) const {
                            const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                            return element_fp12_2over3over2(A0B0 + mul_by_non_residue(A1B1),
                                                            (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 -
                                                                A1B1);
                        }

                        element_fp12_2over3over2 sqrt() const {

                            // compute squared root with Tonelli--Shanks
                        }

                        element_fp12_2over3over2 squared() const {

                            return (*this) * (*this);    // maybe can be done more effective
                        }

                        template<typename PowerType>
                        element_fp12_2over3over2 pow(const PowerType &pwr) const {
                            return element_fp12_2over3over2(power(*this, pwr));
                        }

                        element_fp12_2over3over2 inversed() const {

                            /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig
                             * Curves"; Algorithm 8 */

                            const underlying_type &A0 = data[0], &A1 = data[1];

                            const underlying_type t0 = A0.squared();
                            const underlying_type t1 = A1.squared();
                            const underlying_type t2 = t0 - mul_by_non_residue(t1);
                            const underlying_type t3 = t2.inversed();
                            const underlying_type c0 = A0 * t3;
                            const underlying_type c1 = -(A1 * t3);

                            return element_fp12_2over3over2(c0, c1);
                        }

                        template<typename PowerType>
                        element_fp12_2over3over2 Frobenius_map(const PowerType &pwr) const {
                            // return element_fp12_2over3over2(data[0].Frobenius_map(pwr),
                            //                                 policy_type::Frobenius_coeffs_c1[pwr % 12] *
                            //                                 data[1].Frobenius_map(pwr)});
                            return element_fp12_2over3over2(data[0].Frobenius_map(pwr),
                                                            typename policy_type::non_residue_type(
                                                                policy_type::Frobenius_coeffs_c1[(pwr % 12) * 2],
                                                                policy_type::Frobenius_coeffs_c1[(pwr % 12) * 2 + 1]) *
                                                                data[1].Frobenius_map(pwr));
                        }

                        element_fp12_2over3over2 unitary_inversed() const {
                            return element_fp12_2over3over2(data[0], -data[1]);
                        }

                        element_fp12_2over3over2 cyclotomic_squared() const {
                            // naive implementation
                            // return this->squared();

                            typename underlying_type::underlying_type z0 = data[0].data[0];
                            typename underlying_type::underlying_type z4 = data[0].data[1];
                            typename underlying_type::underlying_type z3 = data[0].data[2];

                            typename underlying_type::underlying_type z2 = data[1].data[0];
                            typename underlying_type::underlying_type z1 = data[1].data[1];
                            typename underlying_type::underlying_type z5 = data[1].data[2];

                            typename underlying_type::underlying_type t0, t1, t2, t3, t4, t5, tmp;

                            // t0 + t1*y = (z0 + z1*y)^2 = a^2
                            tmp = z0 * z1;
                            t0 = (z0 + z1) * (z0 + underlying_type::non_residue * z1) - tmp -
                                 underlying_type::non_residue * tmp;
                            t1 = tmp + tmp;
                            // t2 + t3*y = (z2 + z3*y)^2 = b^2
                            tmp = z2 * z3;
                            t2 = (z2 + z3) * (z2 + underlying_type::non_residue * z3) - tmp -
                                 underlying_type::non_residue * tmp;
                            t3 = tmp + tmp;
                            // t4 + t5*y = (z4 + z5*y)^2 = c^2
                            tmp = z4 * z5;
                            t4 = (z4 + z5) * (z4 + underlying_type::non_residue * z5) - tmp -
                                 underlying_type::non_residue * tmp;
                            t5 = tmp + tmp;

                            // for A

                            // z0 = 3 * t0 - 2 * z0
                            z0 = t0 - z0;
                            z0 = z0 + z0;
                            z0 = z0 + t0;
                            // z1 = 3 * t1 + 2 * z1
                            z1 = t1 + z1;
                            z1 = z1 + z1;
                            z1 = z1 + t1;

                            // for B

                            // z2 = 3 * (xi * t5) + 2 * z2
                            tmp = underlying_type::non_residue * t5;
                            z2 = tmp + z2;
                            z2 = z2 + z2;
                            z2 = z2 + tmp;

                            // z3 = 3 * t4 - 2 * z3
                            z3 = t4 - z3;
                            z3 = z3 + z3;
                            z3 = z3 + t4;

                            // for C

                            // z4 = 3 * t2 - 2 * z4
                            z4 = t2 - z4;
                            z4 = z4 + z4;
                            z4 = z4 + t2;

                            // z5 = 3 * t3 + 2 * z5
                            z5 = t3 + z5;
                            z5 = z5 + z5;
                            z5 = z5 + t3;

                            return element_fp12_2over3over2(underlying_type(z0, z4, z3), underlying_type(z2, z1, z5));
                        }

                        template<typename PowerType>
                        element_fp12_2over3over2 cyclotomic_exp(const PowerType &exponent) const {
                            element_fp12_2over3over2 res = one();

                            if (exponent == 0)
                                return res;

                            bool found_one = false;
                            for (long i = nil::crypto3::multiprecision::msb(exponent); i >= 0; --i) {
                                if (found_one) {
                                    res = res.cyclotomic_squared();
                                }

                                if (nil::crypto3::multiprecision::bit_test(exponent, i)) {
                                    found_one = true;
                                    res = res * (*this);
                                }
                            }

                            return res;
                            // return *this;
                        }

                        element_fp12_2over3over2
                            mul_by_045(const typename underlying_type::underlying_type &ell_0,
                                       const typename underlying_type::underlying_type &ell_VW,
                                       const typename underlying_type::underlying_type &ell_VV) const {

                            // element_fp12_2over3over2 a(
                            //     underlying_type(ell_VW, underlying_type::underlying_type::zero(),
                            //                     underlying_type::underlying_type::zero()),
                            //     underlying_type(underlying_type::underlying_type::zero(), ell_0, ell_VV));
                            //
                            // return (*this) * a;

                            typename underlying_type::underlying_type z0 = this->data[0].data[0];
                            typename underlying_type::underlying_type z1 = this->data[0].data[1];
                            typename underlying_type::underlying_type z2 = this->data[0].data[2];
                            typename underlying_type::underlying_type z3 = this->data[1].data[0];
                            typename underlying_type::underlying_type z4 = this->data[1].data[1];
                            typename underlying_type::underlying_type z5 = this->data[1].data[2];

                            typename underlying_type::underlying_type x0 = ell_VW;
                            typename underlying_type::underlying_type x4 = ell_0;
                            typename underlying_type::underlying_type x5 = ell_VV;

                            typename underlying_type::underlying_type t0, t1, t2, t3, t4, t5;
                            typename underlying_type::underlying_type tmp1, tmp2;

                            // TODO: non_residue should be used as static
                            tmp1 = element_fp12_2over3over2().non_residue * x4;
                            tmp2 = element_fp12_2over3over2().non_residue * x5;

                            t0 = x0 * z0 + tmp1 * z4 + tmp2 * z3;
                            t1 = x0 * z1 + tmp1 * z5 + tmp2 * z4;
                            t2 = x0 * z2 + x4 * z3 + tmp2 * z5;
                            t3 = x0 * z3 + tmp1 * z2 + tmp2 * z1;
                            t4 = x0 * z4 + x4 * z0 + tmp2 * z2;
                            t5 = x0 * z5 + x4 * z1 + x5 * z0;

                            return element_fp12_2over3over2(underlying_type(t0, t1, t2), underlying_type(t3, t4, t5));
                        }

                        element_fp12_2over3over2
                            mul_by_024(const typename underlying_type::underlying_type &ell_0,
                                       const typename underlying_type::underlying_type &ell_VW,
                                       const typename underlying_type::underlying_type &ell_VV) const {
                            element_fp12_2over3over2 a(
                                underlying_type(ell_0, underlying_type::underlying_type::zero(), ell_VV),
                                underlying_type(underlying_type::underlying_type::zero(), ell_VW,
                                                underlying_type::underlying_type::zero()));

                            return (*this) * a;
                        }

                        /*element_fp12_2over3over2 sqru() {
                            element_fp2<FieldParams> &z0(a_.a_);
                            element_fp2<FieldParams> &z4(a_.b_);
                            element_fp2<FieldParams> &z3(a_.c_);
                            element_fp2<FieldParams> &z2(b_.a_);
                            element_fp2<FieldParams> &z1(b_.b_);
                            element_fp2<FieldParams> &z5(b_.c_);
                            element_fp4<FieldParams> t0t1;
                            element_fp2<FieldParams> t0 = t0t1.data[0], t1 = t0t1.data[1];

                            t0t1 = sq_Fp4UseDbl({z0, z1});    // a^2 = t0 + t1*y
                            // For A
                            z0 = t0 - z0;
                            z0 += z0;
                            z0 += t0;

                            z1 = (t1 + z1).doubled() + t1;

                            // t0 and t1 are unnecessary from here.
                            element_fp2 t2, t3;
                            t0t1 = sq_Fp4UseDbl({z2, z3});    // b^2 = t0 + t1*y
                            t0t1 = sq_Fp4UseDbl({z4, z5});    // c^2 = t2 + t3*y
                            // For C
                            z4 = (t0 - z4).doubled() + t0;

                            z5 = (t1 + z5).doubled() + t1;

                            // For B
                            t0 = t3.mul_xi();

                            z2 = (t0 + z2).doubled() + t0;

                            z3 = (t2 - z3).doubled() + t2;
                        }*/

                        /*inline static*/ underlying_type mul_by_non_residue(const underlying_type &A) const {
                            return underlying_type(non_residue * A.data[2], A.data[0], A.data[1]);
                        }
                    };

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams>
                        operator*(const typename FieldParams::underlying_type::underlying_type::underlying_type &lhs,
                                  const element_fp12_2over3over2<FieldParams> &rhs) {

                        return element_fp12_2over3over2<FieldParams>(lhs * rhs.data[0], lhs * rhs.data[1]);
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams>
                        operator*(const element_fp12_2over3over2<FieldParams> &lhs,
                                  const typename FieldParams::underlying_type::underlying_type::underlying_type &rhs) {

                        return rhs * lhs;
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams>
                        operator*(const typename FieldParams::underlying_type::underlying_type &lhs,
                                  const element_fp12_2over3over2<FieldParams> &rhs) {

                        return element_fp12_2over3over2<FieldParams>(lhs * rhs.data[0], lhs * rhs.data[1]);
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams>
                        operator*(const element_fp12_2over3over2<FieldParams> &lhs,
                                  const typename FieldParams::underlying_type::underlying_type &rhs) {

                        return rhs * lhs;
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams> operator*(const typename FieldParams::underlying_type &lhs,
                                                                    const element_fp12_2over3over2<FieldParams> &rhs) {

                        return element_fp12_2over3over2<FieldParams>(lhs * rhs.data[0], lhs * rhs.data[1]);
                    }

                    template<typename FieldParams>
                    element_fp12_2over3over2<FieldParams> operator*(const element_fp12_2over3over2<FieldParams> &lhs,
                                                                    const typename FieldParams::underlying_type &rhs) {

                        return rhs * lhs;
                    }

                    /*
                        (a + bw) -> (a - bw) gammar
                    */
                    /*template <typename FieldParams>
                    element_fp12_2over3over2<FieldParams> Frobenius(element_fp12_2over3over2<FieldParams> A) {
                        // this assumes (q-1)/6 is odd

                        z.a_.a_.a_ = A.a_.a_.a_;
                        z.a_.b_.a_ = A.a_.b_.a_;
                        z.a_.c_.a_ = A.a_.c_.a_;
                        z.b_.a_.a_ = A.b_.a_.a_;
                        z.b_.b_.a_ = A.b_.b_.a_;
                        z.b_.c_.a_ = A.b_.c_.a_;

                        z.a_.a_.b_ = -A.a_.a_.b_;
                        z.a_.b_.b_ = -A.a_.b_.b_;
                        z.a_.c_.b_ = -A.a_.c_.b_;
                        z.b_.a_.b_ = -A.b_.a_.b_;
                        z.b_.b_.b_ = -A.b_.b_.b_;
                        z.b_.c_.b_ = -A.b_.c_.b_;

                        z.a_.b_ *= Param::gammar[1];
                        z.a_.c_ *= Param::gammar[3];

                        z.b_.a_ *= Param::gammar[0];
                        z.b_.b_ *= Param::gammar[2];
                        z.b_.c_ *= Param::gammar[4];
                    }*/

                    /*
                        gammar = c + dw
                        a + bw -> t = (a - bw)(c + dw)
                        ~t = (a + bw)(c - dw)
                        ~t * (c + dw) = (a + bw) * ((c + dw)(c - dw))
                        gammar2 = (c + dw)(c - dw) in Fp6
                    */
                    /*template <typename FieldParams>
                    element_fp12_2over3over2<FieldParams> Frobenius2(element_fp12_2over3over2<FieldParams> A) {

                        z.a_.a_ = A.a_.a_;

                        z.a_.a_ = A.a_.a_;
                        z.a_.b_ = A.a_.b_.mul_Fp_0(Param::gammar2[1].a_);
                        z.a_.c_ = A.a_.c_.mul_Fp_0(Param::gammar2[3].a_);
                        z.b_.a_ = A.b_.a_.mul_Fp_0(Param::gammar2[0].a_);
                        z.b_.b_ = A.b_.b_.mul_Fp_0(Param::gammar2[2].a_);
                        z.b_.c_ = A.b_.c_.mul_Fp_0(Param::gammar2[4].a_);
                    }

                    template <typename FieldParams>
                    element_fp12_2over3over2<FieldParams> Frobenius3(element_fp12_2over3over2<FieldParams> A) {
                        z.a_.a_.a_ = A.a_.a_.a_;
                        z.a_.b_.a_ = A.a_.b_.a_;
                        z.a_.c_.a_ = A.a_.c_.a_;
                        z.b_.a_.a_ = A.b_.a_.a_;
                        z.b_.b_.a_ = A.b_.b_.a_;
                        z.b_.c_.a_ = A.b_.c_.a_;

                        z.a_.a_.b_ = -A.a_.a_.b_;
                        z.a_.b_.b_ = -A.a_.b_.b_;
                        z.a_.c_.b_ = -A.a_.c_.b_;
                        z.b_.a_.b_ = -A.b_.a_.b_;
                        z.b_.b_.b_ = -A.b_.b_.b_;
                        z.b_.c_.b_ = -A.b_.c_.b_;

                        z.a_.b_ *= Param::gammar3[1];
                        z.a_.c_ *= Param::gammar3[3];

                        z.b_.a_ *= Param::gammar3[0];
                        z.b_.b_ *= Param::gammar3[2];
                        z.b_.c_ *= Param::gammar3[4];
                    }*/

                    template<typename FieldParams>
                    constexpr const typename element_fp12_2over3over2<FieldParams>::non_residue_type
                        element_fp12_2over3over2<FieldParams>::non_residue;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP12_2OVER3OVER2_HPP
