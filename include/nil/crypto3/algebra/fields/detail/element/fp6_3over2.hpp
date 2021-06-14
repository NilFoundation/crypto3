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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP6_3OVER2_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP6_3OVER2_HPP

#include <nil/crypto3/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<typename FieldParams>
                    class element_fp6_3over2 {
                        typedef FieldParams policy_type;

                    public:
                        typedef typename policy_type::non_residue_type non_residue_type;
                        constexpr static const non_residue_type non_residue = policy_type::non_residue;

                        typedef typename policy_type::underlying_type underlying_type;

                        using data_type = std::array<underlying_type, 3>;

                        data_type data;

                        constexpr element_fp6_3over2() {
                            data =
                                data_type({underlying_type::zero(), underlying_type::zero(), underlying_type::zero()});
                        }

                        constexpr element_fp6_3over2(underlying_type in_data0,
                                                     underlying_type in_data1,
                                                     underlying_type in_data2) {
                            data = data_type({in_data0, in_data1, in_data2});
                        }

                        constexpr element_fp6_3over2(const data_type &in_data) {
                            data = data_type({in_data[0], in_data[1], in_data[2]});
                        };

                        constexpr element_fp6_3over2(const element_fp6_3over2 &B) : data {B.data} {};

                        constexpr inline static element_fp6_3over2 zero() {
                            return element_fp6_3over2(
                                underlying_type::zero(), underlying_type::zero(), underlying_type::zero());
                        }

                        constexpr inline static element_fp6_3over2 one() {
                            return element_fp6_3over2(
                                underlying_type::one(), underlying_type::zero(), underlying_type::zero());
                        }

                        constexpr bool operator==(const element_fp6_3over2 &B) const {
                            return (data[0] == B.data[0]) && (data[1] == B.data[1]) && (data[2] == B.data[2]);
                        }

                        constexpr bool operator!=(const element_fp6_3over2 &B) const {
                            return (data[0] != B.data[0]) || (data[1] != B.data[1]) || (data[2] != B.data[2]);
                        }

                        constexpr element_fp6_3over2 &operator=(const element_fp6_3over2 &B) {
                            data[0] = B.data[0];
                            data[1] = B.data[1];
                            data[2] = B.data[2];

                            return *this;
                        }

                        constexpr element_fp6_3over2 operator+(const element_fp6_3over2 &B) const {
                            return element_fp6_3over2(data[0] + B.data[0], data[1] + B.data[1], data[2] + B.data[2]);
                        }

                        constexpr element_fp6_3over2 doubled() const {
                            return element_fp6_3over2(data[0].doubled(), data[1].doubled(), data[2].doubled());
                        }

                        constexpr element_fp6_3over2 operator-(const element_fp6_3over2 &B) const {
                            return element_fp6_3over2(data[0] - B.data[0], data[1] - B.data[1], data[2] - B.data[2]);
                        }

                        constexpr element_fp6_3over2 &operator-=(const element_fp6_3over2 &B) {
                            data[0] -= B.data[0];
                            data[1] -= B.data[1];
                            data[2] -= B.data[2];

                            return *this;
                        }

                        constexpr element_fp6_3over2 &operator+=(const element_fp6_3over2 &B) {
                            data[0] += B.data[0];
                            data[1] += B.data[1];
                            data[2] += B.data[2];

                            return *this;
                        }

                        constexpr element_fp6_3over2 operator-() const {
                            return zero() - *this;
                        }

                        constexpr element_fp6_3over2 operator*(const element_fp6_3over2 &B) const {
                            const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1],
                                                  A2B2 = data[2] * B.data[2];

                            return element_fp6_3over2(
                                A0B0 + mul_by_non_residue((data[1] + data[2]) * (B.data[1] + B.data[2]) - A1B1 - A2B2),
                                (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1 + mul_by_non_residue(A2B2),
                                (data[0] + data[2]) * (B.data[0] + B.data[2]) - A0B0 + A1B1 - A2B2);
                        }

                        element_fp6_3over2 sqrt() const {

                            // compute squared root with Tonelli--Shanks
                        }

                        element_fp6_3over2 mul_Fp_b(const element_fp<FieldParams> &B) {
                            return element_fp6_3over2(data[0], data[1].mul_Fp_0(B), data[2]);
                        }

                        element_fp6_3over2 mul_Fp_c(const element_fp<FieldParams> &B) {
                            return element_fp6_3over2(data[0], data[1], data[2].mul_Fp_0(B));
                        }

                        element_fp6_3over2 mulFp6_24_Fp_01(const element_fp<FieldParams> *B) {
                            return element_fp6_3over2(data[0], data[1].mul_Fp_0(B[1]), data[2].mul_Fp_0(B[0]));
                        }

                        constexpr element_fp6_3over2 squared() const {
                            return (*this) * (*this);    // maybe can be done more effective
                        }

                        template<typename PowerType>
                        constexpr element_fp6_3over2 pow(const PowerType &pwr) const {
                            return element_fp6_3over2(power(*this, pwr));
                        }

                        constexpr element_fp6_3over2 inversed() const {

                            /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig
                             * Curves"; Algorithm 17 */

                            const underlying_type &A0 = data[0], &A1 = data[1], &A2 = data[2];

                            const underlying_type t0 = A0.squared();
                            const underlying_type t1 = A1.squared();
                            const underlying_type t2 = A2.squared();
                            const underlying_type t3 = A0 * A1;
                            const underlying_type t4 = A0 * A2;
                            const underlying_type t5 = A1 * A2;
                            const underlying_type c0 = t0 - mul_by_non_residue(t5);
                            const underlying_type c1 = mul_by_non_residue(t2) - t3;
                            const underlying_type c2 =
                                t1 - t4;    // typo in paper referenced above. should be "-" as per Scott, but is "*"
                            const underlying_type t6 = (A0 * c0 + mul_by_non_residue(A2 * c1 + A1 * c2)).inversed();
                            return element_fp6_3over2(t6 * c0, t6 * c1, t6 * c2);
                        }

                        template<typename PowerType>
                        constexpr element_fp6_3over2 Frobenius_map(const PowerType &pwr) const {
                            // return element_fp6_3over2(data[0].Frobenius_map(pwr),
                            //                           policy_type::Frobenius_coeffs_c1[pwr % 6] *
                            //                           data[1].Frobenius_map(pwr),
                            //                           policy_type::Frobenius_coeffs_c2[pwr % 6] *
                            //                           data[2].Frobenius_map(pwr)});
                            return element_fp6_3over2(data[0].Frobenius_map(pwr),
                                                      typename policy_type::non_residue_type(
                                                          policy_type::Frobenius_coeffs_c1[(pwr % 6) * 2],
                                                          policy_type::Frobenius_coeffs_c1[(pwr % 6) * 2 + 1]) *
                                                          data[1].Frobenius_map(pwr),
                                                      typename policy_type::non_residue_type(
                                                          policy_type::Frobenius_coeffs_c2[(pwr % 6) * 2],
                                                          policy_type::Frobenius_coeffs_c2[(pwr % 6) * 2 + 1]) *
                                                          data[2].Frobenius_map(pwr));
                        }

                        constexpr /*inline static*/ underlying_type mul_by_non_residue(const underlying_type &A) const {
                            return underlying_type(non_residue * A);
                        }
                    };

                    template<typename FieldParams>
                    constexpr element_fp6_3over2<FieldParams>
                        operator*(const typename FieldParams::underlying_type::underlying_type &lhs,
                                  const element_fp6_3over2<FieldParams> &rhs) {

                        return element_fp6_3over2<FieldParams>(lhs * rhs.data[0], lhs * rhs.data[1], lhs * rhs.data[2]);
                    }

                    template<typename FieldParams>
                    constexpr element_fp6_3over2<FieldParams>
                        operator*(const element_fp6_3over2<FieldParams> &lhs,
                                  const typename FieldParams::underlying_type::underlying_type &rhs) {

                        return rhs * lhs;
                    }

                    template<typename FieldParams>
                    constexpr element_fp6_3over2<FieldParams>
                        operator*(const typename FieldParams::underlying_type &lhs,
                                  const element_fp6_3over2<FieldParams> &rhs) {

                        return element_fp6_3over2<FieldParams>(lhs * rhs.data[0], lhs * rhs.data[1], lhs * rhs.data[2]);
                    }

                    template<typename FieldParams>
                    constexpr element_fp6_3over2<FieldParams>
                        operator*(const element_fp6_3over2<FieldParams> &lhs,
                                  const typename FieldParams::underlying_type &rhs) {

                        return rhs * lhs;
                    }

                    template<typename FieldParams>
                    constexpr const typename element_fp6_3over2<FieldParams>::non_residue_type
                        element_fp6_3over2<FieldParams>::non_residue;
                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP6_3OVER2_HPP
