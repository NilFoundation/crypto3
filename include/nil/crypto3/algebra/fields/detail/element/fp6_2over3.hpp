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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP6_2OVER3_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP6_2OVER3_HPP

#include <nil/crypto3/algebra/fields/detail/exponentiation.hpp>

#include <nil/crypto3/multiprecision/wnaf.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<typename FieldParams>
                    class element_fp6_2over3 {
                        typedef FieldParams policy_type;

                    public:
                        typedef typename policy_type::non_residue_type non_residue_type;
                        constexpr static const non_residue_type non_residue = policy_type::non_residue;

                        typedef typename policy_type::underlying_type underlying_type;

                        using data_type = std::array<underlying_type, 2>;

                        data_type data;

                        constexpr element_fp6_2over3() {
                            data = data_type({underlying_type::zero(), underlying_type::zero()});
                        }

                        constexpr element_fp6_2over3(underlying_type in_data0, underlying_type in_data1) {
                            data = data_type({in_data0, in_data1});
                        }

                        constexpr element_fp6_2over3(const data_type &in_data) {
                            data = data_type({in_data[0], in_data[1]});
                        };

                        constexpr element_fp6_2over3(const element_fp6_2over3 &B) : data {B.data} {};

                        constexpr inline static element_fp6_2over3 zero() {
                            return element_fp6_2over3(underlying_type::zero(), underlying_type::zero());
                        }

                        constexpr inline static element_fp6_2over3 one() {
                            return element_fp6_2over3(underlying_type::one(), underlying_type::zero());
                        }

                        constexpr bool operator==(const element_fp6_2over3 &B) const {
                            return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                        }

                        constexpr bool operator!=(const element_fp6_2over3 &B) const {
                            return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                        }

                        constexpr element_fp6_2over3 &operator=(const element_fp6_2over3 &B) {
                            data[0] = B.data[0];
                            data[1] = B.data[1];

                            return *this;
                        }

                        constexpr element_fp6_2over3 operator+(const element_fp6_2over3 &B) const {
                            return element_fp6_2over3(data[0] + B.data[0], data[1] + B.data[1]);
                        }

                        constexpr element_fp6_2over3 doubled() const {
                            return element_fp6_2over3(data[0].doubled(), data[1].doubled());
                        }

                        constexpr element_fp6_2over3 operator-(const element_fp6_2over3 &B) const {
                            return element_fp6_2over3(data[0] - B.data[0], data[1] - B.data[1]);
                        }

                        constexpr element_fp6_2over3 &operator-=(const element_fp6_2over3 &B) {
                            data[0] -= B.data[0];
                            data[1] -= B.data[1];

                            return *this;
                        }

                        constexpr element_fp6_2over3 &operator+=(const element_fp6_2over3 &B) {
                            data[0] += B.data[0];
                            data[1] += B.data[1];

                            return *this;
                        }

                        constexpr element_fp6_2over3 operator-() const {
                            return zero() - *this;
                        }

                        constexpr element_fp6_2over3 operator*(const element_fp6_2over3 &B) const {
                            const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                            return element_fp6_2over3(A0B0 + mul_by_non_residue(A1B1),
                                                      (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1);
                        }

                        element_fp6_2over3 sqrt() const {

                            // compute squared root with Tonelli--Shanks
                        }

                        constexpr element_fp6_2over3 squared() const {
                            // return (*this) * (*this);    // maybe can be done more effective

                            /* Devegili OhEig Scott Dahab --- Multiplication and Squaring on Pairing-Friendly
                             * Fields.pdf; Section 3 (Complex) */
                            const underlying_type &B = data[1], &A = data[0];
                            const underlying_type AB = A * B;

                            return element_fp6_2over3(
                                (A + B) * (A + mul_by_non_residue(B)) - AB - mul_by_non_residue(AB), AB + AB);
                        }

                        template<typename PowerType>
                        constexpr element_fp6_2over3 pow(const PowerType &pwr) const {
                            return element_fp6_2over3(power(*this, pwr));
                        }

                        constexpr element_fp6_2over3 inversed() const {

                            /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig
                             * Curves"; Algorithm 8 */

                            const underlying_type &A0 = data[0], &A1 = data[1];

                            const underlying_type t0 = A0.squared();
                            const underlying_type t1 = A1.squared();
                            const underlying_type t2 = t0 - mul_by_non_residue(t1);
                            const underlying_type t3 = t2.inversed();
                            const underlying_type c0 = A0 * t3;
                            const underlying_type c1 = -(A1 * t3);

                            return element_fp6_2over3(c0, c1);
                        }

                        template<typename PowerType>
                        constexpr element_fp6_2over3 Frobenius_map(const PowerType &pwr) const {
                            // return element_fp6_2over3(data[0].Frobenius_map(pwr),
                            //                           policy_type::Frobenius_coeffs_c1[pwr % 6] *
                            //                           data[1].Frobenius_map(pwr)});
                            return element_fp6_2over3(
                                data[0].Frobenius_map(pwr),
                                typename policy_type::non_residue_type(policy_type::Frobenius_coeffs_c1[pwr % 6]) *
                                    data[1].Frobenius_map(pwr));
                        }

                        constexpr element_fp6_2over3 unitary_inversed() const {
                            return element_fp6_2over3(data[0], -data[1]);
                        }

                        element_fp6_2over3 cyclotomic_squared() const {
                            using e_fp = typename underlying_type::underlying_type;
                            using e_fp2 = std::array<e_fp, 2>;

                            auto fp2_squared = [&](const e_fp &A, const e_fp &B) {
                                /* Devegili OhEig Scott Dahab --- Multiplication and Squaring on Pairing-Friendly
                                 * Fields.pdf; Section 3 (Complex squaring) */
                                const e_fp AB = A * B;

                                return e_fp2 {(A + B) * (A + non_residue * B) - AB - non_residue * AB, AB + AB};
                            };

                            // e_fp2 a(data[0].data[0], data[1].data[1]);
                            // e_fp2 b(data[1].data[0], data[0].data[2]);
                            // e_fp2 c(data[0].data[1], data[1].data[2]);
                            //
                            // e_fp2 asq = a.squared();
                            // e_fp2 bsq = b.squared();
                            // e_fp2 csq = c.squared();
                            e_fp2 asq = fp2_squared(data[0].data[0], data[1].data[1]);
                            e_fp2 bsq = fp2_squared(data[1].data[0], data[0].data[2]);
                            e_fp2 csq = fp2_squared(data[0].data[1], data[1].data[2]);

                            // A = vector(3*a^2 - 2*Fp2([vector(a)[0],-vector(a)[1]]))
                            // my_Fp A_a = my_Fp(3l) * asq_a - my_Fp(2l) * a_a;
                            e_fp A_a = asq[0] - data[0].data[0];
                            A_a = A_a + A_a + asq[0];
                            // my_Fp A_b = my_Fp(3l) * asq_b + my_Fp(2l) * a_b;
                            e_fp A_b = asq[1] + data[1].data[1];
                            A_b = A_b + A_b + asq[1];

                            // B = vector(3*Fp2([non_residue*c2[1],c2[0]]) + 2*Fp2([vector(b)[0],-vector(b)[1]]))
                            // my_Fp B_a = my_Fp(3l) * underlying_type::non_residue * csq_b + my_Fp(2l) * b_a;
                            e_fp B_tmp = non_residue * csq[1];
                            e_fp B_a = B_tmp + data[1].data[0];
                            B_a = B_a + B_a + B_tmp;

                            // my_Fp B_b = my_Fp(3l) * csq_a - my_Fp(2l) * b_b;
                            e_fp B_b = csq[0] - data[0].data[2];
                            B_b = B_b + B_b + csq[0];

                            // C = vector(3*b^2 - 2*Fp2([vector(c)[0],-vector(c)[1]]))
                            // my_Fp C_a = my_Fp(3l) * bsq_a - my_Fp(2l) * c_a;
                            e_fp C_a = bsq[0] - data[0].data[1];
                            C_a = C_a + C_a + bsq[0];
                            // my_Fp C_b = my_Fp(3l) * bsq_b + my_Fp(2l) * c_b;
                            e_fp C_b = bsq[1] + data[1].data[2];
                            C_b = C_b + C_b + bsq[1];

                            return element_fp6_2over3(underlying_type(A_a, C_a, B_b), underlying_type(B_a, A_b, C_b));
                        }

                        template<typename PowerType>
                        element_fp6_2over3 cyclotomic_exp(const PowerType &exponent) const {
                            // naive implementation
                            // return this->squared();

                            element_fp6_2over3 res = one();
                            element_fp6_2over3 this_inverse = this->unitary_inversed();

                            bool found_nonzero = false;
                            std::vector<long> NAF = nil::crypto3::multiprecision::find_wnaf(1, exponent);

                            for (long i = static_cast<long>(NAF.size() - 1); i >= 0; --i) {
                                if (found_nonzero) {
                                    res = res.cyclotomic_squared();
                                }

                                if (NAF[i] != 0) {
                                    found_nonzero = true;

                                    if (NAF[i] > 0) {
                                        res = res * (*this);
                                    } else {
                                        res = res * this_inverse;
                                    }
                                }
                            }

                            return res;
                        }

                        constexpr /*inline static*/ underlying_type mul_by_non_residue(const underlying_type &A) const {
                            return underlying_type(non_residue * A.data[2], A.data[0], A.data[1]);
                        }

                        element_fp6_2over3 mul_by_2345(const element_fp6_2over3 &other) const {
                            /* Devegili OhEig Scott Dahab --- Multiplication and Squaring on Pairing-Friendly
                             * Fields.pdf; Section 3 (Karatsuba) */

                            const underlying_type &B = other.data[1], &A = other.data[0], &b = this->data[1],
                                                  &a = this->data[0];
                            const underlying_type aA = underlying_type(a.data[1] * A.data[2] * non_residue,
                                                                       a.data[2] * A.data[2] * non_residue,
                                                                       a.data[0] * A.data[2]);
                            const underlying_type bB = b * B;
                            const underlying_type beta_bB = element_fp6_2over3::mul_by_non_residue(bB);

                            return element_fp6_2over3(aA + beta_bB, (a + b) * (A + B) - aA - bB);
                        }
                    };

                    template<typename FieldParams>
                    constexpr element_fp6_2over3<FieldParams>
                        operator*(const typename FieldParams::underlying_type::underlying_type &lhs,
                                  const element_fp6_2over3<FieldParams> &rhs) {

                        return element_fp6_2over3<FieldParams>(lhs * rhs.data[0], lhs * rhs.data[1]);
                    }

                    template<typename FieldParams>
                    constexpr element_fp6_2over3<FieldParams>
                        operator*(const element_fp6_2over3<FieldParams> &lhs,
                                  const typename FieldParams::underlying_type::underlying_type &rhs) {

                        return rhs * lhs;
                    }

                    template<typename FieldParams>
                    constexpr const typename element_fp6_2over3<FieldParams>::non_residue_type
                        element_fp6_2over3<FieldParams>::non_residue;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_ELEMENT_FP6_2OVER3_HPP
