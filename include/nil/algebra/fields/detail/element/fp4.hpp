//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_ELEMENT_FP4_HPP
#define ALGEBRA_FIELDS_ELEMENT_FP4_HPP

#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<typename FieldParams>
                class element_fp4 {
                    typedef FieldParams policy_type;

                public:

                    /*constexpr static*/ const typename policy_type::non_residue_type non_residue =
                        typename policy_type::non_residue_type(policy_type::non_residue);

                    using underlying_type = typename policy_type::underlying_type;

                    using value_type = std::array<underlying_type, 2>;

                    value_type data;

                    element_fp4() {
                        data = value_type({underlying_type::zero(), underlying_type::zero()});
                    }

                    element_fp4(underlying_type in_data0, underlying_type in_data1) {
                        data = value_type({in_data0, in_data1});
                    }

                    element_fp4(const element_fp4 &other) {
                        data[0] = underlying_type(other.data[0]);
                        data[1] = underlying_type(other.data[1]);
                    };

                    inline static element_fp4 zero() {
                        return element_fp4(underlying_type::zero(), underlying_type::zero());
                    }

                    inline static element_fp4 one() {
                        return element_fp4(underlying_type::one(), underlying_type::zero());
                    }

                    bool operator==(const element_fp4 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                    }

                    bool operator!=(const element_fp4 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                    }

                    element_fp4 &operator=(const element_fp4 &B) {
                        data[0] = B.data[0];
                        data[1] = B.data[1];

                        return *this;
                    }

                    element_fp4 operator+(const element_fp4 &B) const {
                        return element_fp4(data[0] + B.data[0], data[1] + B.data[1]);
                    }

                    element_fp4 doubled() const {
                        return element_fp4(data[0].doubled(), data[1].doubled());
                    }

                    element_fp4 operator-(const element_fp4 &B) const {
                        return element_fp4(data[0] - B.data[0], data[1] - B.data[1]);
                    }

                    element_fp4 &operator-=(const element_fp4 &B) {
                        data[0] -= B.data[0];
                        data[1] -= B.data[1];

                        return *this;
                    }

                    element_fp4 &operator+=(const element_fp4 &B) {
                        data[0] += B.data[0];
                        data[1] += B.data[1];

                        return *this;
                    }

                    element_fp4 operator-() const {
                        return zero() - *this;
                    }

                    element_fp4 operator*(const element_fp4 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                        return element_fp4(A0B0 + mul_by_non_residue(A1B1),
                                            (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1);
                    }

                    element_fp4 sqrt() const {

                        // compute squared root with Tonelli--Shanks
                    }

                    element_fp4 squared() const {
                        return (*this) * (*this);    // maybe can be done more effective
                    }

                    template<typename PowerType>
                    element_fp4 pow(const PowerType &pwr) const {
                        return element_fp4(power(*this, pwr));
                    }

                    element_fp4 inversed() const {

                        /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig
                         * Curves"; Algorithm 8 */

                        const underlying_type &A0 = data[0], &A1 = data[1];

                        const underlying_type t0 = A0.squared();
                        const underlying_type t1 = A1.squared();
                        const underlying_type t2 = t0 - mul_by_non_residue(t1);
                        const underlying_type t3 = t2.inversed();
                        const underlying_type c0 = A0 * t3;
                        const underlying_type c1 = -(A1 * t3);

                        return element_fp4(c0, c1);
                    }

                    template<typename PowerType>
                    element_fp4 Frobenius_map(const PowerType &pwr) const {
                        return element_fp4(data[0].Frobenius_map(pwr),
                                            typename policy_type::non_residue_type(policy_type::Frobenius_coeffs_c1[pwr % 4]) * data[1].Frobenius_map(pwr));
                        //return element_fp4(data[0].Frobenius_map(pwr),
                        //                    policy_type::Frobenius_coeffs_c1[pwr % 4] * data[1].Frobenius_map(pwr)});
                    }

                    element_fp4  unitary_inversed() const {
                        return element_fp4(data[0], -data[1]);
                    }

                    element_fp4  cyclotomic_squared() const {
                        const underlying_type A = data[1].squared();
                        const underlying_type B = data[0] + data[1];
                        const underlying_type C = B.squared() - A;
                        const underlying_type D = mul_by_non_residue(A); // Fp2(A.c1 * non_residue, A.c0)
                        const underlying_type E = C - D;
                        const underlying_type F = D + D + underlying_type::one();
                        const underlying_type G = E - underlying_type::one();

                        return element_fp4 (F, G);
                    }

                    template<typename PowerType>
                    element_fp4 cyclotomic_exp(const PowerType &exponent) const {
                        /*element_fp4  res = this->one();
                        element_fp4  this_inverse = this->unitary_inversed();

                        bool found_nonzero = false;
                        std::vector<long> NAF = find_wnaf(1, exponent);

                        for (long i = static_cast<long>(NAF.size() - 1); i >= 0; --i) {
                            if (found_nonzero) {
                                res = res.cyclotomic_squared();
                            }

                            if (NAF[i] != 0) {
                                found_nonzero = true;

                                if (NAF[i] > 0) {
                                    res = res * (*this);
                                }
                                else {
                                    res = res * this_inverse;
                                }
                            }
                        }

                        return res;*/

                        return *this;
                    }

                    /*inline static*/ underlying_type mul_by_non_residue(const underlying_type &A) const {
                        return underlying_type(non_residue * A.data[1], A.data[0]);
                    }

                    element_fp4 mul_by_023(const element_fp4 &other) const {
                        /* Devegili OhEig Scott Dahab --- Multiplication and Squaring on Pairing-Friendly Fields.pdf; Section 3 (Karatsuba) */
                        assert(other.data[0].data[1].is_zero());

                        const underlying_type &A = other.data[0], &B = other.data[1], 
                            &a = this->data[0], &b = this->data[1];
                        const underlying_type aA = underlying_type(a.data[0] * A.data[0], a.data[1] * A.data[0]);
                        const underlying_type bB = b*B;

                        const underlying_type beta_bB = element_fp4::mul_by_non_residue(bB);
                        return element_fp4(aA + beta_bB,
                                                    (a+b)*(A+B) - aA  - bB);
                    }
                };

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP4_HPP
