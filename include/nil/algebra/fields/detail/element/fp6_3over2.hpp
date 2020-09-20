//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_ELEMENT_FP6_3OVER2_HPP
#define ALGEBRA_FIELDS_ELEMENT_FP6_3OVER2_HPP

#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<typename FieldParams>
                struct element_fp6_3over2 {
                private:
                    typedef FieldParams policy_type;

                public:
                    /*constexpr static*/ const typename policy_type::non_residue_type non_residue =
                        policy_type::non_residue_type(policy_type::non_residue);

                    using underlying_type = typename policy_type::underlying_type;

                    using value_type = std::array<underlying_type, 3>;

                    value_type data;

                    element_fp6_3over2(value_type data) : data(data) {};

                    inline static element_fp6_3over2 zero() {
                        return element_fp6_3over2(
                            {underlying_type::zero(), underlying_type::zero(), underlying_type::zero()});
                    }

                    inline static element_fp6_3over2 one() {
                        return element_fp6_3over2(
                            {underlying_type::one(), underlying_type::zero(), underlying_type::zero()});
                    }

                    bool operator==(const element_fp6_3over2 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]) && (data[2] == B.data[2]);
                    }

                    bool operator!=(const element_fp6_3over2 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]) || (data[2] != B.data[2]);
                    }

                    element_fp6_3over2 &operator=(const element_fp6_3over2 &B) {
                        data[0] = B.data[0];
                        data[1] = B.data[1];
                        data[2] = B.data[2];

                        return *this;
                    }

                    element_fp6_3over2 operator+(const element_fp6_3over2 &B) const {
                        return element_fp6_3over2({data[0] + B.data[0], data[1] + B.data[1], data[2] + B.data[2]});
                    }

                    element_fp6_3over2 doubled() const {
                        return element_fp6_3over2({data[0].doubled(), data[1].doubled(), data[2].doubled()});
                    }

                    element_fp6_3over2 operator-(const element_fp6_3over2 &B) const {
                        return element_fp6_3over2({data[0] - B.data[0], data[1] - B.data[1], data[2] - B.data[2]});
                    }

                    element_fp6_3over2 &operator-=(const element_fp6_3over2 &B) {
                        data[0] -= B.data[0];
                        data[1] -= B.data[1];
                        data[2] -= B.data[2];

                        return *this;
                    }

                    element_fp6_3over2 &operator+=(const element_fp6_3over2 &B) {
                        data[0] += B.data[0];
                        data[1] += B.data[1];
                        data[2] += B.data[2];

                        return *this;
                    }

                    element_fp6_3over2 operator-() const {
                        return zero() - *this;
                    }

                    element_fp6_3over2 operator*(const element_fp6_3over2 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1],
                                              A2B2 = data[2] * B.data[2];

                        return element_fp6_3over2(
                            {A0B0 + mul_by_non_residue((data[1] + data[2]) * (B.data[1] + B.data[2]) - A1B1 - A2B2),
                             (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1 + mul_by_non_residue(A2B2),
                             (data[0] + data[2]) * (B.data[0] + B.data[2]) - A0B0 + A1B1 - A2B2});
                    }

                    element_fp6_3over2 sqrt() const {

                        // compute squared root with Tonelli--Shanks
                    }

                    element_fp6_3over2 mul_Fp_b(const element_fp<FieldParams> &B) {
                        return element_fp6_3over2({data[0], data[1].mul_Fp_0(B), data[2]});
                    }

                    element_fp6_3over2 mul_Fp_c(const element_fp<FieldParams> &B) {
                        return element_fp6_3over2({data[0], data[1], data[2].mul_Fp_0(B)});
                    }

                    element_fp6_3over2 mulFp6_24_Fp_01(const element_fp<FieldParams> *B) {
                        return element_fp6_3over2({data[0], data[1].mul_Fp_0(B[1]), data[2].mul_Fp_0(B[0])});
                    }

                    element_fp6_3over2 squared() const {
                        return (*this) * (*this);    // maybe can be done more effective
                    }

                    template<typename PowerType>
                    element_fp6_3over2 pow(const PowerType &pwr) const {
                        return element_fp6_3over2(power(*this, pwr));
                    }

                    element_fp6_3over2 inversed() const {

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
                        return element_fp6_3over2({t6 * c0, t6 * c1, t6 * c2});
                    }

                    template<typename PowerType>
                    element_fp6_3over2 Frobenius_map(const PowerType &pwr) const {
                        //return element_fp6_3over2({data[0].Frobenius_map(pwr),
                        //                           policy_type::Frobenius_coeffs_c1[pwr % 6] * data[1].Frobenius_map(pwr),
                        //                           policy_type::Frobenius_coeffs_c2[pwr % 6] * data[2].Frobenius_map(pwr)});
                        return element_fp6_3over2({data[0].Frobenius_map(pwr),
                                                   non_residue_type(policy_type::Frobenius_coeffs_c1[(pwr % 6) * 2], policy_type::Frobenius_coeffs_c1[(pwr % 6) * 2 + 1]) * data[1].Frobenius_map(pwr),
                                                   non_residue_type(policy_type::Frobenius_coeffs_c2[(pwr % 6) * 2], policy_type::Frobenius_coeffs_c2[(pwr % 6) * 2 + 1]) * data[2].Frobenius_map(pwr)});
                    }

                private:
                    /*inline static*/ underlying_type mul_by_non_residue(const underlying_type &A) {
                        return element_fp6_3over2({non_residue * A});
                    }
                };

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP6_3OVER2_HPP
