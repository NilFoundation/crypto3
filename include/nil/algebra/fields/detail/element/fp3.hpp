//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_ELEMENT_FP3_HPP
#define ALGEBRA_FIELDS_ELEMENT_FP3_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<typename FieldParams>
                struct element_fp3 {
                private:
                    typedef FieldParams policy_type;

                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                public:

                    /*constexpr static*/ typename policy_type::non_residue_type non_residue =
                        typename policy_type::non_residue_type(policy_type::non_residue);

                    using underlying_type = typename policy_type::underlying_type;

                    using value_type = std::array<underlying_type, 3>;

                    value_type data;

                    element_fp3() {
                        data = {underlying_type::zero(), underlying_type::zero(), underlying_type::zero()};
                    }

                    element_fp3(value_type in_data) {
                        data = value_type(in_data);
                    }

                    element_fp3(modulus_type in_data0, modulus_type in_data1, modulus_type in_data2) {
                        data = value_type(
                            {underlying_type(in_data0), underlying_type(in_data1), underlying_type(in_data2)});
                    }

                    element_fp3(const element_fp3 &other) {
                        data[0] = underlying_type(other.data[0]);
                        data[1] = underlying_type(other.data[1]);
                        data[2] = underlying_type(other.data[2]);
                    };

                    inline static element_fp3 zero() {
                        return element_fp3({underlying_type::zero(), underlying_type::zero(), underlying_type::zero()});
                    }

                    inline static element_fp3 one() {
                        return element_fp3({underlying_type::one(), underlying_type::zero(), underlying_type::zero()});
                    }

                    bool is_zero() const {
                        return (data[0] == underlying_type::zero()) && (data[1] == underlying_type::zero()) &&
                               (data[2] == underlying_type::zero());
                    }

                    bool is_one() const {
                        return (data[0] == underlying_type::one()) && (data[1] == underlying_type::zero()) &&
                               (data[2] == underlying_type::zero());
                    }

                    bool operator==(const element_fp3 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]) && (data[2] == B.data[2]);
                    }

                    bool operator!=(const element_fp3 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]) || (data[2] != B.data[2]);
                    }

                    element_fp3 &operator=(const element_fp3 &B) {
                        data[0] = B.data[0];
                        data[1] = B.data[1];
                        data[2] = B.data[2];

                        return *this;
                    }

                    element_fp3 operator+(const element_fp3 &B) const {
                        return element_fp3({data[0] + B.data[0], data[1] + B.data[1], data[2] + B.data[2]});
                    }

                    element_fp3 doubled() const {
                        return element_fp3({data[0].doubled(), data[1].doubled(), data[2].doubled()});
                    }

                    element_fp3 operator-(const element_fp3 &B) const {
                        return element_fp3({data[0] - B.data[0], data[1] - B.data[1], data[2] - B.data[2]});
                    }

                    element_fp3 &operator-=(const element_fp3 &B) {
                        data[0] -= B.data[0];
                        data[1] -= B.data[1];

                        return *this;
                    }

                    element_fp3 &operator+=(const element_fp3 &B) {
                        data[0] += B.data[0];
                        data[1] += B.data[1];

                        return *this;
                    }

                    element_fp3 operator-() const {
                        return zero() - *this;
                    }

                    element_fp3 operator*(const element_fp3 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1],
                                              A2B2 = data[2] * B.data[2];

                        return element_fp3(
                            {A0B0 + non_residue * ((data[1] + data[2]) * (B.data[1] + B.data[2]) - A1B1 - A2B2),
                             (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1 + non_residue * A2B2,
                             (data[0] + data[2]) * (B.data[0] + B.data[2]) - A0B0 + A1B1 - A2B2});
                    }

                    element_fp3 sqrt() const {

                        element_fp3 one = this->one();

                        size_t v = policy_type::s;
                        element_fp3 z(policy_type::nqr_to_t[0], policy_type::nqr_to_t[1], policy_type::nqr_to_t[2]);
                        element_fp3 w = this->pow(policy_type::t_minus_1_over_2);
                        element_fp3 x((*this) * w);
                        element_fp3 b = x * w;    // b = (*this)^t

                        // compute square root with Tonelli--Shanks
                        // (does not terminate if not a square!)

                        while (b != one) {
                            size_t m = 0;
                            element_fp3 b2m = b;
                            while (b2m != one) {
                                /* invariant: b2m = b^(2^m) after entering this loop */
                                b2m = b2m.squared();
                                m += 1;
                            }

                            int j = v - m - 1;
                            w = z;
                            while (j > 0) {
                                w = w.squared();
                                --j;
                            }    // w = z^2^(v-m-1)

                            z = w.squared();
                            b = b * z;
                            x = x * w;
                            v = m;
                        }

                        return x;
                    }

                    element_fp3 squared() const {
                        return (*this) * (*this);    // maybe can be done more effective
                    }

                    template<typename PowerType>
                    element_fp3 pow(const PowerType &pwr) const {
                        return element_fp3(power(*this, pwr));
                    }

                    element_fp3 inversed() const {

                        /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig
                         * Curves"; Algorithm 17 */

                        const underlying_type &A0 = data[0], &A1 = data[1], &A2 = data[2];

                        const underlying_type t0 = A0.squared();
                        const underlying_type t1 = A1.squared();
                        const underlying_type t2 = A2.squared();
                        const underlying_type t3 = A0 * A1;
                        const underlying_type t4 = A0 * A2;
                        const underlying_type t5 = A1 * A2;
                        const underlying_type c0 = t0 - non_residue * t5;
                        const underlying_type c1 = non_residue * t2 - t3;
                        const underlying_type c2 =
                            t1 - t4;    // typo in paper referenced above. should be "-" as per Scott, but is "*"
                        const underlying_type t6 = (A0 * c0 + non_residue * (A2 * c1 + A1 * c2)).inversed();
                        return element_fp3({t6 * c0, t6 * c1, t6 * c2});
                    }

                    template<typename PowerType>
                    element_fp3 Frobenius_map(const PowerType &pwr) const {
                        return element_fp3({data[0], 
                                            non_residue_type(policy_type::Frobenius_coeffs_c1[pwr % 3]) * data[1],
                                            non_residue_type(policy_type::Frobenius_coeffs_c2[pwr % 3]) * data[2]});
                        //return element_fp3({data[0], 
                        //                    policy_type::Frobenius_coeffs_c1[pwr % 3] * data[1],
                        //                    policy_type::Frobenius_coeffs_c2[pwr % 3] * data[2]});
                    }

                };

                template<typename FieldParams>
                element_fp3<FieldParams> operator*(const typename FieldParams::underlying_type &lhs,
                                                   const element_fp3<FieldParams> &rhs) {
                    return element_fp3<FieldParams>({lhs * rhs.data[0], lhs * rhs.data[1], lhs * rhs.data[2]});
                }

                template<typename FieldParams>
                element_fp3<FieldParams> operator*(const element_fp3<FieldParams> &lhs,
                                                   const typename FieldParams::underlying_type &rhs) {
                    return rhs * lhs;
                }

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP3_HPP
