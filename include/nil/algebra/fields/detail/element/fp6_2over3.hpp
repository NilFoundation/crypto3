//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_ELEMENT_FP6_2OVER3_HPP
#define ALGEBRA_FIELDS_ELEMENT_FP6_2OVER3_HPP

#include <nil/algebra/fields/detail/element/fp3.hpp>
#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<typename FieldParams>
                struct element_fp6_2over3 {
                private:
                    typedef FieldParams policy_type;

                public:
                    /*constexpr static*/ const typename policy_type::non_residue_type non_residue =
                        policy_type::non_residue_type(policy_type::non_residue);

                    using underlying_type = typename policy_type::underlying_type;

                    using value_type = std::array<underlying_type, 2>;

                    value_type data;

                    element_fp6_2over3(value_type data) : data(data) {};

                    inline static element_fp6_2over3 zero() {
                        return element_fp6_2over3({underlying_type::zero(), underlying_type::zero()});
                    }

                    inline static element_fp6_2over3 one() {
                        return element_fp6_2over3({underlying_type::one(), underlying_type::zero()});
                    }

                    bool operator==(const element_fp6_2over3 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                    }

                    bool operator!=(const element_fp6_2over3 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                    }

                    element_fp6_2over3 &operator=(const element_fp6_2over3 &B) {
                        data[0] = B.data[0];
                        data[1] = B.data[1];

                        return *this;
                    }

                    element_fp6_2over3 operator+(const element_fp6_2over3 &B) const {
                        return element_fp6_2over3({data[0] + B.data[0], data[1] + B.data[1]});
                    }

                    element_fp6_2over3 doubled() const {
                        return element_fp6_2over3({data[0].doubled(), data[1].doubled()});
                    }

                    element_fp6_2over3 operator-(const element_fp6_2over3 &B) const {
                        return element_fp6_2over3({data[0] - B.data[0], data[1] - B.data[1]});
                    }

                    element_fp6_2over3 &operator-=(const element_fp6_2over3 &B) {
                        data[0] -= B.data[0];
                        data[1] -= B.data[1];

                        return *this;
                    }

                    element_fp6_2over3 &operator+=(const element_fp6_2over3 &B) {
                        data[0] += B.data[0];
                        data[1] += B.data[1];

                        return *this;
                    }

                    element_fp6_2over3 operator-() const {
                        return zero() - *this;
                    }

                    element_fp6_2over3 operator*(const element_fp6_2over3 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                        return element_fp6_2over3({A0B0 + mul_by_non_residue(A1B1),
                                                   (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1});
                    }

                    element_fp6_2over3 sqrt() const {

                        // compute squared root with Tonelli--Shanks
                    }

                    element_fp6_2over3 squared() const {
                        return (*this) * (*this);    // maybe can be done more effective
                    }

                    template<typename PowerType>
                    element_fp6_2over3 pow(const PowerType &pwr) const {
                        return element_fp6_2over3(power(*this, pwr));
                    }

                    element_fp6_2over3 inversed() const {

                        /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig
                         * Curves"; Algorithm 8 */

                        const underlying_type &A0 = data[0], &A1 = data[1];

                        const underlying_type t0 = A0.squared();
                        const underlying_type t1 = A1.squared();
                        const underlying_type t2 = t0 - mul_by_non_residue(t1);
                        const underlying_type t3 = t2.inversed();
                        const underlying_type c0 = A0 * t3;
                        const underlying_type c1 = -(A1 * t3);

                        return element_fp6_2over3({c0, c1});
                    }

                    template<typename PowerType>
                    element_fp6_2over3 Frobenius_map(const PowerType &pwr) const {
                        //return element_fp6_2over3({data[0].Frobenius_map(pwr),
                        //                           policy_type::Frobenius_coeffs_c1[pwr % 6] * data[1].Frobenius_map(pwr)});
                        return element_fp6_2over3({data[0].Frobenius_map(pwr),
                                                   non_residue_type(policy_type::Frobenius_coeffs_c1[pwr % 6]) * data[1].Frobenius_map(pwr)});
                    }

                private:
                    /*inline static*/ underlying_type mul_by_non_residue(const underlying_type &A) {
                        return element_fp6_2over3({non_residue * A.data[2], A.data[1], A.data[0]});
                    }
                };

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP6_2OVER3_HPP
