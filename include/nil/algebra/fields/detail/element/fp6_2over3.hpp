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

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp3.hpp>
#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<typename FieldParams>
                struct element_fp6_2over3{
                private:
                    typedef FieldParams policy_type;
                public:
                    static const typename policy_type::fp6_2over3_non_residue_type 
                        non_residue = policy_type::fp6_2over3_non_residue_type(policy_type::fp6_2over3_non_residue);

                    using underlying_type = element_fp3<FieldParams>;

                    using value_type = std::array<underlying_type, 2>;

                    value_type data;

                    element_fp6_2over3(value_type data) : data(data) {};

                    inline static element_fp6_2over3 zero() {
                        return {underlying_type::zero(), underlying_type::zero()};
                    }

                    inline static element_fp6_2over3 one() {
                        return {underlying_type::one(), underlying_type::zero()};
                    }

                    bool operator==(const element_fp6_2over3 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                    }

                    bool operator!=(const element_fp6_2over3 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                    }

                    element_fp6_2over3 operator+(const element_fp6_2over3 &B) const {
                        return {data[0] + B.data[0], data[1] + B.data[1]};
                    }

                    element_fp6_2over3 operator-(const element_fp6_2over3 &B) const {
                        return {data[0] - B.data[0], data[1] - B.data[1]};
                    }

                    element_fp6_2over3 operator-() const {
                        return zero()-data;
                    }

                    element_fp6_2over3 operator*(const element_fp6_2over3 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                        return {A0B0 + mul_by_non_residue(A1B1), (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1};
                    }

                    element_fp6_2over3 sqrt() const {

                        // compute square root with Tonelli--Shanks
                    }

                    element_fp6_2over3 square() const {
                        return data*data;    // maybe can be done more effective
                    }

                    template <typename PowerType>
                    element_fp6_2over3 pow(const PowerType &power) const {
                        return power(data, power);
                    }

                    element_fp6_2over3 inverse() const {

                        /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves";
                         * Algorithm 8 */

                        const underlying_type &A0 = data[0], &A1 = data[1];
                        
                        const underlying_type t0 = A0.square();
                        const underlying_type t1 = A1.square();
                        const underlying_type t2 = t0 - mul_by_non_residue(t1);
                        const underlying_type t3 = t2.inverse();
                        const underlying_type c0 = A0 * t3;
                        const underlying_type c1 = -(A1 * t3);

                        return {c0, c1};

                    }

                private:
                    inline static underlying_type mul_by_non_residue(const underlying_type &A){
                        return {non_residue * A.data[2], A.data[1], A.data[0]};
                    }
                };
                
            }   // namespace detail
        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP6_2OVER3_HPP
