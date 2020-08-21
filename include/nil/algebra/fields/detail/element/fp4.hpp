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

#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<typename FieldParams>
                struct element_fp4{
                private:
                    typedef FieldParams policy_type;
                public:
                    static const typename policy_type::fp4_non_residue_type 
                        non_residue = policy_type::fp4_non_residue_type(policy_type::fp4_non_residue);

                    using underlying_type = element_fp2<FieldParams>;

                    using value_type = std::array<underlying_type, 2>;

                    value_type data;

                    element_fp4(value_type data) : data(data) {};

                    inline static element_fp4 zero() {
                        return element_fp4({underlying_type::zero(), underlying_type::zero()});
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

                    element_fp4& operator=(const element_fp4 &B) {
                        data[0] = B.data[0];
                        data[1] = B.data[1];

                        return *this;
                    }

                    element_fp4 operator+(const element_fp4 &B) const {
                        return element_fp4({data[0] + B.data[0], data[1] + B.data[1]});
                    }

                    element_fp4 operator-(const element_fp4 &B) const {
                        return element_fp4({data[0] - B.data[0], data[1] - B.data[1]});
                    }

                    element_fp4& operator-=(const element_fp4 &B) {
                        data[0] -= B.data[0];
                        data[1] -= B.data[1];

                        return *this;
                    }

                    element_fp4& operator+=(const element_fp4 &B) {
                        data[0] += B.data[0];
                        data[1] += B.data[1];

                        return *this;
                    }

                    element_fp4 operator-() const {
                        return zero() - *this;
                    }
                    
                    element_fp4 operator*(const element_fp4 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                        return element_fp4({A0B0 +  mul_by_non_residue(A1B1), (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1});
                    }

                    element_fp4 sqrt() const {

                        // compute square root with Tonelli--Shanks
                    }

                    element_fp4 square() const {
                        return (*this) * (*this);    // maybe can be done more effective
                    }

                    template <typename PowerType>
                    element_fp4 pow(const PowerType &power) const {
                        return element_fp4(power(*this, pwr));
                    }

                    element_fp4 inverse() const {

                        /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves";
                         * Algorithm 8 */

                        const underlying_type &A0 = data[0], &A1 = data[1];
                        
                        const underlying_type t0 = A0.square();
                        const underlying_type t1 = A1.square();
                        const underlying_type t2 = t0 - mul_by_non_residue(t1);
                        const underlying_type t3 = t2.inverse();
                        const underlying_type c0 = A0 * t3;
                        const underlying_type c1 = -(A1 * t3);

                        return element_fp4({c0, c1});

                    }

                private:
                    inline static underlying_type mul_by_non_residue(const underlying_type &A){
                        return element_fp4({non_residue * A.data[1], A.data[0]});
                    }

                };

            }   // namespace detail
        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP4_HPP
