//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_ELEMENT_FP2_HPP
#define ALGEBRA_FIELDS_ELEMENT_FP2_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<typename FieldParams>
                struct element_fp2 {
                private:
                    typedef FieldParams policy_type;

                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                public:
                    using underlying_type = element_fp<FieldParams>;

                    const typename policy_type::fp2_non_residue_type non_residue =
                        underlying_type(typename policy_type::fp2_non_residue_type(policy_type::fp2_non_residue));

                    using value_type = std::array<underlying_type, 2>;

                    value_type data;

                    element_fp2() {
                        data = {underlying_type::zero(), underlying_type::zero()};
                    }

                    element_fp2(value_type in_data) {
                        data = value_type(in_data);
                    }

                    element_fp2(modulus_type in_data0, modulus_type in_data1) {
                        data = value_type({underlying_type(in_data0), underlying_type(in_data1)});
                    }

                    element_fp2(const element_fp2 &B) {
                        data[0] = underlying_type(B.data[0]);
                        data[1] = underlying_type(B.data[1]);
                    };

                    inline static element_fp2 zero() {
                        return element_fp2({underlying_type::zero(), underlying_type::zero()});
                    }

                    inline static element_fp2 one() {
                        return element_fp2({underlying_type::one(), underlying_type::zero()});
                    }

                    bool is_zero() const {
                        return (data[0] == underlying_type::zero()) && (data[1] == underlying_type::zero());
                    }

                    bool is_one() const {
                        return (data[0] == underlying_type::one()) && (data[1] == underlying_type::zero());
                    }

                    bool operator==(const element_fp2 &B) const {
                        return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                    }

                    bool operator!=(const element_fp2 &B) const {
                        return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                    }

                    element_fp2 &operator=(const element_fp2 &B) {
                        data[0] = B.data[0];
                        data[1] = B.data[1];

                        return *this;
                    }

                    element_fp2 operator+(const element_fp2 &B) const {
                        return element_fp2({data[0] + B.data[0], data[1] + B.data[1]});
                    }

                    element_fp2 operator-(const element_fp2 &B) const {
                        return element_fp2({data[0] - B.data[0], data[1] - B.data[1]});
                    }

                    element_fp2 &operator-=(const element_fp2 &B) {
                        data[0] -= B.data[0];
                        data[1] -= B.data[1];

                        return *this;
                    }

                    element_fp2 &operator+=(const element_fp2 &B) {
                        data[0] += B.data[0];
                        data[1] += B.data[1];

                        return *this;
                    }

                    element_fp2 operator-() const {
                        return zero() - *this;
                    }

                    element_fp2 operator*(const element_fp2 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                        return element_fp2(
                            {A0B0 + non_residue * A1B1, (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1});
                    }

                    /*
                        For pairing bn128
                        XITAG
                        u^2 = -1
                        xi = 9 + u
                        (a + bu)(9 + u) = (9a - b) + (a + 9b)u
                    */
                    element_fp2 mul_xi() {
                        return element_fp2({data[0].doubled().doubled().doubled() + data[0] - data[1],
                                            data[1].doubled().doubled().doubled() + data[1] + data[0]});
                    }

                    /*
                    u^2 = -1
                    (a + b)u = -b + au

                    1 * Fp neg
                    */
                    element_fp2 mul_x() {
                        return element_fp2({-data[1], data[0]});
                    }

                    // z = x * b
                    element_fp2 mul_Fp_0(const underlying_type &b) {
                        return element_fp2({data[0] * b, data[1] * b});
                    }

                    /*
                        (a + bu)cu = -bc + acu,
                        where u is u^2 = -1.

                        2 * Fp mul
                        1 * Fp neg
                    */
                    element_fp2 mul_Fp_1(const underlying_type &y_b) {
                        return element_fp2({-(data[1] * y_b), data[0] * y_b});
                    }

                    element_fp2 _2z_add_3x() {
                        return element_fp2({data[0]._2z_add_3x(), data[1]._2z_add_3x()});
                    }

                    element_fp2 divBy2() const {
                        return element_fp2({divBy2(data[0]), divBy2(data[1])});
                    }

                    element_fp2 divBy4() const {
                        return element_fp2({divBy4(data[0]), divBy4(data[1])});
                    }

                    element_fp2 doubled() const {
                        return element_fp2({data[0].doubled(), data[1].doubled()});
                    }

                    element_fp2 sqrt() const {

                        // compute square root with Tonelli--Shanks
                    }

                    element_fp2 squared() const {
                        return (*this) * (*this);    // maybe can be done more effective
                    }

                    template<typename PowerType>
                    element_fp2 pow(const PowerType &pwr) const {
                        return element_fp2(power(*this, pwr));
                    }

                    element_fp2 inversed() const {

                        /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig
                         * Curves"; Algorithm 8 */

                        const underlying_type &A0 = data[0], &A1 = data[1];

                        const underlying_type t0 = A0.squared();
                        const underlying_type t1 = A1.squared();
                        const underlying_type t2 = t0 - non_residue * t1;
                        const underlying_type t3 = t2.inversed();
                        const underlying_type c0 = A0 * t3;
                        const underlying_type c1 = -(A1 * t3);

                        return element_fp2({c0, c1});
                    }
                };

                template<typename FieldParams>
                element_fp2<FieldParams> addNC(const element_fp2<FieldParams> &A, const element_fp2<FieldParams> &B) {
                }

                template<typename FieldParams>
                element_fp2<FieldParams> subNC(const element_fp2<FieldParams> &A, const element_fp2<FieldParams> &B) {
                }

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP2_HPP
