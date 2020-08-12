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

#include <nil/algebra/fields/detail/element.hpp>
#include <nil/algebra/fields/detail/element/fp.hpp>

#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/fields/detail/exponentiation.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {


                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct element_fp2 : public element<fp2<ModulusBits, GeneratorBits>> {

                    using underlying_type = element_fp<ModulusBits, GeneratorBits>;

                    using value_type = std::array<underlying_type, 2>;

                    value_type data;

                    element_fp2(value_type data) : data(data);

                    inline static element_fp2 zero() const {
                        return {underlying_type::zero(), underlying_type::zero()};
                    }

                    inline static element_fp2 one() const {
                        return {underlying_type::one(), underlying_type::zero()};
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

                    element_fp2 operator+(const element_fp2 &B) const {
                        return {data[0] + B.data[0], data[1] + B.data[1]};
                    }

                    element_fp2 operator-(const element_fp2 &B) const {
                        return {data[0] - B.data[0], data[1] - B.data[1]};
                    }

                    element_fp2 operator-() const {
                        return zero() - data;
                    }

                    element_fp2 operator*(const element_fp2 &B) const {
                        const underlying_type A0B0 = data[0] * B.data[0], A1B1 = data[1] * B.data[1];

                        return {A0B0 + non_residue * A1B1, (data[0] + data[1]) * (B.data[0] + B.data[1]) - A0B0 - A1B1};
                    }

                    /*
                        For pairing bn128
                        XITAG
                        u^2 = -1
                        xi = 9 + u
                        (a + bu)(9 + u) = (9a - b) + (a + 9b)u
                    */
                    element_fp2 mul_xi() {
                        return {data[0].dbl().dbl().dbl() + data[0] - data[1], data[1].dbl().dbl().dbl() + data[1] + data[0]};
                    }

                    /*
                    u^2 = -1
                    (a + b)u = -b + au

                    1 * Fp neg
                    */
                    element_fp2 mul_x() {
                        return {- data[1], data[0]};
                    }

                    // z = x * b
                    element_fp2 mul_Fp_0(const underlying_type &b) {
                        return {data[0] * b, data[1] * b};
                    }

                    /*
                        (a + bu)cu = -bc + acu,
                        where u is u^2 = -1.

                        2 * Fp mul
                        1 * Fp neg
                    */
                    element_fp2 mul_Fp_1(const underlying_type &y_b) {
                        return {-(data[1] * y_b), data[0] * y_b};
                    }

                    element_fp2 _2z_add_3x() {
                        return {data[0]._2z_add_3x(), data[1]._2z_add_3x()};
                    }

                    element_fp2 divBy2() const {
                        return {divBy2(data[0]), divBy2(data[1])};
                    }

                    element_fp2 divBy4() const {
                        return {divBy4(data[0]), divBy4(data[1])};
                    }

                    element_fp2 dbl() const {
                        return {data[0].dbl(), data[1].dbl()};
                    }

                    element_fp2 sqrt() const {

                        // compute square root with Tonelli--Shanks
                    }

                    element_fp2 square() const {
                        return data * data;    // maybe can be done more effective
                    }

                    template<typename PowerType>
                    element_fp2 pow(const PowerType &power) const {
                        return detail::power(data, power);
                    }

                    element_fp2 inverse() const {

                        /* From "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves";
                         * Algorithm 8 */

                        const underlying_type &A0 = data[0], &A1 = data[1];

                        const underlying_type t0 = A0.square();
                        const underlying_type t1 = A1.square();
                        const underlying_type t2 = t0 - non_residue * t1;
                        const underlying_type t3 = t2.inverse();
                        const underlying_type c0 = A0 * t3;
                        const underlying_type c1 = -(A1 * t3);

                        return {c0, c1};
                    }


                };

                element_fp2 addNC(const element_fp2 &A, const element_fp2 &B) {
                }

                element_fp2 subNC(const element_fp2 &A, const element_fp2 &B) {
                }
                
            }   // namespace detail
        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_FP2_HPP
