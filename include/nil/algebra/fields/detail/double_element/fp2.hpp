//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_FP2_DOUBLE_HPP
#define ALGEBRA_FF_FP2_DOUBLE_HPP

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/algebra/fields/fp.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct double_element<fp2<ModulusBits, GeneratorBits>> {

                typedef arithmetic_params<fp2<ModulusBits, GeneratorBits>> params_type;

                typedef params_type::double_number_type number_type;

            private:
                using value_type = double_element<fp2<ModulusBits, GeneratorBits>>;

                number_type data;

            public:

                value_type(type data) : data(data);

                inline static value_type zero() const {
                    return {underlying_type::zero(), underlying_type::zero()};
                }

                inline static value_type one() const {
                    return {underlying_type::one(), underlying_type::zero()};
                }

                bool is_zero() const {
                    return (data[0] == underlying_type::zero()) && (data[1] == underlying_type::zero());
                }

                bool is_one() const {
                    return (data[0] == underlying_type::one()) && (data[1] == underlying_type::zero());
                }

                bool operator==(const value_type &B) const {
                    return (data[0] == B.data[0]) && (data[1] == B.data[1]);
                }

                bool operator!=(const value_type &B) const {
                    return (data[0] != B.data[0]) || (data[1] != B.data[1]);
                }

                value_type operator+(const value_type &B) const {
                    return {data[0] + B.data[0], data[1] + B.data[1]};
                }

                value_type operator-(const value_type &B) const {
                    return {data[0] - B.data[0], data[1] - B.data[1]};
                }

                value_type operator-() const {
                    return zero()-data;
                }

                value_type operator*(const value_type &B) const {
                    
                }

                //data + data
                value_type dbl() const {
                    return {data[0].dbl(), data[1].dbl()};
                }

                value_type addNC(const value_type &B){
                    return {addNC(data[0] + B.data[0]), addNC(data[1] + B.data[1])};
                }

                value_type subNC(const value_type &B){
                    return {subNC(data[0] + B.data[0]), subNC(data[1] + B.data[1])};
                }

                value_type subOpt1() const {
                    return {mod(data[0]), mod(data[1])};
                }

                value_type square() const {
                    return data * data;    // maybe can be done more effective
                }

                /*
                    XITAG
                    u^2 = -1
                    xi = 9 + u
                    (a + bu)(9 + u) = (9a - b) + (a + 9b)u
                */
                value_type mul_xi() {
                    return {data[0].dbl().dbl().dbl() + data[0] - data[1], data[1].dbl().dbl().dbl() + data[1] + data[0]};
                }

            };
        }    // namespace detail
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_FP2_DOUBLE_HPP
