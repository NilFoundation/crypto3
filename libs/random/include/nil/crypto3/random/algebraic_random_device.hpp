//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_RANDOM_ALGEBRAIC_RANDOM_DEVICE_HPP
#define CRYPTO3_RANDOM_ALGEBRAIC_RANDOM_DEVICE_HPP

#include <type_traits>

#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace random {
            /*!
             * @brief
             * @tparam AlgebraicType denote an some algebraic type (field, curve group types).
             *
             * algebraic_random_device is adapter wrapping boost::random_device producing random values of algebraic
             * type.
             *
             * The class template algebraic_random_device models a \UniformRandomBitGenerator.
             * https://en.cppreference.com/w/cpp/named_req/UniformRandomBitGenerator
             */
            template<typename AlgebraicType, typename = void>
            struct algebraic_random_device;

            template<typename AlgebraicType>
            struct algebraic_random_device<
                AlgebraicType, typename std::enable_if<algebra::is_field<AlgebraicType>::value &&
                                                       !algebra::is_extended_field<AlgebraicType>::value>::type> {
            protected:
                typedef AlgebraicType field_type;
                typedef typename field_type::value_type field_value_type;
                typedef typename field_type::integral_type integral_type;

                constexpr static integral_type _min = 0;
                constexpr static integral_type _max = field_type::modulus - 1;

            public:
                typedef boost::random_device internal_generator_type;
                typedef boost::random::uniform_int_distribution<integral_type> internal_distribution_type;
                typedef field_value_type result_type;

                /** Returns a random value in the range [min, max]. */
                result_type operator()() {
                    return dist(gen);
                }

                /** Returns the smallest value that the \algebraic_random_device can produce. */
                constexpr static inline result_type min() {
                    constexpr result_type min_value(_min);
                    return min_value;
                }

                /** Returns the largest value that the \algebraic_random_device can produce. */
                constexpr static inline result_type max() {
                    constexpr result_type max_value(_max);
                    return max_value;
                }

            protected:
                internal_generator_type gen;
                internal_distribution_type dist = internal_distribution_type(_min, _max);
            };

            template<typename AlgebraicType>
            struct algebraic_random_device<
                AlgebraicType, typename std::enable_if<algebra::is_field<AlgebraicType>::value &&
                                                       algebra::is_extended_field<AlgebraicType>::value>::type> {
            protected:
                typedef AlgebraicType extended_field_type;
                typedef typename extended_field_type::value_type extended_field_value_type;
                typedef typename extended_field_type::underlying_field_type underlying_field_type;

            public:
                typedef algebraic_random_device<underlying_field_type> internal_generator_type;
                typedef extended_field_value_type result_type;

                /** Returns a random value in the range [min, max]. */
                result_type operator()() {
                    result_type result;
                    for (auto &coord : result.data) {
                        coord = gen();
                    }

                    return result;
                }

                /** Returns the smallest value that the \algebraic_random_device can produce. */
                // TODO: evaluate min_value at compile-time
                constexpr static inline result_type min() {
                    result_type min_value;
                    for (auto &coord : min_value.data) {
                        coord = internal_generator_type::min();
                    }

                    return min_value;
                }

                /** Returns the largest value that the \algebraic_random_device can produce. */
                // TODO: evaluate max_value at compile-time
                constexpr static inline result_type max() {
                    result_type max_value;
                    for (auto &coord : max_value.data) {
                        coord = internal_generator_type::max();
                    }

                    return max_value;
                }

            protected:
                internal_generator_type gen;
            };

            template<typename AlgebraicType>
            struct algebraic_random_device<
                AlgebraicType, typename std::enable_if<algebra::is_curve_group<AlgebraicType>::value>::type> {
            protected:
                typedef AlgebraicType group_type;
                typedef typename group_type::value_type group_value_type;
                typedef typename group_type::curve_type::scalar_field_type scalar_field_type;

            public:
                typedef algebraic_random_device<scalar_field_type> internal_generator_type;
                typedef group_value_type result_type;

                /**
                 * Returns a random value in the range [min, max]. Elements of group are ordered in exponent growing
                 * order with respect to group base element.
                 */
                // TODO: check correctness of the generation method
                result_type operator()() {
                    return result_type::one() * gen();
                }

                /** Returns the smallest value that the \algebraic_random_device can produce. */
                // TODO: evaluate returned value at compile-time
                constexpr static inline result_type min() {
                    return result_type::zero();
                }

                /** Returns the largest value that the \algebraic_random_device can produce. */
                // TODO: evaluate returned value at compile-time
                constexpr static inline result_type max() {
                    return result_type::one() * (scalar_field_type::modulus - 1);
                }

            protected:
                internal_generator_type gen;
            };
        }    // namespace random
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RANDOM_ALGEBRAIC_RANDOM_DEVICE_HPP
