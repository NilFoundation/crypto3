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

#ifndef CRYPTO3_RANDOM_ALGEBRAIC_ENGINE_HPP
#define CRYPTO3_RANDOM_ALGEBRAIC_ENGINE_HPP

#include <type_traits>

#include <boost/type_traits.hpp>

#include <boost/random/random_device.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace random {
            /**
             * The class template algebraic_engine is a pseudo-random number engine adaptor that discards a
             * certain amount of data produced by the base engine. It models (not fully) a \RandomNumberEngine.
             * https://en.cppreference.com/w/cpp/named_req/RandomNumberEngine
             *
             * The class template algebraic_engine differs from \RandomNumberEngine as it doesn't have constructor and
             * seed function with parameter of result_type. This is due to the fact that algebraic_engine is adapter
             * wrapping some base \RandomNumberEngine (Engine), so instead it has constructor and seed function with
             * parameter of Engine::result_type;
             *
             *
             * The template parameter Engine shall denote an some base \RandomNumberEngine generating random numbers.
             * The template parameter AlgebraicType shall denote an some algebraic type (field or curve type).
             */
            template<typename AlgebraicType, typename Engine = boost::random::mt19937, typename = void>
            struct algebraic_engine;

            template<typename AlgebraicType, typename Engine>
            struct algebraic_engine<
                AlgebraicType,
                Engine,
                typename std::enable_if<algebra::is_field<AlgebraicType>::value &&
                                        !algebra::is_extended_field<AlgebraicType>::value &&
                                        boost::is_integral<typename Engine::result_type>::value>::type> {
            protected:
                typedef AlgebraicType field_type;
                typedef typename field_type::value_type field_value_type;
                typedef typename field_type::modulus_type modulus_type;

                typedef Engine internal_generator_type;
                typedef boost::random::uniform_int_distribution<modulus_type> internal_distribution_type;

                constexpr static modulus_type _min = 0;
                constexpr static modulus_type _max = field_type::modulus - 1;

            public:
                typedef field_value_type result_type;

                algebraic_engine() {
                    seed();
                }
                BOOST_RANDOM_DETAIL_ARITHMETIC_CONSTRUCTOR(algebraic_engine, typename Engine::result_type, value) {
                    seed(value);
                }
                BOOST_RANDOM_DETAIL_SEED_SEQ_CONSTRUCTOR(algebraic_engine, SeedSeq, seq) {
                    seed(seq);
                }

                void seed() {
                    gen.seed();
                }
                BOOST_RANDOM_DETAIL_ARITHMETIC_SEED(algebraic_engine, typename Engine::result_type, value) {
                    gen.seed(value);
                }
                BOOST_RANDOM_DETAIL_SEED_SEQ_SEED(algebraic_engine, SeeqSeq, seq) {
                    gen.seed(seq);
                }

                constexpr static inline result_type min() {
                    constexpr result_type min_value(_min);
                    return min_value;
                }

                constexpr static inline result_type max() {
                    constexpr result_type max_value(_max);
                    return max_value;
                }

                result_type operator()() {
                    return dist(gen);
                }

                void discard(std::size_t z) {
                    while (z--) {
                        (*this)();
                    }
                }

                template<class CharT, class Traits>
                friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os,
                                                                     const algebraic_engine& ae) {
                    os << ae.gen;
                    return os;
                }

                template<class CharT, class Traits>
                friend std::basic_istream<CharT, Traits>& operator>>(std::basic_istream<CharT, Traits>& is,
                                                                     algebraic_engine& ae) {
                    is >> ae.gen;
                    return is;
                }

                friend bool operator==(const algebraic_engine& x_, const algebraic_engine& y_) {
                    return x_.gen == y_.gen && x_.dist == y_.dist;
                }

                friend bool operator!=(const algebraic_engine& x_, const algebraic_engine& y_) {
                    return !(x_ == y_);
                }

            protected:
                internal_generator_type gen;
                internal_distribution_type dist = internal_distribution_type(_min, _max);
            };

            template<typename AlgebraicType, typename Engine>
            struct algebraic_engine<
                AlgebraicType,
                Engine,
                typename std::enable_if<algebra::is_field<AlgebraicType>::value &&
                                        algebra::is_extended_field<AlgebraicType>::value &&
                                        boost::is_integral<typename Engine::result_type>::value>::type> {
            protected:
                typedef AlgebraicType extended_field_type;
                typedef typename extended_field_type::value_type extended_field_value_type;
                typedef typename extended_field_type::underlying_field_type underlying_field_type;

                typedef algebraic_engine<underlying_field_type, Engine> internal_generator_type;

            public:
                typedef extended_field_value_type result_type;

                algebraic_engine() {
                    seed();
                }
                BOOST_RANDOM_DETAIL_ARITHMETIC_CONSTRUCTOR(algebraic_engine, typename Engine::result_type, value) {
                    seed(value);
                }
                BOOST_RANDOM_DETAIL_SEED_SEQ_CONSTRUCTOR(algebraic_engine, SeedSeq, seq) {
                    seed(seq);
                }

                void seed() {
                    gen.seed();
                }
                BOOST_RANDOM_DETAIL_ARITHMETIC_SEED(algebraic_engine, typename Engine::result_type, value) {
                    gen.seed(value);
                }
                BOOST_RANDOM_DETAIL_SEED_SEQ_SEED(algebraic_engine, SeeqSeq, seq) {
                    gen.seed(seq);
                }

                // TODO: evaluate min_value at compile-time
                constexpr static inline result_type min() {
                    result_type min_value;
                    for (auto& coord : min_value.data) {
                        coord = internal_generator_type::min();
                    }

                    return min_value;
                }

                // TODO: evaluate max_value at compile-time
                constexpr static inline result_type max() {
                    result_type max_value;
                    for (auto& coord : max_value.data) {
                        coord = internal_generator_type::max();
                    }

                    return max_value;
                }

                result_type operator()() {
                    result_type result;
                    for (auto& coord : result.data) {
                        coord = gen();
                    }

                    return result;
                }

                void discard(std::size_t z) {
                    while (z--) {
                        (*this)();
                    }
                }

                template<class CharT, class Traits>
                friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os,
                                                                     const algebraic_engine& ae) {
                    os << ae.gen;
                    return os;
                }

                template<class CharT, class Traits>
                friend std::basic_istream<CharT, Traits>& operator>>(std::basic_istream<CharT, Traits>& is,
                                                                     algebraic_engine& ae) {
                    is >> ae.gen;
                    return is;
                }

                friend bool operator==(const algebraic_engine& x_, const algebraic_engine& y_) {
                    return x_.gen == y_.gen;
                }

                friend bool operator!=(const algebraic_engine& x_, const algebraic_engine& y_) {
                    return !(x_ == y_);
                }

            protected:
                internal_generator_type gen;
            };

            template<typename AlgebraicType, typename Engine>
            struct algebraic_engine<
                AlgebraicType,
                Engine,
                typename std::enable_if<algebra::is_curve_group<AlgebraicType>::value &&
                                        boost::is_integral<typename Engine::result_type>::value>::type> {
            protected:
                typedef AlgebraicType group_type;
                typedef typename group_type::value_type group_value_type;
                typedef typename group_type::curve_type::scalar_field_type scalar_field_type;

                typedef algebraic_engine<scalar_field_type, Engine> internal_generator_type;

            public:
                typedef group_value_type result_type;

                algebraic_engine() {
                    seed();
                }
                BOOST_RANDOM_DETAIL_ARITHMETIC_CONSTRUCTOR(algebraic_engine, typename Engine::result_type, value) {
                    seed(value);
                }
                BOOST_RANDOM_DETAIL_SEED_SEQ_CONSTRUCTOR(algebraic_engine, SeedSeq, seq) {
                    seed(seq);
                }

                void seed() {
                    gen.seed();
                }
                BOOST_RANDOM_DETAIL_ARITHMETIC_SEED(algebraic_engine, typename Engine::result_type, value) {
                    gen.seed(value);
                }
                BOOST_RANDOM_DETAIL_SEED_SEQ_SEED(algebraic_engine, SeeqSeq, seq) {
                    gen.seed(seq);
                }

                // TODO: evaluate returned value at compile-time
                constexpr static inline result_type min() {
                    return result_type::zero();
                }

                // TODO: evaluate max_value at compile-time
                constexpr static inline result_type max() {
                    return result_type::one() * (scalar_field_type::modulus - 1);
                }

                // TODO: check correctness of the generation method
                result_type operator()() {
                    return result_type::one() * gen();
                }

                void discard(std::size_t z) {
                    while (z--) {
                        (*this)();
                    }
                }

                template<class CharT, class Traits>
                friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os,
                                                                     const algebraic_engine& ae) {
                    os << ae.gen;
                    return os;
                }

                template<class CharT, class Traits>
                friend std::basic_istream<CharT, Traits>& operator>>(std::basic_istream<CharT, Traits>& is,
                                                                     algebraic_engine& ae) {
                    is >> ae.gen;
                    return is;
                }

                friend bool operator==(const algebraic_engine& x_, const algebraic_engine& y_) {
                    return x_.gen == y_.gen;
                }

                friend bool operator!=(const algebraic_engine& x_, const algebraic_engine& y_) {
                    return !(x_ == y_);
                }

            protected:
                internal_generator_type gen;
            };
        }    // namespace random
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RANDOM_ALGEBRAIC_ENGINE_HPP
