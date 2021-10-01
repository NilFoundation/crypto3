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
            /*!
             * @brief
             * @tparam AlgebraicType denote an some algebraic type (field, curve group types).
             * @tparam Engine denote an some base \RandomNumberEngine generating random numbers
             *
             * The class template algebraic_engine is a pseudo-random number engine adaptor that generate random values
             * of algebraic type using data produced by the base engine. It models (not fully) a
             * \RandomNumberEngine. https://en.cppreference.com/w/cpp/named_req/RandomNumberEngine
             *
             * @warning The class template algebraic_engine differs from \RandomNumberEngine as it doesn't have
             * constructor and seed function with parameter of result_type. This is due to the fact that
             * algebraic_engine is adapter wrapping some base \RandomNumberEngine (Engine), so instead it has
             * constructor and seed function with parameter of Engine::result_type.
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
                typedef typename field_type::integral_type integral_type;

                constexpr static integral_type _min = 0;
                constexpr static integral_type _max = field_type::modulus - 1;

            public:
                typedef Engine internal_generator_type;
                typedef boost::random::uniform_int_distribution<integral_type> internal_distribution_type;
                typedef typename internal_generator_type::result_type internal_result_type;
                typedef field_value_type result_type;

                /**
                 * Constructs a @c algebraic_engine and calls @c seed().
                 */
                algebraic_engine() {
                    seed();
                }
                /**
                 * Constructs a @c algebraic_engine and calls @c seed(value).
                 */
                BOOST_RANDOM_DETAIL_ARITHMETIC_CONSTRUCTOR(algebraic_engine, typename Engine::result_type, value) {
                    seed(value);
                }
                /**
                 * Constructs a algebraic_engine and calls @c seed(seq).
                 *
                 * @xmlnote
                 * The copy constructor will always be preferred over
                 * the templated constructor.
                 * @endxmlnote
                 */
                BOOST_RANDOM_DETAIL_SEED_SEQ_CONSTRUCTOR(algebraic_engine, SeedSeq, seq) {
                    seed(seq);
                }

                /** Calls @c seed(default_seed) of base Engine. */
                void seed() {
                    gen.seed();
                }
                /** Calls @c seed(value) of base Engine. */
                BOOST_RANDOM_DETAIL_ARITHMETIC_SEED(algebraic_engine, typename Engine::result_type, value) {
                    gen.seed(value);
                }
                /** Calls @c seed(seq) of base Engine. */
                BOOST_RANDOM_DETAIL_SEED_SEQ_SEED(algebraic_engine, SeeqSeq, seq) {
                    gen.seed(seq);
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

                /** Returns a random value in the range [min, max]. */
                result_type operator()() {
                    return dist(gen);
                }

                /**
                 * Advances the state of the generator by @c z steps.  Equivalent to
                 */
                void discard(std::size_t z) {
                    while (z--) {
                        (*this)();
                    }
                }

                /** Writes a algebraic_engine to a @c std::ostream */
                template<class CharT, class Traits>
                friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os,
                                                                     const algebraic_engine& ae) {
                    os << ae.gen;
                    return os;
                }

                /** Reads a algebraic_engine from a @c std::istream */
                template<class CharT, class Traits>
                friend std::basic_istream<CharT, Traits>& operator>>(std::basic_istream<CharT, Traits>& is,
                                                                     algebraic_engine& ae) {
                    is >> ae.gen;
                    return is;
                }

                /**
                 * Returns true if the two generators are in the same state,
                 * and will thus produce identical sequences.
                 */
                friend bool operator==(const algebraic_engine& x_, const algebraic_engine& y_) {
                    return x_.gen == y_.gen && x_.dist == y_.dist;
                }

                /**
                 * Returns true if the two generators are in different states.
                 */
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

            public:
                typedef algebraic_engine<underlying_field_type, Engine> internal_generator_type;
                typedef extended_field_value_type result_type;

                /**
                 * Constructs a @c algebraic_engine and calls @c seed().
                 */
                algebraic_engine() {
                    seed();
                }
                /**
                 * Constructs a @c algebraic_engine and calls @c seed(value).
                 */
                BOOST_RANDOM_DETAIL_ARITHMETIC_CONSTRUCTOR(algebraic_engine, typename Engine::result_type, value) {
                    seed(value);
                }
                /**
                 * Constructs a algebraic_engine and calls @c seed(seq).
                 *
                 * @xmlnote
                 * The copy constructor will always be preferred over
                 * the templated constructor.
                 * @endxmlnote
                 */
                BOOST_RANDOM_DETAIL_SEED_SEQ_CONSTRUCTOR(algebraic_engine, SeedSeq, seq) {
                    seed(seq);
                }

                /** Calls @c seed(default_seed) of base Engine. */
                void seed() {
                    gen.seed();
                }
                /** Calls @c seed(value) of base Engine. */
                BOOST_RANDOM_DETAIL_ARITHMETIC_SEED(algebraic_engine, typename Engine::result_type, value) {
                    gen.seed(value);
                }
                /** Calls @c seed(seq) of base Engine. */
                BOOST_RANDOM_DETAIL_SEED_SEQ_SEED(algebraic_engine, SeeqSeq, seq) {
                    gen.seed(seq);
                }

                /** Returns the smallest value that the \algebraic_random_device can produce. */
                // TODO: evaluate min_value at compile-time
                constexpr static inline result_type min() {
                    result_type min_value;
                    for (auto& coord : min_value.data) {
                        coord = internal_generator_type::min();
                    }

                    return min_value;
                }

                /** Returns the largest value that the \algebraic_random_device can produce. */
                // TODO: evaluate max_value at compile-time
                constexpr static inline result_type max() {
                    result_type max_value;
                    for (auto& coord : max_value.data) {
                        coord = internal_generator_type::max();
                    }

                    return max_value;
                }

                /** Returns a random value in the range [min, max]. */
                result_type operator()() {
                    result_type result;
                    for (auto& coord : result.data) {
                        coord = gen();
                    }

                    return result;
                }

                /**
                 * Advances the state of the generator by @c z steps.  Equivalent to
                 */
                void discard(std::size_t z) {
                    while (z--) {
                        (*this)();
                    }
                }

                /** Writes a algebraic_engine to a @c std::ostream */
                template<class CharT, class Traits>
                friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os,
                                                                     const algebraic_engine& ae) {
                    os << ae.gen;
                    return os;
                }

                /** Reads a algebraic_engine from a @c std::istream */
                template<class CharT, class Traits>
                friend std::basic_istream<CharT, Traits>& operator>>(std::basic_istream<CharT, Traits>& is,
                                                                     algebraic_engine& ae) {
                    is >> ae.gen;
                    return is;
                }

                /**
                 * Returns true if the two generators are in the same state,
                 * and will thus produce identical sequences.
                 */
                friend bool operator==(const algebraic_engine& x_, const algebraic_engine& y_) {
                    return x_.gen == y_.gen;
                }

                /**
                 * Returns true if the two generators are in different states.
                 */
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

            public:
                typedef algebraic_engine<scalar_field_type, Engine> internal_generator_type;
                typedef group_value_type result_type;

                /**
                 * Constructs a @c algebraic_engine and calls @c seed().
                 */
                algebraic_engine() {
                    seed();
                }
                /**
                 * Constructs a @c algebraic_engine and calls @c seed(value).
                 */
                BOOST_RANDOM_DETAIL_ARITHMETIC_CONSTRUCTOR(algebraic_engine, typename Engine::result_type, value) {
                    seed(value);
                }
                /**
                 * Constructs a algebraic_engine and calls @c seed(seq).
                 *
                 * @xmlnote
                 * The copy constructor will always be preferred over
                 * the templated constructor.
                 * @endxmlnote
                 */
                BOOST_RANDOM_DETAIL_SEED_SEQ_CONSTRUCTOR(algebraic_engine, SeedSeq, seq) {
                    seed(seq);
                }

                /** Calls @c seed(default_seed) of base Engine. */
                void seed() {
                    gen.seed();
                }
                /** Calls @c seed(value) of base Engine. */
                BOOST_RANDOM_DETAIL_ARITHMETIC_SEED(algebraic_engine, typename Engine::result_type, value) {
                    gen.seed(value);
                }
                /** Calls @c seed(seq) of base Engine. */
                BOOST_RANDOM_DETAIL_SEED_SEQ_SEED(algebraic_engine, SeeqSeq, seq) {
                    gen.seed(seq);
                }

                /** Returns the smallest value that the \algebraic_random_device can produce. */
                // TODO: evaluate returned value at compile-time
                constexpr static inline result_type min() {
                    return result_type::zero();
                }

                /** Returns the largest value that the \algebraic_random_device can produce. */
                // TODO: evaluate max_value at compile-time
                constexpr static inline result_type max() {
                    return result_type::one() * (scalar_field_type::modulus - 1);
                }

                /**
                 * Returns a random value in the range [min, max]. Elements of group are ordered in exponent growing
                 * order with respect to group base element.
                 */
                // TODO: check correctness of the generation method
                result_type operator()() {
                    return result_type::one() * gen();
                }

                /**
                 * Advances the state of the generator by @c z steps.  Equivalent to
                 */
                void discard(std::size_t z) {
                    while (z--) {
                        (*this)();
                    }
                }

                /** Writes a algebraic_engine to a @c std::ostream */
                template<class CharT, class Traits>
                friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os,
                                                                     const algebraic_engine& ae) {
                    os << ae.gen;
                    return os;
                }

                /** Reads a algebraic_engine from a @c std::istream */
                template<class CharT, class Traits>
                friend std::basic_istream<CharT, Traits>& operator>>(std::basic_istream<CharT, Traits>& is,
                                                                     algebraic_engine& ae) {
                    is >> ae.gen;
                    return is;
                }

                /**
                 * Returns true if the two generators are in the same state,
                 * and will thus produce identical sequences.
                 */
                friend bool operator==(const algebraic_engine& x_, const algebraic_engine& y_) {
                    return x_.gen == y_.gen;
                }

                /**
                 * Returns true if the two generators are in different states.
                 */
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
