//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FIXED_BLOCK_STREAM_PROCESSOR_HPP
#define CRYPTO3_FIXED_BLOCK_STREAM_PROCESSOR_HPP

#include <array>
#include <iterator>

#include <nil/crypto3/codec/detail/pack.hpp>
#include <nil/crypto3/codec/detail/digest.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

#include <boost/range/algorithm/copy.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            template<typename Mode, typename StateAccumulator, typename Params>
            struct fixed_block_stream_processor {
            private:
                typedef Mode mode_type;
                typedef StateAccumulator accumulator_type;
                typedef Params params_type;

                constexpr static const std::size_t input_block_bits = mode_type::input_block_bits;
                typedef typename mode_type::input_block_type input_block_type;

                constexpr static const std::size_t input_value_bits = mode_type::input_value_bits;
                typedef typename input_block_type::value_type input_value_type;

            public:
                typedef typename params_type::endian_type endian_type;

                constexpr static const std::size_t value_bits = params_type::value_bits;
                typedef typename boost::uint_t<value_bits>::least value_type;
                BOOST_STATIC_ASSERT(input_block_bits % value_bits == 0);
                constexpr static const std::size_t block_values = input_block_bits / value_bits;
                typedef std::array<value_type, block_values> cache_type;

            private:
                constexpr static const std::size_t length_bits = params_type::length_bits;
                // FIXME: do something more intelligent than capping at 64
                constexpr static const std::size_t length_type_bits =
                    length_bits < input_block_bits ? input_block_bits : length_bits > 64 ? 64 : length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;

                BOOST_STATIC_ASSERT(!length_bits || length_bits % input_block_bits == 0);
                BOOST_STATIC_ASSERT(input_block_bits % value_bits == 0);

                BOOST_STATIC_ASSERT(!length_bits || value_bits <= length_bits);

                void update_one(value_type value) {
                    std::size_t i = seen % input_block_bits;
                    cache[i / value_bits] = value;
                    seen += value_bits;
                    if (i == input_block_bits - value_bits) {
                        // Convert the input into words
                        input_block_type block = {0};
                        pack<endian_type, value_bits, input_value_bits>(cache.begin(), cache.end(), block);

                        // Process the block
                        state(block);

                        // Reset seen if we don't need to track the length
                        if (!length_bits) {
                            seen = 0;
                        }
                    }
                }

                template<typename InputIterator>
                void update_n(InputIterator first, InputIterator last) {
                    std::size_t n = std::distance(first, last);
#ifndef CRYPTO3_CODEC_NO_OPTIMIZATION
#pragma clang loop unroll(full)
                    for (; n && (seen % input_block_bits); --n, ++first) {
                        update_one(*first);
                    }
#pragma clang loop unroll(full)
                    for (; n >= block_values; n -= block_values, first += block_values) {
                        // Convert the input into words
                        input_block_type block = {0};
                        pack<endian_type, value_bits, input_value_bits>(first, first + block_values, block);
                        seen += value_bits * block_values;

                        state(block);

                        // Reset seen if we don't need to track the length
                        if (!length_bits) {
                            seen = 0;
                        }
                    }
#endif

#pragma clang loop unroll(full)
                    for (; n; --n, ++first) {
                        update_one(*first);
                    }
                }

            public:
                fixed_block_stream_processor(accumulator_type &s) : state(s), cache(cache_type()), seen(0) {
                }

                virtual ~fixed_block_stream_processor() {
                    if (!cache.empty()) {
                        input_block_type block = {0};
                        typename input_block_type::const_iterator v = block.cbegin();

                        pack<endian_type, value_bits, input_value_bits>(cache.begin(), cache.begin() + cache.size(),
                                                                        block);
                        for (length_type itr = seen - (seen % input_block_bits); itr < seen; itr += value_bits) {
                            state(*v++);
                        }
                    }
                }

                template<typename InputIterator>
                inline void operator()(InputIterator b, InputIterator e, std::random_access_iterator_tag) {
                    return update_n(b, e);
                }

                template<typename InputIterator, typename Category>
                inline void operator()(InputIterator first, InputIterator last, Category) {
#pragma clang loop unroll(full)
                    while (first != last) {
                        update_one(*first++);
                    }
                }

                template<typename ValueType>
                inline void operator()(const ValueType &value) {
                    return update_one(value);
                }

                template<typename InputIterator>
                inline void operator()(InputIterator b, InputIterator e) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return operator()(b, e, cat());
                }

                template<typename ValueType>
                inline void operator()(const std::initializer_list<ValueType> &il) {
                    return operator()(il.begin(), il.end());
                }

                inline void reset() {
                    seen = 0;
                }

                accumulator_type &state;

                length_type seen;
                cache_type cache;
            };
        }    // namespace codec
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_FIXED_BLOCK_STREAM_PROCESSOR_HPP
