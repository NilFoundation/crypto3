//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_STATE_PREPROCESSOR_HPP
#define CRYPTO3_BLOCK_STATE_PREPROCESSOR_HPP

#include <array>
#include <iterator>

#include <nil/concept_container/accumulators/bit_count.hpp>

#include <nil/crypto3/codec/detail/pack.hpp>

#include <nil/crypto3/codec/detail/digest.hpp>
#include <nil/crypto3/codec/algorithm/move.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

#include <boost/range/algorithm/copy.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            template<typename Mode,
                     typename Endian, std::size_t ValueBits, std::size_t LengthBits,
                     typename CacheContainer>
            struct block_state_preprocessor {
            private:
                typedef Mode mode_type;

                typedef typename mode_type::input_block_type input_block_type;
                constexpr static const std::size_t input_block_bits = mode_type::input_block_bits;

                typedef typename mode_type::output_block_type output_block_type;
                constexpr static const std::size_t output_block_bits = mode_type::output_block_bits;
            public:

                constexpr static const std::size_t value_bits = ValueBits;
                typedef typename boost::uint_t<value_bits>::least value_type;
                BOOST_STATIC_ASSERT(input_block_bits % value_bits == 0);
                constexpr static const std::size_t block_values = input_block_bits / value_bits;
                typedef std::array<value_type, block_values> value_array_type;

            private:

                constexpr static const std::size_t length_bits = LengthBits;
                // FIXME: do something more intelligent than capping at 64
                constexpr static const std::size_t length_type_bits =
                        length_bits < input_block_bits ? input_block_bits : length_bits > 64 ? 64 : length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;

                BOOST_STATIC_ASSERT(!length_bits || length_bits % input_block_bits == 0);
                BOOST_STATIC_ASSERT(output_block_bits % value_bits == 0);

                BOOST_STATIC_ASSERT(!length_bits || value_bits <= length_bits);

                template<typename OutputIterator>
                inline OutputIterator update_one(value_type value, std::size_t values_remains, OutputIterator out) {
                    std::size_t i = input_block_bits == 0 ? 0 : accumulators::extract::bit_count(cache.stats()) %
                                                                input_block_bits;
                    value_array[i / value_bits] = value;
                    cache.stats()(value);
                    if (i == input_block_bits - value_bits || values_remains == 1) {
                        // Convert the input into words
                        input_block_type block = {0};
                        pack<Endian, value_bits, block_values == 0 ? 0 : input_block_bits / block_values>(
                                value_array.begin(), value_array.end(), block);

                        // Process the block
                        out = move(mode_type::process_block(block), out);

                        // Reset seen if we don't need to track the length
                        if (!length_bits) {
                            cache.stats() = {};
                        }
                    }
                    return out;
                }

                template<typename InputIterator, typename OutputIterator>
                inline OutputIterator update_n(InputIterator first, InputIterator last, OutputIterator out) {
                    std::size_t n = std::distance(first, last), block_bits =
                            input_block_bits == 0 ? n * value_bits : input_block_bits;
#ifndef CRYPTO3_CODEC_NO_OPTIMIZATION
                    for (; n && (accumulators::extract::bit_count(cache.stats()) % block_bits); --n, ++first) {
                        out = update_one(*first, n, out);
                    }
                    for (; n >= block_values; n -= block_values, first += block_values) {
                        // Convert the input into words
                        input_block_type block = {0};
                        pack<Endian, value_bits, block_values == 0 ? 0 : input_block_bits / block_values>(first,
                                first + block_values, block);
                        cache.stats()(block.begin(), block.end());

                        out = move(mode_type::process_block(block), out);

                        // Reset seen if we don't need to track the length
                        if (!length_bits) {
                            cache.stats() = {};
                        }
                    }
#endif

                    for (; n; --n, ++first) {
                        out = update_one(*first, n, out);
                    }
                    return out;
                }

            public:
                block_state_preprocessor(CacheContainer &c) : cache(c), value_array(value_array_type()) {
                    BOOST_ASSERT(accumulators::extract::bit_count(c.stats()) <= value_bits * block_values);

                    pack<Endian, std::numeric_limits<typename CacheContainer::value_type>::digits +
                                 std::numeric_limits<typename CacheContainer::value_type>::is_signed, value_bits>(
                            c.data(), value_array);
                }

                virtual ~block_state_preprocessor() {
                    pack<Endian, value_bits, std::numeric_limits<typename CacheContainer::value_type>::digits +
                                             std::numeric_limits<typename CacheContainer::value_type>::is_signed>(
                            value_array, cache.data());
                }

                template<typename InputIterator, typename OutputIterator>
                OutputIterator operator()(InputIterator b, InputIterator e, OutputIterator out,
                                          std::random_access_iterator_tag) {
                    return update_n(b, e, out);
                }

                template<typename InputIterator, typename OutputIterator, typename Category>
                OutputIterator operator()(InputIterator first, InputIterator last, OutputIterator out, Category) {
                    while (first != last) {
                        out = update_one(*first++, std::distance(first, last), out);
                    }
                    return out;
                }

                template<typename ValueType, typename OutputIterator>
                OutputIterator operator()(const ValueType &value, OutputIterator out) {
                    return update_one(value, 1, out);
                }

                template<typename InputIterator, typename OutputIterator>
                OutputIterator operator()(InputIterator b, InputIterator e, OutputIterator out) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return operator()(b, e, out, cat());
                }

                template<typename SinglePassRange, typename OutputRange>
                OutputRange operator()(const SinglePassRange &c, OutputRange &out) {
                    return update_n(c.begin(), c.end(), out);
                }

                template<typename ValueType, typename OutputIterator>
                OutputIterator operator()(const std::initializer_list<ValueType> &il, OutputIterator out) {
                    return operator()(il.begin(), il.end(), out);
                }

                void reset() {
                    value_array.fill(0);
                }

                CacheContainer &cache;

                value_array_type value_array;
            };
        }
    }
}

#endif //CRYPTO3_BLOCK_STATE_PREPROCESSOR_HPP
