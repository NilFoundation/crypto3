//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLOCK_BLOCK_STATE_PREPROCESSOR_HPP
#define CRYPTO3_BLOCK_BLOCK_STATE_PREPROCESSOR_HPP

#include <array>
#include <iterator>
#include <climits>

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/digest.hpp>

#include <nil/crypto3/block/accumulators/bits_count.hpp>
#include <nil/crypto3/block/accumulators/parameters/bits.hpp>

#include <boost/integer.hpp>
#include <boost/cstdint.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

#include <boost/range/algorithm/copy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            template<typename Mode, typename StateAccumulator, typename Params>
            struct block_stream_processor {
            private:
                typedef Mode mode_type;
                typedef StateAccumulator accumulator_type;
                typedef Params params_type;

                typedef typename mode_type::block_type block_type;
                constexpr static const std::size_t block_bits = mode_type::block_bits;

                constexpr static const std::size_t word_bits = mode_type::word_bits;

                constexpr static const std::size_t actual_bits = sizeof(typename block_type::value_type) * CHAR_BIT;

            public:
                typedef typename mode_type::endian_type endian_type;

                constexpr static const std::size_t value_bits = params_type::value_bits;
                typedef typename boost::uint_t<value_bits>::least value_type;
                BOOST_STATIC_ASSERT(block_bits % value_bits == 0);
                constexpr static const std::size_t block_values = block_bits / value_bits;
                typedef std::array<value_type, block_values> cache_type;

            private:
                constexpr static const std::size_t length_bits = params_type::length_bits;
                // FIXME: do something more intelligent than capping at sizeof(boost::uintmax_t) * CHAR_BIT
                constexpr static const std::size_t length_type_bits = length_bits < word_bits ?
                                                                          word_bits :
                                                                          length_bits >
                                                                                  sizeof(boost::uintmax_t) * CHAR_BIT ?
                                                                          sizeof(boost::uintmax_t) * CHAR_BIT :
                                                                          length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;

                BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);
                BOOST_STATIC_ASSERT(block_bits % value_bits == 0);

                BOOST_STATIC_ASSERT(!length_bits || value_bits <= length_bits);

                inline void process_block(std::size_t block_seen = block_bits) {
                    using namespace nil::crypto3::detail;
                    // Convert the input into words
                    block_type block;
                    pack_to<endian_type, value_bits, actual_bits>(cache.begin(), cache.end(), block.begin());
                    // Process the block
                    acc(block, accumulators::bits = block_seen);
                }

            public:
                inline void update_one(value_type value) {
                    cache[cache_seen] = value;
                    ++cache_seen;
                    if (cache_seen == block_values) {
                        // Process the completed block
                        process_block();
                        cache_seen = 0;
                    }
                }

                template<typename InputIterator>
                inline void update_n(InputIterator p, size_t n) {
                    for (; n; --n) {
                        update_one(*p++);
                    }
                }

                template<typename InputIterator>
                inline void update_n(InputIterator first, InputIterator last) {
                    std::size_t n = std::distance(first, last);
                    update_n(first, n);
                }

            public:
                block_stream_processor(StateAccumulator &s) : acc(s), cache(cache_type()), cache_seen(0) {
                }

                virtual ~block_stream_processor() {
                    if (cache_seen != 0) {
                        process_block(cache_seen * value_bits);
                        cache_seen = 0;
                    }
                }

                template<typename InputIterator>
                inline void operator()(InputIterator b, InputIterator e, std::random_access_iterator_tag) {
                    return update_n(b, e);
                }

                template<typename InputIterator, typename Category>
                inline void operator()(InputIterator first, InputIterator last, Category) {

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

                void reset() {
                    cache_seen = 0;
                }

                StateAccumulator &acc;

                length_type cache_seen;
                cache_type cache;
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_BLOCK_STATE_PREPROCESSOR_HPP