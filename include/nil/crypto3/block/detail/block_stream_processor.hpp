//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_BLOCK_STATE_PREPROCESSOR_HPP
#define CRYPTO3_BLOCK_BLOCK_STATE_PREPROCESSOR_HPP

#include <array>
#include <iterator>

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/digest.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

#include <boost/range/algorithm/copy.hpp>
#include <nil/crypto3/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            template<typename Mode, typename StateAccumulator, typename Params>
            struct block_stream_processor {
            private:
                typedef Mode mode_type;
                typedef StateAccumulator accumulator_type;
                typedef Params params_type;

                typedef typename mode_type::block_type input_block_type;
                constexpr static const std::size_t input_block_bits = mode_type::block_bits;

            public:
                typedef typename mode_type::endian_type endian_type;
                typedef typename mode_type::input_endian_type input_endian_type;

                constexpr static const std::size_t value_bits = params_type::value_bits;
                typedef typename boost::uint_t<value_bits>::least value_type;
                BOOST_STATIC_ASSERT(input_block_bits % value_bits == 0);
                constexpr static const std::size_t block_values = input_block_bits / value_bits;
                typedef std::array<value_type, block_values> cache_type;

            private:
                constexpr static const std::size_t length_bits = params_type::length_bits;
                // FIXME: do something more intelligent than capping at 64
                //constexpr static const std::size_t length_type_bits =
                    //length_bits < input_block_bits ? input_block_bits : length_bits > 64 ? 64 : length_bits;
                typedef typename boost::uint_t<64>::least length_type;

                //BOOST_STATIC_ASSERT(!length_bits || length_bits % input_block_bits == 0);
                BOOST_STATIC_ASSERT(input_block_bits % value_bits == 0);

                BOOST_STATIC_ASSERT(!length_bits || value_bits <= length_bits);

                typedef ::nil::crypto3::detail::packer<input_endian_type, endian_type, value_bits, 
                    input_block_bits / block_values> packer_type;
/*
                template<typename Endianness = input_endian_type>
                typename std::enable_if<!(Endianness == stream_endian::big_octet_big_bit)>::type
                process_block(std::size_t block_seen = block_bits) {
                    acc(cache, accumulators::block_bits = block_seen);
                }
                template<typename Endianness = input_endian_type>
                typename std::enable_if<Endianness == stream_endian::big_octet_big_bit>::type
                process_block(std::size_t block_seen = block_bits) {
                    using namespace nil::crypto3::detail;
                    // Convert the input into words
                    block_type block;
                    pack<endian_type, value_bits, word_bits>(cache, block);
                    // Process the block
                    acc(block, accumulators::block_bits = block_seen);
                }
                */


                void update_one(value_type value) {
                    std::size_t i = seen % input_block_bits;
                    cache[i / value_bits] = value;
                    seen += value_bits;
                    if (i == input_block_bits - value_bits) {
                        // Convert the input into words
                        input_block_type block = {0};
                        packer_type::pack(cache.begin(), cache.end(), block.begin());

                        // Process the block
                        state(block);

                        // Reset seen if we don't need to track the length
                        if (!length_bits) {
                            seen = 0;
                        }
                    }
                }

                template<typename InputIterator>
                inline void update_n(InputIterator first, InputIterator last) {
                    std::size_t n = std::distance(first, last);
#ifndef CRYPTO3_BLOCK_NO_OPTIMIZATION
#pragma clang loop unroll(full)
                    for (; n && (seen % input_block_bits); --n, ++first) {
                        update_one(*first);
                    }
#pragma clang loop unroll(full)
                    for (; n >= block_values; n -= block_values, first += block_values) {
                        // Convert the input into words
                        input_block_type block = {0};
                        packer_type::pack(first, first + block_values, block.begin());
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
                block_stream_processor(StateAccumulator &s) : state(s), cache(cache_type()), seen(0) {
                }

                virtual ~block_stream_processor() {
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

                void reset() {
                    seen = 0;
                }

                StateAccumulator &state;

                length_type seen;
                cache_type cache;
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_BLOCK_STATE_PREPROCESSOR_HPP