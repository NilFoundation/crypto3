//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_HASH_BLOCK_STREAM_PROCESSOR_HPP
#define CRYPTO3_HASH_BLOCK_STREAM_PROCESSOR_HPP

#include <array>
#include <iterator>

#include <nil/crypto3/detail/pack.hpp>

#include <nil/crypto3/hash/accumulators/bits_count.hpp>
#include <nil/crypto3/hash/accumulators/parameters/bits.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {

            /*!
             * @brief This will convert input data stream (bytes, uint64, etc. — everything convertable
             * to block_type via pack function) into blocks and feed these blocks to StateAccumulator.
             *
             * @tparam Construction
             * @tparam StateAccumulator
             * @tparam Params
             */
            template<typename Policy, typename StateAccumulator, std::size_t ValueBits>
            class block_stream_processor {
            protected:
                typedef StateAccumulator accumulator_type;

                constexpr static const std::size_t word_bits = Policy::word_bits;

                constexpr static const std::size_t block_bits = Policy::block_bits;
                typedef typename Policy::block_type block_type;

            public:
                typedef typename Policy::digest_endian endian_type;

                constexpr static const std::size_t value_bits = ValueBits;
                typedef typename boost::uint_t<value_bits>::least value_type;
                BOOST_STATIC_ASSERT(word_bits % value_bits == 0);

                constexpr static const std::size_t block_values = block_bits / value_bits;
                typedef std::array<value_type, block_values> cache_type;

            protected:
                inline void process_block(std::size_t block_seen = block_bits) {
                    using namespace nil::crypto3::detail;
                    // Convert the input into words
                    block_type block;
                    pack_to<endian_type, value_bits, word_bits>(cache.begin(), cache.end(), block.begin());
                    // Process the block
                    acc(block, ::nil::crypto3::accumulators::bits = block_seen);
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
                inline void operator()(InputIterator b, InputIterator e) {
                    while (b != e) {
                        update_one(*b++);
                    }
                }

                template<typename ContainerT>
                inline void operator()(const ContainerT &c) {
                    update_n(c.data(), c.size());
                }

            public:
                block_stream_processor(accumulator_type &acc) : acc(acc), cache(), cache_seen(0) {
                }

                virtual ~block_stream_processor() {
                    if (cache_seen > 0) {
                        process_block(cache_seen * value_bits);
                        cache_seen = 0;
                    }
                }

            private:
                accumulator_type &acc;

                cache_type cache;
                std::size_t cache_seen;
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif
