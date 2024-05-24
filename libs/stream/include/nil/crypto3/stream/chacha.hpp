//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_STREAM_CHACHA_HPP
#define CRYPTO3_STREAM_CHACHA_HPP

#include <nil/crypto3/stream/detail/chacha/chacha_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            template<std::size_t IVBits, std::size_t KeyBits, std::size_t Rounds>
            struct chacha_finalizer {
                typedef detail::chacha_functions<Rounds, IVBits, KeyBits> policy_type;

            public:
                constexpr static const std::size_t rounds = policy_type::rounds;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_size = policy_type::block_size;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t min_key_schedule_bits = policy_type::min_key_schedule_bits;
                constexpr static const std::size_t min_key_schedule_size = policy_type::min_key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                typedef typename policy_type::iv_type iv_type;

                constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                constexpr static const std::size_t key_bits = policy_type::key_bits;
                typedef typename policy_type::key_type key_type;

                template<typename InputRange, typename OutputRange>
                void process(InputRange &in, OutputRange &out, key_schedule_type &schedule, block_type &block) {
                    xor_buf(out, in, block, block_size);
                }
            };
            /*!
             * @brief DJB's ChaCha (https://cr.yp.to/chacha.html)
             * @tparam Rounds Amount of rounds
             * @ingroup stream
             * @note Currently only 8, 12 or 20 rounds are supported, all others
             * will throw an exception
             */
            template<std::size_t IVBits = 64, std::size_t KeyBits = 128, std::size_t Rounds = 20>
            class chacha {
                typedef detail::chacha_functions<Rounds, IVBits, KeyBits> policy_type;

            public:
                constexpr static const std::size_t rounds = policy_type::rounds;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_size = policy_type::block_size;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t min_key_schedule_bits = policy_type::min_key_schedule_bits;
                constexpr static const std::size_t min_key_schedule_size = policy_type::min_key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                typedef typename policy_type::iv_type iv_type;

                constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                constexpr static const std::size_t key_bits = policy_type::key_bits;
                typedef typename policy_type::key_type key_type;

                chacha(key_schedule_type &schedule, const key_type &key, const iv_type &iv = iv_type()) {
                    policy_type::schedule_key(schedule, key);
                    policy_type::schedule_iv(schedule, iv);
                }

                template<typename InputRange, typename OutputRange>
                void process(InputRange &in, OutputRange &out, key_schedule_type &schedule, block_type &block) {
                    xor_buf(out, in, block, block_size);
                    policy_type::chacha_x4(block, schedule);
                }

                void seek(block_type &block, key_schedule_type &schedule, uint64_t offset) {
                    // Find the block offset
                    uint64_t counter = offset / 64;

                    uint8_t out[8];

                    boost::endian::store_little_u64(out, counter);

                    schedule[12] = boost::endian::store_little_u32(out, 0);
                    schedule[13] += boost::endian::store_little_u32(out, 1);

                    policy_type::chacha_x4(block, schedule);
                }
            };
        }    // namespace stream
    }        // namespace crypto3
}    // namespace nil

#endif
