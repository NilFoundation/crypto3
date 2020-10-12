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

#ifndef CRYPTO3_STREAM_SALSA20_HPP
#define CRYPTO3_STREAM_SALSA20_HPP

#include <nil/crypto3/stream/detail/salsa20/salsa20_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            template<std::size_t IVBits, std::size_t KeyBits, std::size_t Rounds = 20>
            class salsa20_finalizer {
                typedef detail::salsa20_functions<IVBits, KeyBits, Rounds> policy_type;

            public:
                constexpr static const std::size_t rounds = policy_type::rounds;

                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                typedef typename policy_type::iv_type iv_type;

                constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                constexpr static const std::size_t key_bits = policy_type::key_bits;
                typedef typename policy_type::key_type key_type;

                template<typename InputRange, typename OutputRange>
                void process(OutputRange &out, InputRange &in, key_schedule_type &schedule, block_type &block) {
                    xor_buf(out, in, block, block.size());
                }
            };
            /*!
             * @brief
             * @tparam IVBits
             * @tparam KeyBits
             * @tparam Rounds
             * @ingroup stream
             */
            template<std::size_t IVBits, std::size_t KeyBits, std::size_t Rounds = 20>
            class salsa20 {
                typedef detail::salsa20_functions<IVBits, KeyBits, Rounds> policy_type;

            public:
                constexpr static const std::size_t rounds = policy_type::rounds;

                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                typedef typename policy_type::iv_type iv_type;

                constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                constexpr static const std::size_t key_bits = policy_type::key_bits;
                typedef typename policy_type::key_type key_type;

                salsa20(key_schedule_type &schedule, const key_type &key, const iv_type &iv = iv_type()) {
                    policy_type::schedule_key(schedule, key);
                    policy_type::schedule_iv(schedule, iv);
                }

                template<typename InputRange, typename OutputRange>
                void process(OutputRange &out, InputRange &in, key_schedule_type &schedule, block_type &block) {
                    xor_buf(out, in, block, block.size());
                    policy_type::salsa_core(block, schedule);

                    ++schedule[8];
                    schedule[9] += (schedule[8] == 0);
                }

                void seek(key_schedule_type &schedule, block_type &block, std::size_t offset) {
                    // Find the block offset
                    const uint64_t counter = offset / 64;
                    uint8_t counter8[8];
                    boost::endian::store_little_u64(counter8, counter);

                    schedule[8] = boost::endian::store_little_u32(counter8, 0);
                    schedule[9] += boost::endian::store_little_u32(counter8, 1);

                    salsa_core(block, schedule);

                    ++schedule[8];
                    schedule[9] += (schedule[8] == 0);
                }
            };
        }    // namespace stream
    }        // namespace crypto3
}    // namespace nil

#endif
