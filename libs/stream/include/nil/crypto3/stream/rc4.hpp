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

#ifndef CRYPTO3_STREAM_RC4_HPP
#define CRYPTO3_STREAM_RC4_HPP

#include <nil/crypto3/stream/detail/rc4/rc4_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            template<std::size_t IVBits, std::size_t KeyBits>
            class rc4_finalizer {
                typedef detail::rc4_functions<IVBits, KeyBits> policy_type;

            public:
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                constexpr static const std::size_t state_size = policy_type::state_size;
                constexpr static const std::size_t state_bits = policy_type::state_bits;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                typedef typename policy_type::iv_type iv_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_size = policy_type::key_size;
                typedef typename policy_type::key_type key_type;

                template<typename OutputRange, typename InputRange>
                void process(OutputRange &out, InputRange &in, key_schedule_type &schedule, state_type &state,
                             const block_type &block) {
                    xor_buf(out, in, state.data, state.size());
                }
            };
            /*!
             * @brief
             * @tparam IVBits
             * @tparam KeyBits
             * @ingroup stream
             */
            template<std::size_t IVBits, std::size_t KeyBits, std::size_t SkipSize>
            class rc4 {
                typedef detail::rc4_functions<IVBits, KeyBits> policy_type;

            public:
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                constexpr static const std::size_t state_size = policy_type::state_size;
                constexpr static const std::size_t state_bits = policy_type::state_bits;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t iv_bits = policy_type::iv_bits;
                typedef typename policy_type::iv_type iv_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_size = policy_type::key_size;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t skip_size = SkipSize;

                rc4(key_schedule_type &schedule, state_type &state, const key_type &key,
                    const iv_type &iv = iv_type()) {
                    schedule_key(schedule, key);
                }

                template<typename OutputRange, typename InputRange>
                void process(OutputRange &out, InputRange &in, key_schedule_type &schedule, state_type &state,
                             const block_type &block) {
                    xor_buf(out, in, state.data, state.size());
                    policy_type::generate(schedule, state);
                }

            protected:
                void schedule_key(block_type &block, key_schedule_type &schedule, state_type &state, const key_type
                                                                                                       &key) {
                    for (std::size_t i = 0; i != key_schedule_size; ++i) {
                        schedule[i] = i;
                    }

                    for (size_t i = 0, state_index = 0; i != key_schedule_size; ++i) {
                        state_index = (state_index + key[i % key_size] + schedule[i]) % key_schedule_size;
                        std::swap(schedule[i], schedule[state_index]);
                    }

                    for (size_t i = 0; i <= SkipSize; i += block.size()) {
                        policy_type::generate(schedule, state);
                    }
                }
            };
        }    // namespace stream
    }        // namespace crypto3
}    // namespace nil

#endif
