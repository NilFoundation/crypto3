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

#ifndef CRYPTO3_STREAM_RC4_FUNCTIONS_HPP
#define CRYPTO3_STREAM_RC4_FUNCTIONS_HPP

#include <nil/crypto3/stream/detail/rc4/rc4_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<std::size_t IVSize, std::size_t KeyBits>
                struct rc4_functions : public rc4_policy<IVSize, KeyBits> {
                    typedef rc4_policy<IVSize, KeyBits> policy_type;

                    typedef typename policy_type::byte_type byte_type;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                    constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t state_size = policy_type::state_size;
                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    typedef typename policy_type::state_type state_type;

                    static void generate(key_schedule_type &schedule, state_type &state) {
                        std::uint8_t SX, SY;
                        for (std::size_t i = 0; i != state_size; i += 4) {
                            SX = schedule[state.x + 1];
                            state.y = (state.y + SX) % 256;
                            SY = schedule[state.y];
                            schedule[state.x + 1] = SY;
                            schedule[state.y] = SX;
                            state.data[i] = schedule[(SX + SY) % 256];

                            SX = schedule[state.x + 2];
                            state.y = (state.y + SX) % 256;
                            SY = schedule[state.y];
                            schedule[state.x + 2] = SY;
                            schedule[state.y] = SX;
                            state.data[i + 1] = schedule[(SX + SY) % 256];

                            SX = schedule[state.x + 3];
                            state.y = (state.y + SX) % 256;
                            SY = schedule[state.y];
                            schedule[state.x + 3] = SY;
                            schedule[state.y] = SX;
                            state.data[i + 2] = schedule[(SX + SY) % 256];

                            state.x = (state.x + 4) % 256;
                            SX = schedule[state.x];
                            state.y = (state.y + SX) % 256;
                            SY = schedule[state.y];
                            schedule[state.x] = SY;
                            schedule[state.y] = SX;
                            state.data[i + 3] = schedule[(SX + SY) % 256];
                        }
                    }
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RC4_FUNCTIONS_HPP
