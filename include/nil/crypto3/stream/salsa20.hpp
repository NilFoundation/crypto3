//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREAM_SALSA20_HPP
#define CRYPTO3_STREAM_SALSA20_HPP

#include <nil/crypto3/stream/detail/salsa20/salsa20_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
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

                void process(key_schedule_type &schedule, const block_type &block) {
                    while (length >= m_buffer.size() - m_position) {
                        xor_buf(out, in, &m_buffer[m_position], m_buffer.size() - m_position);
                        length -= (m_buffer.size() - m_position);
                        in += (m_buffer.size() - m_position);
                        out += (m_buffer.size() - m_position);
                        policy_type::salsa_core(m_buffer.data(), schedule);

                        ++schedule[8];
                        schedule[9] += (schedule[8] == 0);

                        m_position = 0;
                    }

                    xor_buf(out, in, &m_buffer[m_position], length);

                    m_position += length;
                }

                void seek(key_schedule_type &schedule, const block_type &block) {
                    // Find the block offset
                    const uint64_t counter = offset / 64;
                    uint8_t counter8[8];
                    store_le(counter, counter8);

                    schedule[8] = load_le<uint32_t>(counter8, 0);
                    schedule[9] += load_le<uint32_t>(counter8, 1);

                    salsa_core(m_buffer.data(), schedule);

                    ++schedule[8];
                    schedule[9] += (schedule[8] == 0);

                    m_position = offset % 64;
                }
            };
        }    // namespace stream
    }        // namespace crypto3
}    // namespace nil

#endif
