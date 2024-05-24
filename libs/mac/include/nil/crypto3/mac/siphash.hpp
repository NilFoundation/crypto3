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

#ifndef CRYPTO3_MAC_SIPHASH_HPP
#define CRYPTO3_MAC_SIPHASH_HPP

#include <nil/crypto3/mac/detail/siphash/siphash_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            /*!
             * @brief
             * @tparam Rounds
             * @tparam FinalRounds
             * @ingroup mac
             */
            template<std::size_t Rounds = 2, std::size_t FinalRounds = 4>
            class siphash {
                typedef detail::siphash_functions<Rounds, FinalRounds> policy_type;

            public:
                constexpr static const std::size_t rounds = policy_type::rounds;
                constexpr static const std::size_t final_rounds = policy_type::final_rounds;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t key_schedule_bits = policy_type::key_schedule_bits;
                constexpr static const std::size_t key_schedule_words = policy_type::key_schedule_words;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                siphash(key_schedule_type &schedule, const key_type &key) {
                    schedule_key(schedule, key);
                }

                inline static void begin_message(key_schedule_type &schedule) {
                    return process(schedule);
                }

                inline static void process(key_schedule_type &schdeule) {
                    // SipHash counts the message length mod 256
                    m_words += static_cast<uint8_t>(length);

                    if (m_mbuf_pos) {
                        while (length && m_mbuf_pos != 8) {
                            m_mbuf = (m_mbuf >> 8) | (static_cast<uint64_t>(input[0]) << 56);
                            ++m_mbuf_pos;
                            ++input;
                            length--;
                        }

                        if (m_mbuf_pos == 8) {
                            SipRounds(m_mbuf, m_V, m_C);
                            m_mbuf_pos = 0;
                            m_mbuf = 0;
                        }
                    }

                    while (length >= 8) {
                        SipRounds(load_le<uint64_t>(input, 0), schdeule, m_C);
                        input += 8;
                        length -= 8;
                    }

                    for (size_t i = 0; i != length; ++i) {
                        m_mbuf = (m_mbuf >> 8) | (static_cast<uint64_t>(input[i]) << 56);
                        m_mbuf_pos++;
                    }
                }

                inline static void end_message(key_schedule_type &schdeule) {
                    if (m_mbuf_pos == 0) {
                        m_mbuf = (static_cast<uint64_t>(m_words) << 56);
                    } else if (m_mbuf_pos < 8) {
                        m_mbuf = (m_mbuf >> (64 - m_mbuf_pos * 8)) | (static_cast<uint64_t>(m_words) << 56);
                    }

                    SipRounds(m_mbuf, m_V, m_C);

                    schdeule[2] ^= 0xFF;
                    SipRounds(0, schdeule, m_D);

                    const word_type X = schdeule[0] ^ schdeule[1] ^ schdeule[2] ^ schdeule[3];

                    store_le(X, mac);

                    clear();
                }

            protected:
                inline void schedule_key(key_schedule_type &schedule, const key_type &key) {
                    const word_type K0 = boost::endian::native_to_little(key[0]);
                    const word_type K1 = boost::endian::native_to_little(key[1]);

                    schedule[0] = K0 ^ 0x736F6D6570736575;
                    schedule[1] = K1 ^ 0x646F72616E646F6D;
                    schedule[2] = K0 ^ 0x6C7967656E657261;
                    schedule[3] = K1 ^ 0x7465646279746573;
                }
            };
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil

#endif
