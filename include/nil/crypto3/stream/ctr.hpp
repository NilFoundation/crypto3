//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_STREAM_CTR_HPP
#define CRYPTO3_STREAM_CTR_HPP

#include <nil/crypto3/stream/detail/ctr/ctr_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace stream {
            /*!
             * @brief CTR-BE (Counter mode, big-endian). Converts BlockCipher to StreamCipher.
             * @tparam BlockCipher
             * @ingroup stream
             */
            template<typename BlockCipher, std::size_t CtrBits = BlockCipher::block_bits>
            class ctr {
                typedef detail::ctr_functions<BlockCipher, CtrBits> policy_type;

            public:
                typedef typename policy_type::cipher_type cipher_type;

                constexpr static const std::size_t rounds = policy_type::rounds;

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

                ctr(const key_type &key, const iv_type &iv = iv_type()) : cipher(key) {

                }

                void process(const block_type &block) {
                    const uint8_t *pad_bits = &m_pad[0];
                    const size_t pad_size = m_pad.size();

                    if (m_pad_pos > 0) {
                        const size_t avail = pad_size - m_pad_pos;
                        const size_t take = std::min(length, avail);
                        xor_buf(out, in, pad_bits + m_pad_pos, take);
                        length -= take;
                        in += take;
                        out += take;
                        m_pad_pos += take;

                        if (take == avail) {
                            add_counter(m_ctr_blocks);
                            m_cipher->encrypt_n(m_counter.data(), m_pad.data(), m_ctr_blocks);
                            m_pad_pos = 0;
                        }
                    }

                    while (length >= pad_size) {
                        xor_buf(out, in, pad_bits, pad_size);
                        length -= pad_size;
                        in += pad_size;
                        out += pad_size;

                        add_counter(m_ctr_blocks);
                        m_cipher->encrypt_n(m_counter.data(), m_pad.data(), m_ctr_blocks);
                    }

                    xor_buf(out, in, pad_bits, length);
                    m_pad_pos += length;
                }

                void seek(uint64_t offset) {
                    const uint64_t base_counter = m_ctr_blocks * (offset / m_counter.size());

                    zeroise(m_counter);
                    buffer_insert(m_counter, 0, m_iv);

                    const size_t BS = m_block_size;

                    // Set m_counter blocks to IV, IV + 1, ... IV + n

                    if (m_ctr_size == 4 && BS >= 8) {
                        const uint32_t low32 = load_be<uint32_t>(&m_counter[BS - 4], 0);

                        if (m_ctr_blocks >= 4 && is_power_of_2(m_ctr_blocks)) {
                            size_t written = 1;
                            while (written < m_ctr_blocks) {
                                copy_mem(&m_counter[written * BS], &m_counter[0], BS * written);
                                written *= 2;
                            }
                        } else {
                            for (size_t i = 1; i != m_ctr_blocks; ++i) {
                                copy_mem(&m_counter[i * BS], &m_counter[0], BS - 4);
                            }
                        }

                        for (size_t i = 1; i != m_ctr_blocks; ++i) {
                            const uint32_t c = static_cast<uint32_t>(low32 + i);
                            store_be(c, &m_counter[(BS - 4) + i * BS]);
                        }
                    } else {
                        // do everything sequentially:
                        for (size_t i = 1; i != m_ctr_blocks; ++i) {
                            buffer_insert(m_counter, i * BS, &m_counter[(i - 1) * BS], BS);

                            for (size_t j = 0; j != m_ctr_size; ++j)
                                if (++m_counter[i * BS + (BS - 1 - j)])
                                    break;
                        }
                    }

                    if (base_counter > 0)
                        add_counter(base_counter);

                    m_cipher->encrypt_n(m_counter.data(), m_pad.data(), m_ctr_blocks);
                    m_pad_pos = offset % m_counter.size();
                }

            protected:
                cipher_type cipher;
            };
        }    // namespace stream
    }        // namespace crypto3
}    // namespace nil

#endif
