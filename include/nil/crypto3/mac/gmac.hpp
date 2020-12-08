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

#ifndef CRYPTO3_MAC_GMAC_HPP
#define CRYPTO3_MAC_GMAC_HPP

#include <nil/crypto3/mac/detail/gmac/gmac_policy.hpp>
#include <nil/crypto3/mac/detail/gmac/accumulator.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            class ghash;
        }
        namespace mac {
            /*!
             * @brief GMAC
             * @tparam BlockCipher
             * @tparam Hash
             * @ingroup mac
             */
            template<typename BlockCipher, typename Hash = hashes::ghash>
            class gmac {
                typedef detail::gmac_policy<BlockCipher, Hash> policy_type;

                typedef typename policy_type::byte_type byte_type;
                typedef typename policy_type::word_type word_type;

            public:
                typedef typename policy_type::cipher_type cipher_type;
                typedef typename policy_type::hash_type hash_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                gmac(const cipher_type &cipher, const hash_type &hash) : cipher(cipher), hash(hash) {
                }

                gmac(const key_type &key) : cipher(key) {
                }

                void begin_message(const block_type &block) {
                    secure_vector<uint8_t> y0(GCM_BS);

                    if (nonce_len == 12) {
                        copy_mem(y0.data(), nonce, nonce_len);
                        y0[GCM_BS - 1] = 1;
                    } else {
                        hash->ghash_update(y0, nonce, nonce_len);
                        hash->add_final_block(y0, 0, nonce_len);
                    }

                    secure_vector<uint8_t> m_enc_y0(GCM_BS);
                    cipher->encrypt(y0.data(), m_enc_y0.data());
                    hash->start(m_enc_y0.data(), m_enc_y0.size());
                    m_initialized = true;
                }

                void process_block(const block_type &block) {
                    if (m_aad_buf_pos > 0) {
                        const size_t taking = std::min(GCM_BS - m_aad_buf_pos, size);
                        copy_mem(&m_aad_buf[m_aad_buf_pos], input, taking);
                        m_aad_buf_pos += taking;
                        input += taking;
                        size -= taking;

                        if (m_aad_buf_pos == GCM_BS) {
                            hash->update_associated_data(m_aad_buf.data(), GCM_BS);
                            m_aad_buf_pos = 0;
                        }
                    }

                    const size_t left_over = size % GCM_BS;
                    const size_t full_blocks = size - left_over;
                    hash->update_associated_data(input, full_blocks);
                    input += full_blocks;

                    if (left_over > 0) {
                        copy_mem(&m_aad_buf[m_aad_buf_pos], input, left_over);
                        m_aad_buf_pos += left_over;
                    }
                }

                void end_message(const block_type &block) {
                    // This ensures the GMAC computation has been initialized with a fresh
                    // nonce. The aim of this check is to prevent developers from re-using
                    // nonces (and potential nonce-reuse attacks).
                    if (!m_initialized) {
                        throw Invalid_State("GMAC was not used with a fresh nonce");
                    }

                    // process the rest of the aad buffer. Even if it is a partial block only
                    // ghash_update will process it properly.
                    if (m_aad_buf_pos > 0) {
                        m_ghash->update_associated_data(m_aad_buf.data(), m_aad_buf_pos);
                    }
                    secure_vector<uint8_t> result = m_ghash->final();
                    copy_mem(mac, result.data(), result.size());
                    clear();
                }

            protected:
                void schedule_key(const key_type &key) {
                }

                cipher_type cipher;
                hash_type hash;
            };
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil
#endif
