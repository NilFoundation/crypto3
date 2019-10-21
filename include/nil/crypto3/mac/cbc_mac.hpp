//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_CBC_MAC_HPP
#define CRYPTO3_MAC_CBC_MAC_HPP

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>

#include <nil/crypto3/mac/detail/cbc_mac/cbc_mac_policy.hpp>
#include <nil/crypto3/mac/detail/cbc_mac/accumulator.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            /*!
             * @brief CBC-MAC
             * @tparam BlockCipher
             */
            template<typename BlockCipher>
            class cbc_mac {
                typedef detail::cbc_mac_policy<BlockCipher> policy_type;

            public:
                typedef BlockCipher block_cipher_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t state_bits = policy_type::state_bits;
                constexpr static const std::size_t state_words = policy_type::state_words;
                typedef typename policy_type::state_type state_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                cbc_mac(const block_cipher_type &cipher) : cipher(cipher) {
                }

                cbc_mac(const key_type &key) : cipher(key) {
                }

                inline void begin_message(state_type &state, const block_type &block) {
                    size_t xored = std::min(output_length() - m_position, length);
                    xor_buf(&m_state[m_position], input, xored);
                    m_position += xored;

                    if (m_position < output_length()) {
                        return;
                    }

                    m_cipher->encrypt(m_state);
                    input += xored;
                    length -= xored;
                    while (length >= output_length()) {
                        xor_buf(m_state, input, output_length());
                        m_cipher->encrypt(m_state);
                        input += output_length();
                        length -= output_length();
                    }

                    xor_buf(m_state, input, length);
                    m_position = length;
                }

                void process_block(state_type &state, const block_type &block) {
                    size_t xored = std::min(output_length() - m_position, length);
                    xor_buf(&m_state[m_position], input, xored);
                    m_position += xored;

                    if (m_position < output_length()) {
                        return;
                    }

                    m_cipher->encrypt(m_state);
                    input += xored;
                    length -= xored;
                    while (length >= output_length()) {
                        xor_buf(m_state, input, output_length());
                        m_cipher->encrypt(m_state);
                        input += output_length();
                        length -= output_length();
                    }

                    xor_buf(m_state, input, length);
                    m_position = length;
                }

                void end_message(digest_type &digest, const state_type &state, const block_type &block) {
                    if (m_position) {
                        m_cipher->encrypt(m_state);
                    }

                    copy_mem(mac, m_state.data(), m_state.size());
                    zeroise(m_state);
                    m_position = 0;
                }

            protected:
                void schedule_key(const key_type &key) {

                }

                block_cipher_type cipher;
            };
        }    // namespace mac
    }    // namespace crypto3
}    // namespace nil

#endif
