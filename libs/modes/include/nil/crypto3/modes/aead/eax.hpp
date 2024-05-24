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

#ifndef CRYPTO3_MODE_AEAD_EAX_HPP
#define CRYPTO3_MODE_AEAD_EAX_HPP

#include <nil/crypto3/modes/aead/aead.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            template<typename BlockCipher>
            struct cmac;
        }

        namespace stream {
            template<typename BlockCipher, std::size_t CtrBits = BlockCipher::block_bits>
            class ctr;
        }
        namespace block {
            namespace modes {
                namespace detail {
                    template<typename Cipher, typename Padding, std::size_t TagBits, typename MessageAuthenticationCode,
                             typename StreamCipher, template<typename> class Allocator = std::allocator>
                    struct eax_policy {
                        typedef Cipher cipher_type;
                        typedef Padding padding_type;
                        typedef StreamCipher stream_cipher_type;
                        typedef MessageAuthenticationCode mac_type;

                        constexpr static const std::size_t tag_bits = TagBits;
                        constexpr static const std::size_t mac_digest_bits = mac_type::digest_bits;
                        BOOST_STATIC_ASSERT(tag_bits >= CHAR_BIT && tag_bits <= mac_digest_bits);

                        constexpr static const std::size_t block_bits = cipher_type::block_bits;
                        constexpr static const std::size_t block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        BOOST_STATIC_ASSERT(block_bits == 128);

                        typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>>
                            associated_data_type;
                        typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>> nonce_type;

                        static void eax_prf(uint8_t tag, size_t block_size, mac_type &mac, const uint8_t in[],
                                            size_t length) {
                            for (size_t i = 0; i != block_size - 1; ++i) {
                                mac.update(0);
                            }
                            mac.update(tag);
                            mac.update(in, length);
                            return mac.final();
                        }

                        static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            m_nonce_mac = eax_prf(0, block_size(), *m_cmac, nonce, nonce_len);

                            m_ctr->set_iv(m_nonce_mac.data(), m_nonce_mac.size());

                            for (size_t i = 0; i != block_size() - 1; ++i) {
                                m_cmac->update(0);
                            }
                            m_cmac->update(2);

                            return cipher.encrypt(block);
                        }
                    };

                    template<typename Cipher, typename Padding, std::size_t TagBits, typename MessageAuthenticationCode,
                             typename StreamCipher, template<typename> class Allocator = std::allocator>
                    struct eax_encryption_policy
                        : public eax_policy<Cipher, Padding, TagBits, MessageAuthenticationCode, StreamCipher,
                                            Allocator> {
                        typedef eax_policy<Cipher, Padding, TagBits, MessageAuthenticationCode, StreamCipher, Allocator>
                            policy_type;
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;
                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::mac_type mac_type;

                        typedef typename policy_type::associated_data_type associated_data_type;
                        typedef typename policy_type::nonce_type nonce_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            m_ctr->cipher(buf, buf, sz);
                            m_cmac->update(buf, sz);

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            update(buffer, offset);

                            secure_vector<uint8_t> data_mac = m_cmac->final();
                            xor_buf(data_mac, m_nonce_mac, data_mac.size());

                            if (m_ad_mac.empty()) {
                                m_ad_mac = eax_prf(1, block_size(), *m_cmac, nullptr, 0);
                            }

                            xor_buf(data_mac, m_ad_mac, data_mac.size());

                            buffer += std::make_pair(data_mac.data(), tag_size());

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding, std::size_t TagBits, typename MessageAuthenticationCode,
                             typename StreamCipher, template<typename> class Allocator = std::allocator>
                    struct eax_decryption_policy
                        : public eax_policy<Cipher, Padding, TagBits, MessageAuthenticationCode, StreamCipher,
                                            Allocator> {
                        typedef eax_policy<Cipher, Padding, TagBits, MessageAuthenticationCode, StreamCipher, Allocator>
                            policy_type;
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;
                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::mac_type mac_type;

                        typedef typename policy_type::associated_data_type associated_data_type;
                        typedef typename policy_type::nonce_type nonce_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            m_cmac->update(buf, sz);
                            m_ctr->cipher(buf, buf, sz);

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};
                            BOOST_ASSERT_MSG(buffer.size() >= offset, "Offset is sane");
                            const size_t sz = buffer.size() - offset;
                            uint8_t *buf = buffer.data() + offset;

                            BOOST_ASSERT_MSG(sz >= tag_size(), "Have the tag as part of final input");

                            const size_t remaining = sz - tag_size();

                            if (remaining) {
                                m_cmac->update(buf, remaining);
                                m_ctr->cipher(buf, buf, remaining);
                            }

                            const uint8_t *included_tag = &buf[remaining];

                            secure_vector<uint8_t> mac = m_cmac->final();
                            mac ^= m_nonce_mac;

                            if (m_ad_mac.empty()) {
                                m_ad_mac = eax_prf(1, block_size(), *m_cmac, nullptr, 0);
                            }

                            mac ^= m_ad_mac;

                            if (!constant_time_compare(mac.data(), included_tag, tag_size())) {
                                throw integrity_failure("EAX tag check failed");
                            }

                            buffer.resize(offset + remaining);
                            return result;
                        }
                    };

                    template<typename Policy>
                    class eax {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;
                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::mac_type mac_type;

                        typedef typename cipher_type::key_type key_type;
                        typedef typename policy_type::associated_data_type associated_data_type;
                        typedef typename policy_type::nonce_type nonce_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        template<typename AssociatedDataContainer>
                        eax(const cipher_type &cipher, const stream_cipher_type &stream_cipher, const mac_type &mac,
                            const AssociatedDataContainer &associated_data) :
                            cipher(cipher) {
                            schedule_associated_data(associated_data);
                        }

                        template<typename AssociatedDataContainer>
                        eax(const key_type &key, const AssociatedDataContainer &associated_data) :
                            cipher(key), stream_cipher(key), mac(key) {
                            schedule_associated_data(associated_data);
                        }

                        inline block_type begin_message(const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext, ad);
                        }

                        inline block_type process_block(const block_type &plaintext) {
                            return policy_type::process_block(cipher, plaintext, ad);
                        }

                        inline block_type end_message(const block_type &plaintext) {
                            return policy_type::end_message(cipher, plaintext, ad);
                        }

                        inline static std::size_t required_output_size(std::size_t inputlen) {
                            return padding_type::required_output_size(inputlen);
                        }

                    protected:
                        template<typename AssociatedDataContainer>
                        inline void schedule_associated_data(const AssociatedDataContainer &iad) {
                            policy_type::eax_prf(1, block_size(), *cmac, ad, length);
                        }

                        associated_data_type ad;

                        cipher_type cipher;
                        stream_cipher_type stream_cipher;
                        mac_type mac;
                    };
                }    // namespace detail

                /*!
                 * @brief Interface for AEAD (Authenticated Encryption with Associated Data)
                 * modes. These modes provide both encryption and message
                 * authentication, and can authenticate additional per-message data
                 * which is not included in the ciphertext (for instance a sequence
                 * number).
                 *
                 * @tparam BlockCipher
                 * @tparam Padding
                 * @tparam CiphertextStealingMode
                 */
                template<typename BlockCipher, template<typename> class Padding,
                         std::size_t TagBits = BlockCipher::block_bits,
                         typename MessageAuthenticationCode = mac::cmac<BlockCipher>,
                         typename StreamCipher = stream::ctr<BlockCipher>,
                         template<typename> class Allocator = std::allocator>
                struct eax {
                    typedef BlockCipher cipher_type;
                    typedef Padding<BlockCipher> padding_type;
                    typedef StreamCipher stream_cipher_type;
                    typedef MessageAuthenticationCode message_authentication_code_type;

                    typedef detail::eax_encryption_policy<cipher_type, padding_type, TagBits,
                                                          message_authentication_code_type, stream_cipher_type,
                                                          Allocator>
                        encryption_policy;
                    typedef detail::eax_decryption_policy<cipher_type, padding_type, TagBits,
                                                          message_authentication_code_type, stream_cipher_type,
                                                          Allocator>
                        decryption_policy;

                    template<template<typename, typename, std::size_t, typename, typename, template<typename> class>
                             class Policy>
                    struct bind {
                        typedef detail::eax<Policy<cipher_type, padding_type, TagBits, MessageAuthenticationCode,
                                                   StreamCipher, Allocator>>
                            type;
                    };
                };
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif
