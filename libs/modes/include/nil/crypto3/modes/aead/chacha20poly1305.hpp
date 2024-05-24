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

#ifndef CRYPTO3_MODE_AEAD_CHACHA20_POLY1305_HPP
#define CRYPTO3_MODE_AEAD_CHACHA20_POLY1305_HPP

#include <nil/crypto3/modes/aead/aead.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            class poly_1305;
        }
        namespace stream {
            template<std::size_t IVBits = 64, std::size_t KeyBits = 128, std::size_t Rounds = 20>
            class chacha;

            namespace modes {
                namespace detail {
                    template<typename Padding,
                             std::size_t NonceBits,
                             std::size_t TagBits,
                             typename StreamCipher,
                             typename MessageAuthenticationCode,
                             template<typename>
                             class Allocator>
                    struct chacha20poly1305_policy {
                        typedef std::size_t size_type;

                        typedef StreamCipher stream_cipher_type;
                        typedef MessageAuthenticationCode mac_type;
                        typedef Padding padding_type;

                        constexpr static const std::size_t nonce_bits = NonceBits;
                        constexpr static const std::size_t nonce_size = nonce_bits / CHAR_BIT;
                        typedef std::array<std::uint8_t, nonce_size> nonce_type;

                        BOOST_STATIC_ASSERT(nonce_bits == 8 * CHAR_BIT || nonce_bits == 12 * CHAR_BIT);

                        typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>>
                            associated_data_type;
                    };

                    template<typename Padding,
                             std::size_t NonceBits,
                             std::size_t TagBits,
                             typename StreamCipher,
                             typename MessageAuthenticationCode,
                             template<typename>
                             class Allocator>
                    struct chacha20poly1305_encryption_policy
                        : public chacha20poly1305_policy<Padding,
                                                         NonceBits,
                                                         TagBits,
                                                         StreamCipher,
                                                         MessageAuthenticationCode,
                                                         Allocator> {
                        typedef chacha20poly1305_policy<Padding,
                                                        NonceBits,
                                                        TagBits,
                                                        StreamCipher,
                                                        MessageAuthenticationCode,
                                                        Allocator>
                            policy_type;

                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename policy_type::associated_data_type associated_data_type;
                        typedef typename policy_type::nonce_type nonce_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const stream_cipher_type &cipher,
                                                               const block_type &plaintext) {
                            block_type block = {0};

                            m_ctext_len = 0;
                            m_nonce_len = nonce_len;

                            m_chacha->set_iv(nonce, nonce_len);

                            secure_vector<uint8_t> init(64); // zeros
                            m_chacha->encrypt(init);

                            m_poly1305->set_key(init.data(), 32);
                            // Remainder of output is discard

                            m_poly1305->update(m_ad);

                            if (cfrg_version()) {
                                if (m_ad.size() % 16) {
                                    const uint8_t zeros[16] = {0};
                                    m_poly1305->update(zeros, 16 - m_ad.size() % 16);
                                }
                            } else {
                                update_len(m_ad.size());
                            }

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const stream_cipher_type &cipher,
                                                               const block_type &plaintext) {
                            block_type block = {0};

                            m_chacha->cipher1(buf, sz);
                            m_poly1305->update(buf, sz); // poly1305 of ciphertext
                            m_ctext_len += sz;

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const stream_cipher_type &cipher,
                                                             const block_type &plaintext) {
                            block_type result = {0};

                            update(buffer, offset);
                            if (cfrg_version()) {
                                if (m_ctext_len % 16) {
                                    const uint8_t zeros[16] = {0};
                                    m_poly1305->update(zeros, 16 - m_ctext_len % 16);
                                }
                                update_len(m_ad.size());
                            }
                            update_len(m_ctext_len);

                            const secure_vector<uint8_t> mac = m_poly1305->final();
                            buffer += std::make_pair(mac.data(), tag_size());
                            m_ctext_len = 0;

                            return result;
                        }
                    };

                    template<typename Padding,
                             std::size_t NonceBits,
                             std::size_t TagBits,
                             typename StreamCipher,
                             typename MessageAuthenticationCode,
                             template<typename>
                             class Allocator>
                    struct chacha20poly1305_decryption_policy
                        : public chacha20poly1305_policy<Padding,
                                                         NonceBits,
                                                         TagBits,
                                                         StreamCipher,
                                                         MessageAuthenticationCode,
                                                         Allocator> {
                        typedef chacha20poly1305_policy<Padding,
                                                        NonceBits,
                                                        TagBits,
                                                        StreamCipher,
                                                        MessageAuthenticationCode,
                                                        Allocator>
                            policy_type;

                        typedef typename policy_type::stream_cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename policy_type::associated_data_type associated_data_type;
                        typedef typename policy_type::nonce_type nonce_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            m_ctext_len = 0;
                            m_nonce_len = nonce_len;

                            m_chacha->set_iv(nonce, nonce_len);

                            secure_vector<uint8_t> init(64); // zeros
                            m_chacha->encrypt(init);

                            m_poly1305->set_key(init.data(), 32);
                            // Remainder of output is discard

                            m_poly1305->update(m_ad);

                            if (cfrg_version()) {
                                if (m_ad.size() % 16) {
                                    const uint8_t zeros[16] = {0};
                                    m_poly1305->update(zeros, 16 - m_ad.size() % 16);
                                }
                            } else {
                                update_len(m_ad.size());
                            }

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            m_poly1305->update(buf, sz); // poly1305 of ciphertext
                            m_chacha->cipher1(buf, sz);
                            m_ctext_len += sz;

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
                                m_poly1305->update(buf, remaining); // poly1305 of ciphertext
                                m_chacha->cipher1(buf, remaining);
                                m_ctext_len += remaining;
                            }

                            if (cfrg_version()) {
                                if (m_ctext_len % 16) {
                                    const uint8_t zeros[16] = {0};
                                    m_poly1305->update(zeros, 16 - m_ctext_len % 16);
                                }
                                update_len(m_ad.size());
                            }

                            update_len(m_ctext_len);
                            const secure_vector<uint8_t> mac = m_poly1305->final();

                            const uint8_t *included_tag = &buf[remaining];

                            m_ctext_len = 0;

                            if (!constant_time_compare(mac.data(), included_tag, tag_size())) {
                                throw integrity_failure("ChaCha20Poly1305 tag check failed");
                            }
                            buffer.resize(offset + remaining);

                            return result;
                        }
                    };

                    template<typename Policy>
                    class chacha20poly1305 {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::padding_type padding_type;
                        typedef typename policy_type::mac_type mac_type;

                        typedef typename stream_cipher_type::key_type key_type;
                        typedef typename policy_type::associated_data_type associated_data_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename stream_cipher_type::block_type block_type;

                        template<typename AssociatedDataContainer>
                        chacha20poly1305(const stream_cipher_type &cipher,
                                         const AssociatedDataContainer &associated_data) :
                            cipher(cipher) {
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
                        }

                        associated_data_type ad;

                        stream_cipher_type cipher;
                        mac_type mac;
                    };
                }    // namespace detail

                /*!
                 * @brief See draft-irtf-cfrg-chacha20-poly1305-03 for specification
                 * If a nonce of 64 bits is used the older version described in
                 * draft-agl-tls-chacha20poly1305-04 is used instead.
                 *
                 * @tparam StreamCipher
                 * @tparam Padding
                 * @tparam CiphertextStealingMode
                 */
                template<template<typename> class Padding,
                         std::size_t NonceBits,
                         std::size_t TagBits = 16 * CHAR_BIT,
                         typename StreamCipher = stream::chacha<>,
                         typename MessageAuthenticationCode = mac::poly_1305,
                         template<typename> class Allocator = std::allocator>
                struct chacha20poly1305 {
                    typedef StreamCipher stream_cipher_type;
                    typedef MessageAuthenticationCode mac_type;
                    typedef Padding<StreamCipher> padding_type;

                    typedef detail::chacha20poly1305_encryption_policy<padding_type,
                                                                       NonceBits,
                                                                       TagBits,
                                                                       stream_cipher_type,
                                                                       mac_type,
                                                                       Allocator>
                        encryption_policy;
                    typedef detail::chacha20poly1305_decryption_policy<padding_type,
                                                                       NonceBits,
                                                                       TagBits,
                                                                       stream_cipher_type,
                                                                       mac_type,
                                                                       Allocator>
                        decryption_policy;

                    template<template<typename, typename, std::size_t, std::size_t, template<typename> class>
                             class Policy>
                    struct bind {
                        typedef detail::chacha20poly1305<
                            Policy<stream_cipher_type, padding_type, NonceBits, TagBits, Allocator>>
                            type;
                    };
                };
            }    // namespace modes
        }        // namespace stream
    }    // namespace crypto3
}    // namespace nil

#endif
