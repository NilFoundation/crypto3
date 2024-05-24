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

#ifndef CRYPTO3_MODE_AEAD_GCM_HPP
#define CRYPTO3_MODE_AEAD_GCM_HPP

#include <nil/crypto3/modes/aead/aead.hpp>

#include <nil/crypto3/hash/ghash.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            struct ghash;
        }
        namespace stream {
            template<typename BlockCipher>
            class ctr;
        }
        namespace block {
            namespace modes {
                namespace detail {
                    template<typename Cipher, std::size_t TagBits, typename Padding, typename StreamCipher,
                             typename Hash, template<typename> class Allocator>
                    struct gcm_policy {
                        typedef Cipher cipher_type;
                        typedef Padding padding_type;
                        typedef StreamCipher stream_cipher_type;
                        typedef Hash hash_type;

                        template<typename T>
                        using allocator_type = Allocator<T>;

                        constexpr static const std::size_t tag_bits = TagBits;

                        BOOST_STATIC_ASSERT(tag_bits >= 12 * CHAR_BIT && tag_bits <= 16 * CHAR_BIT);

                        constexpr static const std::size_t block_bits = cipher_type::block_bits;
                        constexpr static const std::size_t block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        BOOST_STATIC_ASSERT(block_bits == 128);

                        typedef std::vector<boost::uint_t<CHAR_BIT>, allocator_type<boost::uint_t<CHAR_BIT>>>
                            associated_data_type;
                        typedef std::vector<boost::uint_t<CHAR_BIT>, allocator_type<boost::uint_t<CHAR_BIT>>>
                            nonce_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            // any size is valid for GCM nonce

                            secure_vector<uint8_t> y0(GCM_BS);

                            if (nonce_len == 12) {
                                copy_mem(y0.data(), nonce, nonce_len);
                                y0[15] = 1;
                            } else {
                                y0 = m_ghash->nonce_hash(nonce, nonce_len);
                            }

                            m_ctr->set_iv(y0.data(), y0.size());

                            zeroise(y0);
                            m_ctr->encipher(y0);

                            m_ghash->start(y0.data(), y0.size());

                            return cipher.encrypt(block);
                        }
                    };

                    template<typename Cipher, std::size_t TagBits, typename Padding, typename StreamCipher,
                             typename Hash, template<typename> class Allocator>
                    class gcm_encryption_policy
                        : public gcm_policy<Cipher, TagBits, Padding, StreamCipher, Hash, Allocator> {
                        typedef gcm_policy<Cipher, TagBits, Padding, StreamCipher, Hash, Allocator> policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;
                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::hash_type hash_type;

                        typedef typename policy_type::associated_data_type associated_data_type;
                        typedef typename policy_type::nonce_type nonce_type;

                        constexpr static const std::size_t tag_bits = policy_type::tag_bits;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            CRYPTO3_ARG_CHECK(sz % update_granularity() == 0);
                            m_ctr->cipher(buf, buf, sz);
                            m_ghash->update(buf, sz);

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            CRYPTO3_ARG_CHECK(offset <= buffer.size());
                            const size_t sz = buffer.size() - offset;
                            uint8_t *buf = buffer.data() + offset;

                            m_ctr->cipher(buf, buf, sz);
                            m_ghash->update(buf, sz);
                            auto mac = m_ghash->final();
                            buffer += std::make_pair(mac.data(), tag_size());

                            return result;
                        }
                    };

                    template<typename Cipher, std::size_t TagBits, typename Padding, typename StreamCipher,
                             typename Hash, template<typename> class Allocator>
                    struct gcm_decryption_policy
                        : public gcm_policy<Cipher, TagBits, Padding, StreamCipher, Hash, Allocator> {
                        typedef gcm_policy<Cipher, TagBits, Padding, StreamCipher, Hash, Allocator> policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;
                        typedef typename policy_type::stream_cipher_type stream_cipher_type;
                        typedef typename policy_type::hash_type hash_type;

                        typedef typename policy_type::associated_data_type associated_data_type;
                        typedef typename policy_type::nonce_type nonce_type;

                        constexpr static const std::size_t tag_bits = policy_type::tag_bits;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename policy_type::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            CRYPTO3_ARG_CHECK(sz % update_granularity() == 0);
                            m_ghash->update(buf, sz);
                            m_ctr->cipher(buf, buf, sz);

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            CRYPTO3_ARG_CHECK(offset <= buffer.size());
                            const size_t sz = buffer.size() - offset;
                            uint8_t *buf = buffer.data() + offset;

                            if (sz < tag_size()) {
                                throw Exception("Insufficient input for GCM decryption, tag missing");
                            }

                            const size_t remaining = sz - tag_size();

                            // handle any final input before the tag
                            if (remaining) {
                                m_ghash->update(buf, remaining);
                                m_ctr->cipher(buf, buf, remaining);
                            }

                            auto mac = m_ghash->final();

                            const uint8_t *included_tag = &buffer[remaining + offset];

                            if (!constant_time_compare(mac.data(), included_tag, tag_size())) {
                                throw integrity_failure("GCM tag check failed");
                            }

                            buffer.resize(offset + remaining);

                            return result;
                        }
                    };

                    template<typename Policy>
                    class gcm {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename cipher_type::key_type key_type;
                        typedef typename policy_type::associated_data_type associated_data_type;
                        typedef typename policy_type::nonce_type nonce_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        template<typename AssociatedDataContainer>
                        gcm(const cipher_type &cipher, const AssociatedDataContainer &associated_data) :
                            cipher(cipher) {
                            schedule_associated_data(associated_data);
                        }

                        template<typename AssociatedDataContainer>
                        gcm(const key_type &key, const AssociatedDataContainer &associated_data) : cipher(key) {

                            m_ctr->set_key(key, keylen);

                            const std::vector<uint8_t> zeros(GCM_BS);
                            m_ctr->set_iv(zeros.data(), zeros.size());

                            secure_vector<uint8_t> H(GCM_BS);
                            m_ctr->encipher(H);
                            m_ghash->set_key(H);

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
                            m_ghash->set_associated_data(ad, ad_len);
                        }

                        associated_data_type ad;
                        nonce_type nonce;

                        cipher_type cipher;
                    };
                }    // namespace detail

                /*!
                 * @brief Galois/Counter Mode
                 *
                 * @tparam BlockCipher
                 * @tparam Padding
                 * @tparam StreamCipher
                 * @tparam Hash
                 */
                template<typename BlockCipher, template<typename> class Padding, std::size_t TagBits = 16,

                         typename Hash = hashes::ghash, typename StreamCipher = stream::ctr<BlockCipher>,
                         template<typename> class Allocator = std::allocator>
                struct gcm {
                    typedef BlockCipher cipher_type;
                    typedef Padding<BlockCipher> padding_type;
                    typedef StreamCipher stream_cipher_type;
                    typedef Hash hash_type;

                    template<typename T>
                    using allocator_type = Allocator<T>;

                    typedef detail::gcm_encryption_policy<cipher_type, TagBits, padding_type, stream_cipher_type,
                                                          hash_type, allocator_type>
                        encryption_policy;
                    typedef detail::gcm_decryption_policy<cipher_type, TagBits, padding_type, stream_cipher_type,
                                                          hash_type, allocator_type>
                        decryption_policy;

                    template<template<typename, std::size_t, typename, typename, typename, template<typename> class>
                             class Policy>
                    struct bind {
                        typedef detail::gcm<
                            Policy<cipher_type, TagBits, padding_type, stream_cipher_type, hash_type, allocator_type>>
                            type;
                    };
                };
            }    // namespace modes
        }        // namespace block
    }    // namespace crypto3
}    // namespace nil

#endif
