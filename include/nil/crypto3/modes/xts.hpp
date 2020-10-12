//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MODE_XTS_HPP
#define CRYPTO3_MODE_XTS_HPP

#include <memory>

#include <nil/crypto3/modes/cts.hpp>

#include <nil/crypto3/block/cipher.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                namespace detail {
                    template<typename Cipher, typename Padding, template<typename> class Allocator = std::allocator>
                    struct xts_policy {
                        typedef Cipher cipher_type;
                        typedef Padding padding_type;

                        constexpr static const std::size_t block_bits = cipher_type::block_bits;
                        constexpr static const std::size_t block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        constexpr static const std::size_t key_bits = cipher_type::key_bits;
                        constexpr static const std::size_t key_words = cipher_type::key_words;
                        typedef typename cipher_type::key_type key_type;

                        static void update_tweak(const cipher_type &tweak_cipher, size_t which) {
                            const size_t BS = tweak_cipher->block_size();

                            if (which > 0) {
                                poly_double_n_le(m_tweak.data(), &m_tweak[(which - 1) * BS], BS);
                            }

                            const size_t blocks_in_tweak = update_granularity() / BS;

                            for (size_t i = 1; i < blocks_in_tweak; ++i) {
                                poly_double_n_le(&m_tweak[i * BS], &m_tweak[(i - 1) * BS], BS);
                            }
                        }

                        static void schedule_key(const key_type &key) {
                            const size_t key_half = length / 2;

                            if (length % 2 == 1 || !m_cipher->valid_keylength(key_half)) {
                                throw invalid_key_length(name(), length);
                            }

                            m_cipher->set_key(key, key_half);
                            m_tweak_cipher->set_key(&key[key_half], key_half);
                        }
                    };

                    template<typename Cipher, typename Padding, typename CiphertextStealingMode>
                    struct xts_encryption_policy : public xts_policy<Cipher, Padding> {};

                    template<typename Cipher, typename Padding>
                    struct xts_encryption_policy<Cipher, Padding, cts<0, Cipher, Padding>>
                        : public xts_policy<Cipher, Padding> {
                        typedef typename xts_policy<Cipher, Padding>::size_type size_type;

                        typedef typename xts_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename xts_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = xts_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = xts_policy<Cipher, Padding>::block_words;
                        typedef typename xts_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            if (!valid_nonce_length(nonce_len)) {
                                throw invalid_iv_length(name(), nonce_len);
                            }

                            copy_mem(m_tweak.data(), nonce, nonce_len);
                            m_tweak_cipher->encrypt(m_tweak.data());

                            update_tweak(0);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            const size_t BS = cipher().block_size();

                            BOOST_ASSERT_MSG(sz % BS == 0, "Input is full blocks");
                            size_t blocks = sz / BS;

                            const size_t blocks_in_tweak = update_granularity() / BS;

                            while (blocks) {
                                const size_t to_proc = std::min(blocks, blocks_in_tweak);

                                cipher().encrypt_n_xex(buf, tweak(), to_proc);

                                buf += to_proc * BS;
                                blocks -= to_proc;

                                update_tweak(to_proc);
                            }

                            return sz;
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            BOOST_ASSERT_MSG(buffer.size() >= offset, "Offset is sane");
                            const size_t sz = buffer.size() - offset;
                            uint8_t *buf = buffer.data() + offset;

                            BOOST_ASSERT_MSG(sz >= minimum_final_size(), "Have sufficient final input in XTS encipher");

                            const size_t BS = cipher().block_size();

                            if (sz % BS == 0) {
                                update(buffer, offset);
                            } else {
                                // steal ciphertext
                                const size_t full_blocks = ((sz / BS) - 1) * BS;
                                const size_t final_bytes = sz - full_blocks;
                                BOOST_ASSERT_MSG(final_bytes > BS && final_bytes < 2 * BS,
                                                 "Left over size in expected range");

                                secure_vector<uint8_t> last(buf + full_blocks, buf + full_blocks + final_bytes);
                                buffer.resize(full_blocks + offset);
                                update(buffer, offset);

                                xor_buf(last, tweak(), BS);
                                cipher().encrypt(last);
                                xor_buf(last, tweak(), BS);

                                for (size_t i = 0; i != final_bytes - BS; ++i) {
                                    last[i] ^= last[i + BS];
                                    last[i + BS] ^= last[i];
                                    last[i] ^= last[i + BS];
                                }

                                xor_buf(last, tweak() + BS, BS);
                                cipher().encrypt(last);
                                xor_buf(last, tweak() + BS, BS);

                                buffer += last;
                            }
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct xts_encryption_policy<Cipher, Padding, cts<1, Cipher, Padding>>
                        : public xts_policy<Cipher, Padding> {
                        typedef typename xts_policy<Cipher, Padding>::size_type size_type;

                        typedef typename xts_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename xts_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = xts_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = xts_policy<Cipher, Padding>::block_words;
                        typedef typename xts_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            return {};
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct xts_encryption_policy<Cipher, Padding, cts<2, Cipher, Padding>>
                        : public xts_policy<Cipher, Padding> {
                        typedef typename xts_policy<Cipher, Padding>::size_type size_type;

                        typedef typename xts_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename xts_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = xts_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = xts_policy<Cipher, Padding>::block_words;
                        typedef typename xts_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            return {};
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct xts_encryption_policy<Cipher, Padding, cts<3, Cipher, Padding>>
                        : public xts_policy<Cipher, Padding> {
                        typedef typename xts_policy<Cipher, Padding>::size_type size_type;

                        typedef typename xts_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename xts_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = xts_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = xts_policy<Cipher, Padding>::block_words;
                        typedef typename xts_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            return {};
                        }
                    };

                    template<typename Cipher, typename Padding, typename CiphertextStealingMode>
                    struct xts_decryption_policy : public xts_policy<Cipher, Padding> {};

                    template<typename Cipher, typename Padding>
                    struct xts_decryption_policy<Cipher, Padding, cts<0, Cipher, Padding>>
                        : public xts_policy<Cipher, Padding> {
                        typedef typename xts_policy<Cipher, Padding>::size_type size_type;

                        typedef typename xts_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename xts_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = xts_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = xts_policy<Cipher, Padding>::block_words;
                        typedef typename xts_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            if (!valid_nonce_length(nonce_len)) {
                                throw invalid_iv_length(name(), nonce_len);
                            }

                            copy_mem(m_tweak.data(), nonce, nonce_len);
                            m_tweak_cipher->encrypt(m_tweak.data());

                            update_tweak(0);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            BOOST_ASSERT_MSG(buffer.size() >= offset, "Offset is sane");
                            const size_t sz = buffer.size() - offset;
                            uint8_t *buf = buffer.data() + offset;

                            BOOST_ASSERT_MSG(sz >= minimum_final_size(), "Have sufficient final input in XTS isomorphic_decryption_mode");

                            const size_t BS = cipher.block_size();

                            if (sz % BS == 0) {
                                update(buffer, offset);
                            } else {
                                // steal ciphertext
                                const size_t full_blocks = ((sz / BS) - 1) * BS;
                                const size_t final_bytes = sz - full_blocks;
                                BOOST_ASSERT_MSG(final_bytes > BS && final_bytes < 2 * BS, "Left over size in expected range");

                                secure_vector<uint8_t> last(buf + full_blocks, buf + full_blocks + final_bytes);
                                buffer.resize(full_blocks + offset);
                                update(buffer, offset);

                                xor_buf(last, tweak() + BS, BS);
                                cipher.decrypt(last);
                                xor_buf(last, tweak() + BS, BS);

                                for (size_t i = 0; i != final_bytes - BS; ++i) {
                                    last[i] ^= last[i + BS];
                                    last[i + BS] ^= last[i];
                                    last[i] ^= last[i + BS];
                                }

                                xor_buf(last, tweak(), BS);
                                cipher.decrypt(last);
                                xor_buf(last, tweak(), BS);

                                buffer += last;
                            }
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            const size_t BS = cipher().block_size();

                            BOOST_ASSERT_MSG(sz % BS == 0, "Input is full blocks");
                            size_t blocks = sz / BS;

                            const size_t blocks_in_tweak = update_granularity() / BS;

                            while (blocks) {
                                const size_t to_proc = std::min(blocks, blocks_in_tweak);

                                cipher().encrypt_n_xex(buf, tweak(), to_proc);

                                buf += to_proc * BS;
                                blocks -= to_proc;

                                update_tweak(to_proc);
                            }

                            return sz;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct xts_decryption_policy<Cipher, Padding, cts<1, Cipher, Padding>>
                        : public xts_policy<Cipher, Padding> {
                        typedef typename xts_policy<Cipher, Padding>::size_type size_type;

                        typedef typename xts_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename xts_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = xts_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = xts_policy<Cipher, Padding>::block_words;
                        typedef typename xts_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            return {};
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct xts_decryption_policy<Cipher, Padding, cts<2, Cipher, Padding>>
                        : public xts_policy<Cipher, Padding> {
                        typedef typename xts_policy<Cipher, Padding>::size_type size_type;

                        typedef typename xts_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename xts_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = xts_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = xts_policy<Cipher, Padding>::block_words;
                        typedef typename xts_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            return {};
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct xts_decryption_policy<Cipher, Padding, cts<3, Cipher, Padding>>
                        : public xts_policy<Cipher, Padding> {
                        typedef typename xts_policy<Cipher, Padding>::size_type size_type;

                        typedef typename xts_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename xts_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = xts_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = xts_policy<Cipher, Padding>::block_words;
                        typedef typename xts_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            return {};
                        }
                    };

                    // Electronic Code Book CodecMode (ECB)
                    template<typename Policy>
                    class xts {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename policy_type::size_type size_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        xts(const cipher_type &c) : cipher(c) {
                        }

                        block_type begin_message(const block_type &plaintext) {
                            return policy_type::begin_message(cipher, plaintext);
                        }

                        block_type process_block(const block_type &plaintext) {
                            return policy_type::process_block(cipher, plaintext);
                        }

                        block_type end_message(const block_type &plaintext) {
                            return policy_type::end_message(cipher, plaintext);
                        }

                        size_type required_output_size(size_type inputlen) const {
                            return padding_type::required_output_size(inputlen, block_size);
                        }

                        constexpr static const std::size_t key_length = cipher_type::key_length / 8;
                        constexpr static const std::size_t block_size = cipher_type::block_size / 8;

                    private:
                        cipher_type cipher, tweak_cipher;
                    };
                }    // namespace detail

                /*!
                 * @brief IEEE P1619 XTS Mode
                 * @tparam Cipher
                 * @tparam Padding
                 * @tparam CiphertextStealingMode
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, template<typename> class Padding,
                         template<typename, typename> class CiphertextStealingMode = cts0>
                struct xts {
                    typedef Cipher cipher_type;
                    typedef Padding<Cipher> padding_type;
                    typedef CiphertextStealingMode<Cipher, Padding<Cipher>> ciphertext_stealing_type;

                    typedef detail::xts_encryption_policy<cipher_type, padding_type, ciphertext_stealing_type>
                        encryption_policy;
                    typedef detail::xts_decryption_policy<cipher_type, padding_type, ciphertext_stealing_type>
                        decryption_policy;

                    template<template<typename, typename> class Policy>
                    struct bind {
                        typedef detail::xts<Policy<cipher_type, padding_type>> type;
                    };
                };
            }    // namespace modes
        }        // namespace block
    }    // namespace crypto3
}    // namespace nil

#endif
