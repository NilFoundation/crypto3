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

#ifndef CRYPTO3_BLOCK_MODE_CIPHER_FEEDBACK_HPP
#define CRYPTO3_BLOCK_MODE_CIPHER_FEEDBACK_HPP

#include <memory>
#include <limits>

#include <boost/static_assert.hpp>

#include <nil/crypto3/modes/mode.hpp>
#include <nil/crypto3/modes/cts.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                namespace detail {
                    template<typename Cipher, typename Padding, template<typename> class Allocator = std::allocator>
                    struct cfb_policy {
                        typedef std::size_t size_type;

                        typedef Cipher cipher_type;
                        typedef Padding padding_type;

                        constexpr static const size_type block_bits = cipher_type::block_bits;
                        constexpr static const size_type block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        static void shift_register(cipher_type &cipher) {
                            const size_t shift = feedback();
                            const size_t carryover = block_size() - shift;

                            if (carryover > 0) {
                                copy_mem(m_state.data(), &m_state[shift], carryover);
                            }
                            copy_mem(&m_state[carryover], m_keystream.data(), shift);
                            cipher().encrypt(m_state, m_keystream);
                            m_keystream_pos = 0;
                        }

                        static inline void xor_copy(uint8_t buf[], uint8_t key_buf[], size_t len) {
                            for (size_t i = 0; i != len; ++i) {
                                uint8_t k = key_buf[i];
                                key_buf[i] = buf[i];
                                buf[i] ^= k;
                            }
                        }
                    };

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding,
                             typename CiphertextStealingMode>
                    struct cfb_encryption_policy : public cfb_policy<Cipher, Padding> {};

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding>
                    struct cfb_encryption_policy<Cipher, FeedbackBits, Padding, cts<0, Cipher, Padding>>
                        : public cfb_policy<Cipher, Padding> {
                        typedef typename cfb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename cfb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename cfb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = cfb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = cfb_policy<Cipher, Padding>::block_words;
                        typedef typename cfb_policy<Cipher, Padding>::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            if (!valid_nonce_length(nonce_len)) {
                                throw invalid_iv_length(name(), nonce_len);
                            }

                            if (nonce_len == 0) {
                                if (m_state.empty()) {
                                    throw invalid_state("CFB requires a non-empty initial nonce");
                                }
                                // No reason to encipher state->keystream_buf, because no change
                            } else {
                                m_state.assign(nonce, nonce + nonce_len);
                                m_keystream.resize(m_state.size());
                                cipher().encrypt(m_state, m_keystream);
                                m_keystream_pos = 0;
                            }
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            const size_t shift = feedback();

                            size_t left = sz;

                            if (m_keystream_pos != 0) {
                                const size_t take = std::min<size_t>(left, shift - m_keystream_pos);

                                xor_buf(m_keystream.data() + m_keystream_pos, buf, take);
                                copy_mem(buf, m_keystream.data() + m_keystream_pos, take);

                                m_keystream_pos += take;
                                left -= take;
                                buf += take;

                                if (m_keystream_pos == shift) {
                                    shift_register();
                                }
                            }

                            while (left >= shift) {
                                xor_buf(m_keystream.data(), buf, shift);
                                copy_mem(buf, m_keystream.data(), shift);

                                left -= shift;
                                buf += shift;
                                shift_register();
                            }

                            if (left > 0) {
                                xor_buf(m_keystream.data(), buf, left);
                                copy_mem(buf, m_keystream.data(), left);
                                m_keystream_pos += left;
                            }

                            return sz;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            return result;
                        }
                    };

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding>
                    struct cfb_encryption_policy<Cipher, FeedbackBits, Padding, cts<1, Cipher, Padding>>
                        : public cfb_policy<Cipher, Padding> {
                        typedef typename cfb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename cfb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename cfb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = cfb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = cfb_policy<Cipher, Padding>::block_words;
                        typedef typename cfb_policy<Cipher, Padding>::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            return result;
                        }
                    };

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding>
                    struct cfb_encryption_policy<Cipher, FeedbackBits, Padding, cts<2, Cipher, Padding>>
                        : public cfb_policy<Cipher, Padding> {
                        typedef typename cfb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename cfb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename cfb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = cfb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = cfb_policy<Cipher, Padding>::block_words;
                        typedef typename cfb_policy<Cipher, Padding>::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            return result;
                        }
                    };

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding>
                    struct cfb_encryption_policy<Cipher, FeedbackBits, Padding, cts<3, Cipher, Padding>>
                        : public cfb_policy<Cipher, Padding> {
                        typedef typename cfb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename cfb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename cfb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = cfb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = cfb_policy<Cipher, Padding>::block_words;
                        typedef typename cfb_policy<Cipher, Padding>::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = {0};

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = {0};

                            return result;
                        }
                    };

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding,
                             typename CiphertextStealingMode>
                    struct cfb_decryption_policy : public cfb_policy<Cipher, Padding> {};

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding>
                    struct cfb_decryption_policy<Cipher, FeedbackBits, Padding, cts<0, Cipher, Padding>>
                        : public cfb_policy<Cipher, Padding> {
                        typedef typename cfb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename cfb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename cfb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const std::size_t block_bits = cfb_policy<Cipher, Padding>::block_bits;
                        constexpr static const std::size_t block_words = cfb_policy<Cipher, Padding>::block_words;
                        typedef typename cfb_policy<Cipher, Padding>::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(block, iv);

                            return block;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            const size_t shift = feedback();

                            size_t left = sz;

                            if (m_keystream_pos != 0) {
                                const size_t take = std::min<size_t>(left, shift - m_keystream_pos);

                                xor_copy(buf, m_keystream.data() + m_keystream_pos, take);

                                m_keystream_pos += take;
                                left -= take;
                                buf += take;

                                if (m_keystream_pos == shift) {
                                    shift_register();
                                }
                            }

                            while (left >= shift) {
                                xor_copy(buf, m_keystream.data(), shift);
                                left -= shift;
                                buf += shift;
                                shift_register();
                            }

                            if (left > 0) {
                                xor_copy(buf, m_keystream.data(), left);
                                m_keystream_pos += left;
                            }

                            return sz;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, iv);

                            return result;
                        }
                    };

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding>
                    struct cfb_decryption_policy<Cipher, FeedbackBits, Padding, cts<1, Cipher, Padding>>
                        : public cfb_policy<Cipher, Padding> {
                        typedef typename cfb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename cfb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename cfb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const std::size_t block_bits = cfb_policy<Cipher, Padding>::block_bits;
                        constexpr static const std::size_t block_words = cfb_policy<Cipher, Padding>::block_words;
                        typedef typename cfb_policy<Cipher, Padding>::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(block, iv);

                            return block;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, previous);

                            return result;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, iv);

                            return result;
                        }
                    };

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding>
                    struct cfb_decryption_policy<Cipher, FeedbackBits, Padding, cts<2, Cipher, Padding>>
                        : public cfb_policy<Cipher, Padding> {
                        typedef typename cfb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename cfb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename cfb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const std::size_t block_bits = cfb_policy<Cipher, Padding>::block_bits;
                        constexpr static const std::size_t block_words = cfb_policy<Cipher, Padding>::block_words;
                        typedef typename cfb_policy<Cipher, Padding>::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(block, iv);

                            return block;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, previous);

                            return result;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, iv);

                            return result;
                        }
                    };

                    template<typename Cipher, std::size_t FeedbackBits, typename Padding>
                    struct cfb_decryption_policy<Cipher, FeedbackBits, Padding, cts<3, Cipher, Padding>>
                        : public cfb_policy<Cipher, Padding> {
                        typedef typename cfb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename cfb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename cfb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const std::size_t block_bits = cfb_policy<Cipher, Padding>::block_bits;
                        constexpr static const std::size_t block_words = cfb_policy<Cipher, Padding>::block_words;
                        typedef typename cfb_policy<Cipher, Padding>::block_type block_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type block = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(block, iv);

                            return block;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, previous);

                            return result;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, iv);

                            return result;
                        }
                    };

                    template<typename Policy>
                    class cipher_feedback {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename policy_type::size_type size_type;

                        typedef typename cipher_type::key_type key_type;
                        typedef typename policy_type::iv_type iv_type;

                        constexpr static const size_type block_bits = policy_type::block_bits;
                        constexpr static const size_type block_words = policy_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        cipher_feedback(const cipher_type &cipher) : cipher(cipher) {
                        }

                        block_type begin_message(const block_type &plaintext) {
                            previous = policy_type::begin_message(cipher, plaintext);
                            return previous;
                        }

                        block_type process_block(const block_type &plaintext) {
                            previous = policy_type::process_block(cipher, plaintext, previous);
                            return previous;
                        }

                        block_type end_message(const block_type &plaintext) {
                            return policy_type::end_message(cipher, plaintext);
                        }

                        inline static size_type required_output_size(size_type inputlen) {
                            return padding_type::required_output_size(inputlen);
                        }

                    protected:
                        block_type previous;
                        cipher_type cipher;
                    };
                }    // namespace detail

                /*!
                 * @brief Cipher Feedback Mode (CBC).
                 *
                 * @tparam Cipher
                 * @tparam FeedbackBits
                 * @tparam Padding
                 * @tparam CiphertextStealingMode
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, std::size_t FeedbackBits, template<typename> class Padding,
                         template<typename, typename> class CiphertextStealingMode = cts0>
                struct cipher_feedback {
                    typedef Cipher cipher_type;
                    typedef Padding<Cipher> padding_type;
                    typedef CiphertextStealingMode<Cipher, Padding<Cipher>> ciphertext_stealing_type;

                    constexpr static const std::size_t feedback_bits = FeedbackBits;
                    BOOST_STATIC_ASSERT(feedback_bits <= cipher_type::block_bits);
                    BOOST_STATIC_ASSERT(feedback_bits % CHAR_BIT == 0);

                    typedef detail::cfb_encryption_policy<cipher_type, feedback_bits, padding_type,
                                                          ciphertext_stealing_type>
                        encryption_policy;
                    typedef detail::cfb_decryption_policy<cipher_type, feedback_bits, padding_type,
                                                          ciphertext_stealing_type>
                        decryption_policy;

                    template<template<typename, typename> class Policy>
                    struct bind {
                        typedef detail::cipher_feedback<Policy<cipher_type, padding_type>> type;
                    };
                };

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam FeedbackBits
                 * @tparam Padding
                 * @tparam CiphertextStealingMode
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, std::size_t FeedbackBits, template<typename> class Padding,
                         template<typename, typename> class CiphertextStealingMode = cts0>
                using cfb = cipher_feedback<Cipher, FeedbackBits, Padding, CiphertextStealingMode>;
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif
