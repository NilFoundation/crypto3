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

#ifndef CRYPTO3_BLOCK_MODE_OUTPUT_FEEDBACK_HPP
#define CRYPTO3_BLOCK_MODE_OUTPUT_FEEDBACK_HPP

#include <nil/crypto3/modes/cts.hpp>
#include <nil/crypto3/modes/padding.hpp>

#include <nil/crypto3/codec/algorithm/encode.hpp>

//#include <nil/crypto3/codec/logic.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                namespace detail {
                    template<typename Cipher, typename Padding, template<typename> class Allocator = std::allocator>
                    struct ofb_policy {
                        typedef std::size_t size_type;

                        typedef Cipher cipher_type;
                        typedef Padding padding_type;

                        constexpr static const size_type block_bits = cipher_type::block_bits;
                        constexpr static const size_type block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>> iv_type;
                    };

                    template<typename Cipher, typename Padding, typename CiphertextStealingMode>
                    struct ofb_encryption_policy : public ofb_policy<Cipher, Padding> {};

                    template<typename Cipher, typename Padding>
                    struct ofb_encryption_policy<Cipher, Padding, cts<0, Cipher, Padding>>
                        : public ofb_policy<Cipher, Padding> {
                        typedef typename ofb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ofb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ofb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ofb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ofb_policy<Cipher, Padding>::block_words;
                        typedef typename ofb_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ofb_policy<Cipher, Padding>::iv_type iv_type;

                        block_type begin_message(const block_type &plaintext, const iv_type &iv) {
                            return plaintext;
                        }

                        block_type process_block(const block_type &plaintext, const block_type &previous) {
                            return plaintext;
                        }

                        block_type end_message(const block_type &plaintext, const block_type &previous,
                                               const iv_type &iv) {
                            return plaintext;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ofb_encryption_policy<Cipher, Padding, cts<1, Cipher, Padding>>
                        : public ofb_policy<Cipher, Padding> {
                        typedef typename ofb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ofb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ofb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ofb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ofb_policy<Cipher, Padding>::block_words;
                        typedef typename ofb_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ofb_policy<Cipher, Padding>::iv_type iv_type;

                        block_type begin_message(const block_type &plaintext, const iv_type &iv) {
                            return plaintext;
                        }

                        block_type process_block(const block_type &plaintext, const block_type &previous) {
                            return plaintext;
                        }

                        block_type end_message(const block_type &plaintext, const block_type &previous,
                                               const iv_type &iv) {
                            return plaintext;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ofb_encryption_policy<Cipher, Padding, cts<2, Cipher, Padding>>
                        : public ofb_policy<Cipher, Padding> {
                        typedef typename ofb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ofb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ofb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ofb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ofb_policy<Cipher, Padding>::block_words;
                        typedef typename ofb_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ofb_policy<Cipher, Padding>::iv_type iv_type;

                        block_type begin_message(const block_type &plaintext, const iv_type &iv) {
                            return plaintext;
                        }

                        block_type process_block(const block_type &plaintext, const block_type &previous) {
                            return plaintext;
                        }

                        block_type end_message(const block_type &plaintext, const block_type &previous,
                                               const iv_type &iv) {
                            return plaintext;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ofb_encryption_policy<Cipher, Padding, cts<3, Cipher, Padding>>
                        : public ofb_policy<Cipher, Padding> {
                        typedef typename ofb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ofb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ofb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ofb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ofb_policy<Cipher, Padding>::block_words;
                        typedef typename ofb_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ofb_policy<Cipher, Padding>::iv_type iv_type;

                        block_type begin_message(const block_type &plaintext, const iv_type &iv) {
                            return plaintext;
                        }

                        block_type process_block(const block_type &plaintext, const block_type &previous) {
                            return plaintext;
                        }

                        block_type end_message(const block_type &plaintext, const block_type &previous,
                                               const iv_type &iv) {
                            return plaintext;
                        }
                    };

                    template<typename Cipher, typename Padding, typename CiphertextStealingMode>
                    struct ofb_decryption_policy : public ofb_policy<Cipher, Padding> {};

                    template<typename Cipher, typename Padding>
                    struct ofb_decryption_policy<Cipher, Padding, cts<0, Cipher, Padding>>
                        : public ofb_policy<Cipher, Padding> {
                        typedef typename ofb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ofb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ofb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ofb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ofb_policy<Cipher, Padding>::block_words;
                        typedef typename ofb_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ofb_policy<Cipher, Padding>::iv_type iv_type;

                        block_type begin_message(const block_type &plaintext, const iv_type &iv) {
                            return plaintext;
                        }

                        block_type process_block(const block_type &plaintext, const block_type &previous) {
                            return plaintext;
                        }

                        block_type end_message(const block_type &plaintext, const block_type &previous,
                                               const iv_type &iv) {
                            return plaintext;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ofb_decryption_policy<Cipher, Padding, cts<1, Cipher, Padding>>
                        : public ofb_policy<Cipher, Padding> {
                        typedef typename ofb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ofb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ofb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ofb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ofb_policy<Cipher, Padding>::block_words;
                        typedef typename ofb_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ofb_policy<Cipher, Padding>::iv_type iv_type;

                        block_type begin_message(const block_type &plaintext, const iv_type &iv) {
                            return plaintext;
                        }

                        block_type process_block(const block_type &plaintext, const block_type &previous) {
                            return plaintext;
                        }

                        block_type end_message(const block_type &plaintext, const block_type &previous,
                                               const iv_type &iv) {
                            return plaintext;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ofb_decryption_policy<Cipher, Padding, cts<2, Cipher, Padding>>
                        : public ofb_policy<Cipher, Padding> {
                        typedef typename ofb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ofb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ofb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ofb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ofb_policy<Cipher, Padding>::block_words;
                        typedef typename ofb_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ofb_policy<Cipher, Padding>::iv_type iv_type;

                        block_type begin_message(const block_type &plaintext, const iv_type &iv) {
                            return plaintext;
                        }

                        block_type process_block(const block_type &plaintext, const block_type &previous) {
                            return plaintext;
                        }

                        block_type end_message(const block_type &plaintext, const block_type &previous,
                                               const iv_type &iv) {
                            return plaintext;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ofb_decryption_policy<Cipher, Padding, cts<3, Cipher, Padding>>
                        : public ofb_policy<Cipher, Padding> {
                        typedef typename ofb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ofb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ofb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ofb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ofb_policy<Cipher, Padding>::block_words;
                        typedef typename ofb_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ofb_policy<Cipher, Padding>::iv_type iv_type;

                        block_type begin_message(const block_type &plaintext, const iv_type &iv) {
                            return plaintext;
                        }

                        block_type process_block(const block_type &plaintext, const block_type &previous) {
                            return plaintext;
                        }

                        block_type end_message(const block_type &plaintext, const block_type &previous,
                                               const iv_type &iv) {
                            return plaintext;
                        }
                    };

                    /*!
                     * @brief Output Feedback Mode (OFB)
                     *
                     * @ingroup block_modes
                     *
                     * @tparam Cipher
                     * @tparam Allocator
                     */
                    template<typename Policy>
                    class output_feedback_mode {
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

                        output_feedback_mode(const cipher_type &cipher) : cipher(cipher) {
                        }

                        ~output_feedback_mode() {
                            buf.fill(0);
                        }

                        void encrypt(const void *key, const iv_type &iv, const void *in, void *out, size_type len) {
                            this->c_.encrypt(key, iv_, buf_);
                            while (len > 0) {
                                buf_[i] ^= in[i];
                                std::memcpy(out, buf_, bufsize);
                                this->c_.encrypt(key, buf_, buf_);
                                in += block_size;
                                out += block_size;
                                len -= block_size;
                            }
                        }

                        void decrypt(const void *key, const void *iv, const void *in, void *out, size_type len) {
                        }

                    private:
                        cipher_type cipher;
                        block_type buf;
                    };
                }    // namespace detail

                /*!
                 * @brief
                 * @tparam Cipher
                 * @tparam Padding
                 * @tparam CiphertextStealingMode
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, template<typename> class Padding,
                         template<typename, template<typename> class> class CiphertextStealingMode = cts0>
                struct output_feedback_mode {
                    typedef Cipher cipher_type;
                    typedef Padding<Cipher> padding_type;
                    typedef CiphertextStealingMode<Cipher, Padding> ciphertext_stealing_type;

                    typedef detail::ofb_encryption_policy<cipher_type, padding_type, ciphertext_stealing_type>
                        encryption_policy;
                    typedef detail::ofb_decryption_policy<cipher_type, padding_type, ciphertext_stealing_type>
                        decryption_policy;

                    template<template<typename, typename> class Policy>
                    struct bind {
                        typedef detail::output_feedback_mode<Policy<cipher_type, padding_type>> type;
                    };
                };

                /*!
                 * @brief
                 *
                 * @tparam Cipher
                 * @tparam Padding
                 * @tparam CiphertextStealingMode
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, template<typename> class Padding,
                         template<typename, template<typename> class> class CiphertextStealingMode = cts0>
                using ofb = output_feedback_mode<Cipher, Padding, CiphertextStealingMode>;
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif