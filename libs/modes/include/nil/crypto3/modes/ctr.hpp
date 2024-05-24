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

#ifndef CRYPTO3_BLOCK_MODE_CIPHER_BLOCK_CHAINING_HPP
#define CRYPTO3_BLOCK_MODE_CIPHER_BLOCK_CHAINING_HPP

#include <boost/integer.hpp>

#include <nil/crypto3/modes/mode.hpp>
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
                    struct ctr_policy {
                        typedef std::size_t size_type;

                        typedef Cipher cipher_type;
                        typedef Padding padding_type;

                        constexpr static const size_type block_bits = cipher_type::block_bits;
                        constexpr static const size_type block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        typedef std::vector<boost::uint_t<CHAR_BIT>, Allocator<boost::uint_t<CHAR_BIT>>> iv_type;
                    };

                    template<typename Cipher, typename Padding, typename CiphertextStealingMode>
                    struct ctr_encryption_policy : public ctr_policy<Cipher, Padding> {};

                    template<typename Cipher, typename Padding>
                    struct ctr_encryption_policy<Cipher, Padding, cts<0, Cipher, Padding>>
                        : public ctr_policy<Cipher, Padding> {
                        typedef typename ctr_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ctr_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ctr_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ctr_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ctr_policy<Cipher, Padding>::block_words;
                        typedef typename ctr_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ctr_policy<Cipher, Padding>::iv_type iv_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext,
                                                               const iv_type &iv = iv_type()) {
                            block_type block = {0};

                            //                        codec::encode<codec::encoder::logic_xor>(plaintext, iv,
                            //                        block.begin());

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext,
                                                               const block_type &previous = block_type()) {
                            block_type block = {0};

                            //                        codec::encode<codec::encoder::logic_xor>(plaintext, previous,
                            //                        block.begin());

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext,
                                                             const block_type &previous = block_type(),
                                                             const iv_type &iv = iv_type()) {
                            block_type result = {0};
                            std::array<uint8_t, block_bits / CHAR_BIT> byte_array = {0};

                            pack(plaintext, byte_array);

                            size_type rem = std::count(byte_array.begin(), byte_array.end(), block_type::value_type()) %
                                            (block_bits / CHAR_BIT);
                            if (rem || padding_type::always_pad) {
                                block_type padbuffer = padding_type::pad(plaintext, rem), block;
                                //                            codec::encode<codec::encoder::logic_xor>(!iv.empty() ? iv
                                //                            : previous, padbuffer, block .begin());
                                result = cipher.encrypt(block);
                            }

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ctr_encryption_policy<Cipher, Padding, cts<1, Cipher, Padding>>
                        : public ctr_policy<Cipher, Padding> {
                        typedef typename ctr_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ctr_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ctr_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ctr_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ctr_policy<Cipher, Padding>::block_words;
                        typedef typename ctr_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ctr_policy<Cipher, Padding>::iv_type iv_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext,
                                                               const iv_type &iv = iv_type()) {
                            block_type block = {0};

                            //                        codec::encode<codec::encoder::logic_xor>(plaintext, iv,
                            //                        block.begin());

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext,
                                                               const block_type &previous = block_type()) {
                            block_type block = {0};

                            //                        codec::encode<codec::encoder::logic_xor>(plaintext, previous,
                            //                        block.begin());

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext,
                                                             const block_type &previous = block_type(),
                                                             const iv_type &iv = iv_type()) {
                            block_type result = {0};
                            std::array<uint8_t, block_bits / CHAR_BIT> byte_array = {0};

                            pack(plaintext, byte_array);

                            size_type rem = std::count(byte_array.begin(), byte_array.end(), block_type::value_type()) %
                                            (block_bits / CHAR_BIT);
                            if (rem || padding_type::always_pad) {
                                block_type padbuffer = padding_type::pad(plaintext, rem), block;
                                //                            codec::encode<codec::encoder::logic_xor>(!iv.empty() ? iv
                                //                            : previous, padbuffer, block .begin());
                                result = cipher.encrypt(block);
                            }

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ctr_encryption_policy<Cipher, Padding, cts<2, Cipher, Padding>>
                        : public ctr_policy<Cipher, Padding> {
                        typedef typename ctr_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ctr_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ctr_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ctr_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ctr_policy<Cipher, Padding>::block_words;
                        typedef typename ctr_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ctr_policy<Cipher, Padding>::iv_type iv_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext,
                                                               const iv_type &iv = iv_type()) {
                            block_type block = {0};

                            //                        codec::encode<codec::encoder::logic_xor>(plaintext, iv,
                            //                        block.begin());

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext,
                                                               const block_type &previous = block_type()) {
                            block_type block = {0};

                            //                        codec::encode<codec::encoder::logic_xor>(plaintext, previous,
                            //                        block.begin());

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext,
                                                             const block_type &previous = block_type(),
                                                             const iv_type &iv = iv_type()) {
                            block_type result = {0};
                            std::array<uint8_t, block_bits / CHAR_BIT> byte_array = {0};

                            pack(plaintext, byte_array);

                            size_type rem = std::count(byte_array.begin(), byte_array.end(), block_type::value_type()) %
                                            (block_bits / CHAR_BIT);
                            if (rem || padding_type::always_pad) {
                                block_type padbuffer = padding_type::pad(plaintext, rem), block;
                                //                            codec::encode<codec::encoder::logic_xor>(!iv.empty() ? iv
                                //                            : previous, padbuffer, block .begin());
                                result = cipher.encrypt(block);
                            }

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ctr_encryption_policy<Cipher, Padding, cts<3, Cipher, Padding>>
                        : public ctr_policy<Cipher, Padding> {
                        typedef typename ctr_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ctr_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ctr_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ctr_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ctr_policy<Cipher, Padding>::block_words;
                        typedef typename ctr_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ctr_policy<Cipher, Padding>::iv_type iv_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext,
                                                               const iv_type &iv = iv_type()) {
                            block_type block = {0};

                            //                        codec::encode<codec::encoder::logic_xor>(plaintext, iv,
                            //                        block.begin());

                            return cipher.encrypt(block);
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext,
                                                               const block_type &previous = block_type()) {
                            block_type block = {0};

                            //                        codec::encode<codec::encoder::logic_xor>(plaintext, previous,
                            //                        block.begin());

                            return cipher.encrypt(block);
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext,
                                                             const block_type &previous = block_type(),
                                                             const iv_type &iv = iv_type()) {
                            block_type result = {0};
                            std::array<uint8_t, block_bits / CHAR_BIT> byte_array = {0};

                            pack(plaintext, byte_array);

                            size_type rem = std::count(byte_array.begin(), byte_array.end(), block_type::value_type()) %
                                            (block_bits / CHAR_BIT);
                            if (rem || padding_type::always_pad) {
                                block_type padbuffer = padding_type::pad(plaintext, rem), block;
                                //                            codec::encode<codec::encoder::logic_xor>(!iv.empty() ? iv
                                //                            : previous, padbuffer, block .begin());
                                result = cipher.encrypt(block);
                            }

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding, typename CiphertextStealingMode>
                    struct ctr_decryption_policy : public ctr_policy<Cipher, Padding> {};

                    template<typename Cipher, typename Padding>
                    struct ctr_decryption_policy<Cipher, Padding, cts<0, Cipher, Padding>>
                        : public ctr_policy<Cipher, Padding> {
                        typedef typename ctr_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ctr_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ctr_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const std::size_t block_bits = ctr_policy<Cipher, Padding>::block_bits;
                        constexpr static const std::size_t block_words = ctr_policy<Cipher, Padding>::block_words;
                        typedef typename ctr_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ctr_policy<Cipher, Padding>::iv_type iv_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext,
                                                               const iv_type &iv = iv_type()) {
                            block_type block = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(block, iv);

                            return block;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext,
                                                               const block_type &previous = block_type()) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, previous);

                            return result;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext,
                                                             const iv_type &iv = iv_type()) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, iv);

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ctr_decryption_policy<Cipher, Padding, cts<1, Cipher, Padding>>
                        : public ctr_policy<Cipher, Padding> {
                        typedef typename ctr_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ctr_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ctr_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const std::size_t block_bits = ctr_policy<Cipher, Padding>::block_bits;
                        constexpr static const std::size_t block_words = ctr_policy<Cipher, Padding>::block_words;
                        typedef typename ctr_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ctr_policy<Cipher, Padding>::iv_type iv_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext,
                                                               const iv_type &iv = iv_type()) {
                            block_type block = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(block, iv);

                            return block;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext,
                                                               const block_type &previous = block_type()) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, previous);

                            return result;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext,
                                                             const iv_type &iv = iv_type()) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, iv);

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ctr_decryption_policy<Cipher, Padding, cts<2, Cipher, Padding>>
                        : public ctr_policy<Cipher, Padding> {
                        typedef typename ctr_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ctr_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ctr_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const std::size_t block_bits = ctr_policy<Cipher, Padding>::block_bits;
                        constexpr static const std::size_t block_words = ctr_policy<Cipher, Padding>::block_words;
                        typedef typename ctr_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ctr_policy<Cipher, Padding>::iv_type iv_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext,
                                                               const iv_type &iv = iv_type()) {
                            block_type block = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(block, iv);

                            return block;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext,
                                                               const block_type &previous = block_type()) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, previous);

                            return result;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext,
                                                             const iv_type &iv = iv_type()) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, iv);

                            return result;
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ctr_decryption_policy<Cipher, Padding, cts<3, Cipher, Padding>>
                        : public ctr_policy<Cipher, Padding> {
                        typedef typename ctr_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ctr_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ctr_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const std::size_t block_bits = ctr_policy<Cipher, Padding>::block_bits;
                        constexpr static const std::size_t block_words = ctr_policy<Cipher, Padding>::block_words;
                        typedef typename ctr_policy<Cipher, Padding>::block_type block_type;

                        typedef typename ctr_policy<Cipher, Padding>::iv_type iv_type;

                        inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext,
                                                               const iv_type &iv = iv_type()) {
                            block_type block = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(block, iv);

                            return block;
                        }

                        inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext,
                                                               const block_type &previous = block_type()) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, previous);

                            return result;
                        }

                        inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext,
                                                             const iv_type &iv = iv_type()) {
                            block_type result = cipher.decrypt(plaintext);

                            //                        codec::encode<codec::encoder::logic_xor>(result, iv);

                            return result;
                        }
                    };

                    template<typename Policy>
                    class counter {
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

                        counter(const cipher_type &cipher) : cipher(cipher) {
                        }

                        block_type begin_message(const block_type &plaintext, const iv_type &iv = iv_type()) {
                            previous = policy_type::begin_message(cipher, plaintext, iv);
                            return previous;
                        }

                        block_type process_block(const block_type &plaintext) {
                            previous = policy_type::process_block(cipher, plaintext, previous);
                            return previous;
                        }

                        block_type end_message(const block_type &plaintext, const iv_type &iv = iv_type()) {
                            return policy_type::end_message(cipher, plaintext, iv);
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
                 * @brief Counter Mode (CTR).
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @ingroup block_modes
                 */
                template<typename Cipher, template<typename> class Padding,
                         template<typename, template<typename> class> class CiphertextStealingMode = cts0>
                struct counter {
                    typedef Cipher cipher_type;
                    typedef Padding<Cipher> padding_type;
                    typedef CiphertextStealingMode<Cipher, Padding> ciphertext_stealing_type;

                    typedef detail::ctr_encryption_policy<cipher_type, padding_type, ciphertext_stealing_type>
                        encryption_policy;
                    typedef detail::ctr_decryption_policy<cipher_type, padding_type, ciphertext_stealing_type>
                        decryption_policy;

                    template<template<typename, typename> class Policy>
                    struct bind {
                        typedef detail::counter<Policy<cipher_type, padding_type>> type;
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
                         template<typename, template<typename> class> class CiphertextStealingMode>
                using ctr = counter<Cipher, Padding, CiphertextStealingMode>;
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif
