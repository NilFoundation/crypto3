//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_MODE_ELECTRONIC_CODE_BOOK_HPP
#define CRYPTO3_BLOCK_MODE_ELECTRONIC_CODE_BOOK_HPP

#include <boost/integer.hpp>

#include <nil/crypto3/modes/cts.hpp>

#include <nil/crypto3/codec/algorithm/encode.hpp>

//#include <nil/crypto3/codec/logic.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace modes {
                namespace detail {
                    template<typename Cipher, typename Padding, template<typename> class Allocator = std::allocator>
                    struct ecb_policy {
                        typedef std::size_t size_type;

                        typedef Cipher cipher_type;
                        typedef Padding padding_type;

                        constexpr static const size_type block_bits = cipher_type::block_bits;
                        constexpr static const size_type block_words = cipher_type::block_words;
                        typedef typename cipher_type::block_type block_type;
                    };

                    template<typename Cipher, typename Padding, typename CiphertextStealingMode>
                    struct ecb_encryption_policy : public ecb_policy<Cipher, Padding> {};

                    template<typename Cipher, typename Padding>
                    struct ecb_encryption_policy<Cipher, Padding, cts<0, Cipher, Padding>>
                        : public ecb_policy<Cipher, Padding> {
                        typedef typename ecb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ecb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ecb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ecb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ecb_policy<Cipher, Padding>::block_words;
                        typedef typename ecb_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            const size_type rem = len % block_size;
                            if (rem || padding_type::always_pad) {
                                unsigned char block[block_size];
                                std::memcpy(block, in, rem);
                                padding_type::pad(block, block_size, rem);
                                c_.encrypt_block(block, out);
                            }
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ecb_encryption_policy<Cipher, Padding, cts<1, Cipher, Padding>>
                        : public ecb_policy<Cipher, Padding> {
                        typedef typename ecb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ecb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ecb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ecb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ecb_policy<Cipher, Padding>::block_words;
                        typedef typename ecb_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            const size_type rem = len % block_size;
                            if (rem || padding_type::always_pad) {
                                unsigned char block[block_size];
                                std::memcpy(block, in, rem);
                                padding_type::pad(block, block_size, rem);
                                c_.encrypt_block(block, out);
                            }
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ecb_encryption_policy<Cipher, Padding, cts<2, Cipher, Padding>>
                        : public ecb_policy<Cipher, Padding> {
                        typedef typename ecb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ecb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ecb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ecb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ecb_policy<Cipher, Padding>::block_words;
                        typedef typename ecb_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            const size_type rem = len % block_size;
                            if (rem || padding_type::always_pad) {
                                unsigned char block[block_size];
                                std::memcpy(block, in, rem);
                                padding_type::pad(block, block_size, rem);
                                c_.encrypt_block(block, out);
                            }
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ecb_encryption_policy<Cipher, Padding, cts<3, Cipher, Padding>>
                        : public ecb_policy<Cipher, Padding> {
                        typedef typename ecb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ecb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ecb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ecb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ecb_policy<Cipher, Padding>::block_words;
                        typedef typename ecb_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.encrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            const size_type rem = len % block_size;
                            if (rem || padding_type::always_pad) {
                                unsigned char block[block_size];
                                std::memcpy(block, in, rem);
                                padding_type::pad(block, block_size, rem);
                                c_.encrypt_block(block, out);
                            }
                        }
                    };

                    template<typename Cipher, typename Padding, typename CiphertextStealingMode>
                    struct ecb_decryption_policy : public ecb_policy<Cipher, Padding> {};

                    template<typename Cipher, typename Padding>
                    struct ecb_decryption_policy<Cipher, Padding, cts<0, Cipher, Padding>>
                        : public ecb_policy<Cipher, Padding> {
                        typedef typename ecb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ecb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ecb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ecb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ecb_policy<Cipher, Padding>::block_words;
                        typedef typename ecb_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            const size_type rem = len % block_size;
                            if (rem || padding_type::always_pad) {
                                return cipher.decrypt_block(plaintext);
                            }
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ecb_decryption_policy<Cipher, Padding, cts<1, Cipher, Padding>>
                        : public ecb_policy<Cipher, Padding> {
                        typedef typename ecb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ecb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ecb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ecb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ecb_policy<Cipher, Padding>::block_words;
                        typedef typename ecb_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            const size_type rem = len % block_size;
                            if (rem || padding_type::always_pad) {
                                return cipher.decrypt_block(plaintext);
                            }
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ecb_decryption_policy<Cipher, Padding, cts<2, Cipher, Padding>>
                        : public ecb_policy<Cipher, Padding> {
                        typedef typename ecb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ecb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ecb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ecb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ecb_policy<Cipher, Padding>::block_words;
                        typedef typename ecb_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            const size_type rem = len % block_size;
                            if (rem || padding_type::always_pad) {
                                return cipher.decrypt_block(plaintext);
                            }
                        }
                    };

                    template<typename Cipher, typename Padding>
                    struct ecb_decryption_policy<Cipher, Padding, cts<3, Cipher, Padding>>
                        : public ecb_policy<Cipher, Padding> {
                        typedef typename ecb_policy<Cipher, Padding>::size_type size_type;

                        typedef typename ecb_policy<Cipher, Padding>::cipher_type cipher_type;
                        typedef typename ecb_policy<Cipher, Padding>::padding_type padding_type;

                        constexpr static const size_type block_bits = ecb_policy<Cipher, Padding>::block_bits;
                        constexpr static const size_type block_words = ecb_policy<Cipher, Padding>::block_words;
                        typedef typename ecb_policy<Cipher, Padding>::block_type block_type;

                        block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                            return cipher.decrypt(plaintext);
                        }

                        block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                            const size_type rem = len % block_size;
                            if (rem || padding_type::always_pad) {
                                return cipher.decrypt_block(plaintext);
                            }
                        }
                    };

                    // Electronic Code Book CodecMode (ECB)
                    template<typename Policy>
                    class electronic_code_book {
                        typedef Policy policy_type;

                    public:
                        typedef typename policy_type::cipher_type cipher_type;
                        typedef typename policy_type::padding_type padding_type;

                        typedef typename policy_type::size_type size_type;

                        constexpr static const std::size_t block_bits = policy_type::block_bits;
                        constexpr static const std::size_t block_words = policy_type::block_words;
                        typedef typename cipher_type::block_type block_type;

                        electronic_code_book(const cipher_type &c) : cipher(c) {
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

                        constexpr static const unsigned int key_length = cipher_type::key_length / 8;
                        constexpr static const unsigned int block_size = cipher_type::block_size / 8;

                    private:
                        cipher_type cipher;
                    };
                }    // namespace detail

                /*!
                 * @brief Electronic Code Book Mode (ECB)
                 * @tparam Cipher
                 * @tparam Padding
                 *
                 * @addtogroup block_modes
                 */
                template<typename Cipher, template<typename> class Padding,
                         template<typename, typename> class CiphertextStealingMode = cts0>
                struct electronic_code_book {
                    typedef Cipher cipher_type;
                    typedef Padding<Cipher> padding_type;
                    typedef CiphertextStealingMode<Cipher, Padding<Cipher>> ciphertext_stealing_type;

                    typedef detail::ecb_encryption_policy<cipher_type, padding_type, ciphertext_stealing_type>
                        encryption_policy;
                    typedef detail::ecb_decryption_policy<cipher_type, padding_type, ciphertext_stealing_type>
                        decryption_policy;

                    template<template<typename, typename> class Policy>
                    struct bind {
                        typedef detail::electronic_code_book<Policy<cipher_type, padding_type>> type;
                    };
                };

                template<typename Cipher, template<typename> class Padding>
                using ecb = electronic_code_book<Cipher, Padding>;
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ECB_HPP
