//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CIPHER_MODES_HPP
#define CRYPTO3_CIPHER_MODES_HPP

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<typename Cipher, typename Padding>
                struct isomorphic_policy {
                    typedef std::size_t size_type;

                    typedef Cipher cipher_type;
                    typedef Padding padding_type;

                    constexpr static const size_type block_bits = cipher_type::block_bits;
                    constexpr static const size_type block_words = cipher_type::block_words;
                    typedef typename cipher_type::block_type block_type;
                };

                template<typename Cipher, typename Padding>
                struct isomorphic_encryption_policy : public isomorphic_policy<Cipher, Padding> {
                    typedef typename isomorphic_policy<Cipher, Padding>::cipher_type cipher_type;
                    typedef typename isomorphic_policy<Cipher, Padding>::block_type block_type;

                    inline static block_type begin_message(const cipher_type &cipher, const block_type &plaintext) {
                        return cipher.encrypt(plaintext);
                    }

                    inline static block_type process_block(const cipher_type &cipher, const block_type &plaintext) {
                        return cipher.encrypt(plaintext);
                    }

                    inline static block_type end_message(const cipher_type &cipher, const block_type &plaintext) {
                        return cipher.encrypt(plaintext);
                    }
                };

                template<typename Cipher, typename Padding>
                struct isomorphic_decryption_policy : public isomorphic_policy<Cipher, Padding> {
                    typedef typename isomorphic_policy<Cipher, Padding>::cipher_type cipher_type;
                    typedef typename isomorphic_policy<Cipher, Padding>::block_type block_type;

                    inline static block_type begin_message(const cipher_type &cipher, const block_type &ciphertext) {
                        return cipher.decrypt(ciphertext);
                    }

                    inline static block_type process_block(const cipher_type &cipher, const block_type &ciphertext) {
                        return cipher.decrypt(ciphertext);
                    }

                    inline static block_type end_message(const cipher_type &cipher, const block_type &ciphertext) {
                        return cipher.decrypt(ciphertext);
                    }
                };

                template<typename Policy>
                class isomorphic {
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

                    isomorphic(const cipher_type &cipher) : cipher(cipher) {
                    }

                    block_type begin_message(const block_type &plaintext, const iv_type &iv = iv_type()) {
                        return policy_type::begin_message(cipher, plaintext, iv);
                    }

                    block_type process_block(const block_type &plaintext) {
                        return policy_type::process_block(cipher, plaintext);
                    }

                    block_type end_message(const block_type &plaintext, const iv_type &iv = iv_type()) {
                        return policy_type::end_message(cipher, plaintext, iv);
                    }

                protected:
                    cipher_type cipher;
                };
            }    // namespace detail

            namespace modes {

                template<typename Cipher, template<typename> class Padding>
                struct isomorphic {
                    typedef Cipher cipher_type;
                    typedef Padding<Cipher> padding_type;

                    typedef detail::isomorphic_encryption_policy<cipher_type, padding_type> encryption_policy;
                    typedef detail::isomorphic_decryption_policy<cipher_type, padding_type> decryption_policy;

                    template<template<typename, typename> class Policy>
                    struct bind {
                        typedef detail::isomorphic<Policy<cipher_type, padding_type>> type;
                    };
                };
            }    // namespace modes
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CIPHER_MODES_HPP
