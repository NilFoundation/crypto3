//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_CIPHERS_MD4_HPP
#define CRYPTO3_BLOCK_CIPHERS_MD4_HPP

#include <nil/crypto3/block/detail/block_stream_processor.hpp>

#include <nil/crypto3/block/detail/md4/md4_policy.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
#include <cstdio>
#endif

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief MD4 block cipher. Stands as a foundation for
             * @ref nil::crypto3::hash::md4 "MD4" hash.
             *
             * @ingroup block
             *
             * Encrypt implemented directly from the RFC as found at
             * http://www.faqs.org/rfcs/rfc1320.html
             *
             * Decrypt is a straight-forward inverse
             *
             * In MD4 terminology:
             * - plaintext = AA, BB, CC, and DD
             * - ciphertext = A, B, C, and D
             * - key = M^(i) and X
             */
            class md4 {
                typedef detail::md4_policy policy_type;

            public:
                constexpr static const std::size_t rounds = policy_type::rounds;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef policy_type::key_type key_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef policy_type::block_type block_type;

                template<template<typename, typename> class Mode, typename StateAccumulator, std::size_t ValueBits,
                         typename Padding>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian_type;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode<md4, Padding>, StateAccumulator, params_type> type_;
#ifdef CRYPTO3_BLOCK_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {};
#endif
                };

                md4(const key_type &k) : key(k) {
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    for (unsigned t = 0; t < key_words; ++t) {
                        std::printf("X[%2d] = %.8x\n", t, key[t]);
                    }
#endif
                }

                virtual ~md4() {
                    key.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(key, plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return decrypt_block(key, ciphertext);
                }

            private:
                key_type key;

                inline static block_type encrypt_block(const key_type &key, const block_type &plaintext) {

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    for (unsigned t = 0; t < block_words; ++t) {
                        std::printf("%c%c = %.8x\n", 'A' + t, 'A' + t, plaintext[t]);
                    }
#endif

                    // Initialize working variables with block
                    word_type a = plaintext[0], b = plaintext[1], c = plaintext[2], d = plaintext[3];

                    // Encipher block
#define CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(aa, bb, cc, dd, fun, k, s, val)                            \
    {                                                                                             \
        word_type T = aa + policy_type::fun(bb, cc, dd) + key[policy_type::key_indexes[k]] + val; \
        aa = policy_type::rotl<s>(T);                                                             \
    }
                    for (unsigned t = 0; t < policy_type::rounds / 3; t += 4) {
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(a, b, c, d, ff, t + 0, 3, 0x00000000)
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(d, a, b, c, ff, t + 1, 7, 0x00000000)
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(c, d, a, b, ff, t + 2, 11, 0x00000000)
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(b, c, d, a, ff, t + 3, 19, 0x00000000)

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        printf("Round 1: %.8x %.8x %.8x %.8x\n", a, b, c, d);
#endif
                    }

                    for (unsigned t = 0; t < policy_type::rounds / 12; t += 1) {
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(a, b, c, d, gg, t + 0, 3, 0x5a827999)
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(d, a, b, c, gg, t + 4, 5, 0x5a827999)
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(c, d, a, b, gg, t + 8, 9, 0x5a827999)
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(b, c, d, a, gg, t + 12, 13, 0x5a827999)

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        printf("Round 2: %.8x %.8x %.8x %.8x\n", a, b, c, d);
#endif
                    }
                    std::array<unsigned, 4> t_step3 {{0, 2, 1, 3}};
                    for (unsigned int &t : t_step3) {
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(a, b, c, d, hh, t + 0, 3, 0x6ed9eba1)
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(d, a, b, c, hh, t + 8, 9, 0x6ed9eba1)
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(c, d, a, b, hh, t + 4, 11, 0x6ed9eba1)
                        CRYPTO3_BLOCK_MD4_ENCRYPT_STEP(b, c, d, a, hh, t + 12, 15, 0x6ed9eba1)
                    }
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    printf("Round 3: %.8x %.8x %.8x %.8x\n", a, b, c, d);
#endif

                    return {{a, b, c, d}};
                }

                inline static block_type decrypt_block(const key_type &key, const block_type &ciphertext) {

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    for (unsigned t = 0; t < block_words; ++t) {
                        std::printf("%c = %.8x\n", 'A' + t, ciphertext[t]);
                    }
#endif

                    // Initialize working variables with block
                    word_type a = ciphertext[0], b = ciphertext[1], c = ciphertext[2], d = ciphertext[3];

                    // Decipher block
#define CRYPTO3_BLOCK_MD4_DECRYPT_STEP(aa, bb, cc, dd, fun, k, s, val)                  \
    {                                                                                   \
        word_type T = policy_type::rotr<s>(aa);                                         \
        aa = T - policy_type::fun(bb, cc, dd) - key[policy_type::key_indexes[k]] - val; \
    }
                    for (unsigned t = policy_type::rounds; t -= 4, t >= 2 * policy_type::rounds / 3;) {
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(b, c, d, a, hh, t + 3, 15, 0x6ed9eba1)
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(c, d, a, b, hh, t + 2, 11, 0x6ed9eba1)
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(d, a, b, c, hh, t + 1, 9, 0x6ed9eba1)
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(a, b, c, d, hh, t + 0, 3, 0x6ed9eba1)

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        printf("Round 3: %.8x %.8x %.8x %.8x\n", a, b, c, d);
#endif
                    }
                    for (unsigned t = 2 * policy_type::rounds / 3; t -= 4, t >= policy_type::rounds / 3;) {
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(b, c, d, a, gg, t + 3, 13, 0x5a827999)
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(c, d, a, b, gg, t + 2, 9, 0x5a827999)
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(d, a, b, c, gg, t + 1, 5, 0x5a827999)
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(a, b, c, d, gg, t + 0, 3, 0x5a827999)

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        printf("Round 2: %.8x %.8x %.8x %.8x\n", a, b, c, d);
#endif
                    }
                    for (unsigned t = policy_type::rounds / 3; t -= 4, t < policy_type::rounds / 3;) {
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(b, c, d, a, ff, t + 3, 19, 0x00000000)
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(c, d, a, b, ff, t + 2, 11, 0x00000000)
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(d, a, b, c, ff, t + 1, 7, 0x00000000)
                        CRYPTO3_BLOCK_MD4_DECRYPT_STEP(a, b, c, d, ff, t + 0, 3, 0x00000000)

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        printf("Round 1: %.8x %.8x %.8x %.8x\n", a, b, c, d);
#endif
                    }

                    return {{a, b, c, d}};
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHERS_MD4_HPP
