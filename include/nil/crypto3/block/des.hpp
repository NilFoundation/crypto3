//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DES_H_
#define CRYPTO3_DES_H_

#include <nil/crypto3/block/detail/des/des_functions.hpp>

#include <nil/crypto3/block/cipher_state_preprocessor.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief DES. Triple DES. Originally designed by IBM and NSA in the 1970s.
             *
             * Today, DES's 56-bit key renders it insecure to any well-resourced
             * attacker. DESX and 3DES extend the key length, and are still thought
             * to be secure, modulo the limitation of a 64-bit block.
             * All are somewhat common in some industries such as finance.
             * Avoid in new code.
             *
             * @ingroup block
             */
            class des {
            protected:

                typedef detail::des_functions<detail::des_policy> policy_type;

                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

            public:

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                template<template<typename, typename> class Mode, std::size_t ValueBits, typename Padding>
                struct stream_cipher {
                    typedef cipher_state<Mode<des, Padding>, stream_endian::little_octet_big_bit, ValueBits,
                                         policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                des(const key_type &key) {
                    schedule_key(key);
                }

                ~des() {
                    round_key.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

            protected:
                key_schedule_type round_key;

                inline void schedule_key(const key_type &key) {
                    policy_type::des_key_schedule(round_key, key);
                }

                inline block_type encrypt_block(const block_type &plaintext) {
                    block_type out = {0};
                    uint64_t T = (policy_type::iptab1[plaintext[0]]) | (policy_type::iptab1[plaintext[1]] << 1) |
                                 (policy_type::iptab1[plaintext[2]] << 2) | (policy_type::iptab1[plaintext[3]] << 3) |
                                 (policy_type::iptab1[plaintext[4]] << 4) | (policy_type::iptab1[plaintext[5]] << 5) |
                                 (policy_type::iptab1[plaintext[6]] << 6) | (policy_type::iptab2[plaintext[7]]);

                    word_type L = static_cast<uint32_t>(T >> 32);
                    word_type R = static_cast<uint32_t>(T);

                    policy_type::des_encrypt(L, R, round_key);

                    T = (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 0)] << 5) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 1)] << 3) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 2)] << 1) |
                        (policy_type::fptab2[extract_uint_t<CHAR_BIT>(L, 3)] << 1) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 0)] << 4) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 1)] << 2) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 2)]) |
                        (policy_type::fptab2[extract_uint_t<CHAR_BIT>(R, 3)]);
                    T = policy_type::rotl<32>(T);

                    store_be(T, out.data());

                    return out;
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    block_type out = {0};

                    uint64_t T = (policy_type::iptab1[ciphertext[0]]) | (policy_type::iptab1[ciphertext[1]] << 1) |
                                 (policy_type::iptab1[ciphertext[2]] << 2) | (policy_type::iptab1[ciphertext[3]] << 3) |
                                 (policy_type::iptab1[ciphertext[4]] << 4) | (policy_type::iptab1[ciphertext[5]] << 5) |
                                 (policy_type::iptab1[ciphertext[6]] << 6) | (policy_type::iptab2[ciphertext[7]]);

                    word_type L = static_cast<uint32_t>(T >> word_bits);
                    word_type R = static_cast<uint32_t>(T);

                    policy_type::des_decrypt(L, R, round_key);

                    T = (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 0)] << 5) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 1)] << 3) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 2)] << 1) |
                        (policy_type::fptab2[extract_uint_t<CHAR_BIT>(L, 3)] << 1) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 0)] << 4) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 1)] << 2) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 2)]) |
                        (policy_type::fptab2[extract_uint_t<CHAR_BIT>(R, 3)]);

                    T = policy_type::rotl<32>(T);

                    store_be(T, out.data());

                    return out;
                }
            };

            template<std::size_t KeyBits>
            class triple_des {
            protected:
                typedef detail::des_functions<detail::triple_des_policy<KeyBits>> policy_type;
            public:

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                triple_des(const key_type &key) {
                    schedule_key(key);
                }

                ~triple_des() {
                    round_key.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

            protected:

                key_schedule_type round_key;

                inline void schedule_key(const key_type &key) {
                    policy_type::des_key_schedule(&round_key[0], key);
                    policy_type::des_key_schedule(&round_key[32], key + 8);

                    if (key.size() == 24) {
                        policy_type::des_key_schedule(&round_key[64], key + 16);
                    } else {
                        copy_mem(&round_key[64], &round_key[0], 32);
                    }
                }

                inline block_type encrypt_block(const block_type &plaintext) {
                    block_type out = {0};

                    uint64_t T = (policy_type::iptab1[plaintext[0]]) | (policy_type::iptab1[plaintext[1]] << 1) |
                                 (policy_type::iptab1[plaintext[2]] << 2) | (policy_type::iptab1[plaintext[3]] << 3) |
                                 (policy_type::iptab1[plaintext[4]] << 4) | (policy_type::iptab1[plaintext[5]] << 5) |
                                 (policy_type::iptab1[plaintext[6]] << 6) | (policy_type::iptab2[plaintext[7]]);

                    word_type L = static_cast<uint32_t>(T >> word_bits);
                    word_type R = static_cast<uint32_t>(T);

                    policy_type::des_encrypt(L, R, &round_key[0]);
                    policy_type::des_decrypt(R, L, &round_key[32]);
                    policy_type::des_encrypt(L, R, &round_key[64]);

                    T = (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 0)] << 5) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 1)] << 3) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 2)] << 1) |
                        (policy_type::fptab2[extract_uint_t<CHAR_BIT>(L, 3)] << 1) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 0)] << 4) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 1)] << 2) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 2)]) |
                        (policy_type::fptab2[extract_uint_t<CHAR_BIT>(R, 3)]);

                    T = policy_type::rotl<32>(T);

                    store_be(T, out.data());

                    return out;
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    block_type out = {0};
                    uint64_t T = (policy_type::iptab1[ciphertext[0]]) | (policy_type::iptab1[ciphertext[1]] << 1) |
                                 (policy_type::iptab1[ciphertext[2]] << 2) | (policy_type::iptab1[ciphertext[3]] << 3) |
                                 (policy_type::iptab1[ciphertext[4]] << 4) | (policy_type::iptab1[ciphertext[5]] << 5) |
                                 (policy_type::iptab1[ciphertext[6]] << 6) | (policy_type::iptab2[ciphertext[7]]);

                    word_type L = static_cast<uint32_t>(T >> word_bits);
                    word_type R = static_cast<uint32_t>(T);

                    policy_type::des_decrypt(L, R, &round_key[64]);
                    policy_type::des_encrypt(R, L, &round_key[32]);
                    policy_type::des_decrypt(L, R, &round_key[0]);

                    T = (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 0)] << 5) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 1)] << 3) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(L, 2)] << 1) |
                        (policy_type::fptab2[extract_uint_t<CHAR_BIT>(L, 3)] << 1) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 0)] << 4) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 1)] << 2) |
                        (policy_type::fptab1[extract_uint_t<CHAR_BIT>(R, 2)]) |
                        (policy_type::fptab2[extract_uint_t<CHAR_BIT>(R, 3)]);

                    T = policy_type::rotl<32>(T);

                    store_be(T, out.data());

                    return out;
                }
            };
        }
    }
}

#endif
