//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SEED_H_
#define CRYPTO3_SEED_H_

#include <nil/crypto3/block/detail/seed/seed_policy.hpp>

#include <nil/crypto3/block/cipher_state.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Seed. A older South Korean cipher, widely used in industry
             * there.
             *
             * @ingroup block
             */
            class seed {
            protected:
                typedef detail::seed_policy policy_type;

                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

            public:

                constexpr static const std::size_t rounds = policy_type::rounds;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                seed(const key_type &key) {
                    schedule_key(key);
                }

                ~seed() {
                    key_schedule.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

                template<template<typename, typename> class Mode, std::size_t ValueBits, typename Padding>
                struct stream_cipher {
                    typedef cipher_state<Mode<seed, Padding>, stream_endian::little_octet_big_bit, ValueBits,
                                         policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

            protected:
                key_schedule_type key_schedule;

                inline block_type encrypt_block(const block_type &plaintext) {
//                    word_type B0 = load_be<uint32_t>(plaintext.data(), 0);
//                    word_type B1 = load_be<uint32_t>(plaintext.data(), 1);
//                    word_type B2 = load_be<uint32_t>(plaintext.data(), 2);
//                    word_type B3 = load_be<uint32_t>(plaintext.data(), 3);

                    word_type B0 = plaintext[0];
                    word_type B1 = plaintext[1];
                    word_type B2 = plaintext[2];
                    word_type B3 = plaintext[3];

                    for (size_t j = 0; j != policy_type::rounds; j += 2) {
                        word_type T0, T1;

                        T0 = B2 ^ key_schedule[2 * j];
                        T1 = policy_type::g(B2 ^ B3 ^ key_schedule[2 * j + 1]);
                        T0 = policy_type::g(T1 + T0);
                        T1 = policy_type::g(T1 + T0);
                        B1 ^= T1;
                        B0 ^= T0 + T1;

                        T0 = B0 ^ key_schedule[2 * j + 2];
                        T1 = policy_type::g(B0 ^ B1 ^ key_schedule[2 * j + 3]);
                        T0 = policy_type::g(T1 + T0);
                        T1 = policy_type::g(T1 + T0);
                        B3 ^= T1;
                        B2 ^= T0 + T1;
                    }

//                    block_type out = {0};
//                    store_be(out.data(), B2, B3, B0, B1);

                    return {B2, B3, B0, B1};
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    block_type out = {0};

                    word_type B0 = ciphertext[0];
                    word_type B1 = ciphertext[1];
                    word_type B2 = ciphertext[2];
                    word_type B3 = ciphertext[3];

//                    word_type B0 = load_be<uint32_t>(ciphertext.data(), 0);
//                    word_type B1 = load_be<uint32_t>(ciphertext.data(), 1);
//                    word_type B2 = load_be<uint32_t>(ciphertext.data(), 2);
//                    word_type B3 = load_be<uint32_t>(ciphertext.data(), 3);

                    for (size_t j = 0; j != policy_type::rounds; j += 2) {
                        word_type T0, T1;

                        T0 = B2 ^ key_schedule[30 - 2 * j];
                        T1 = policy_type::g(B2 ^ B3 ^ key_schedule[31 - 2 * j]);
                        T0 = policy_type::g(T1 + T0);
                        T1 = policy_type::g(T1 + T0);
                        B1 ^= T1;
                        B0 ^= T0 + T1;

                        T0 = B0 ^ key_schedule[28 - 2 * j];
                        T1 = policy_type::g(B0 ^ B1 ^ key_schedule[29 - 2 * j]);
                        T0 = policy_type::g(T1 + T0);
                        T1 = policy_type::g(T1 + T0);
                        B3 ^= T1;
                        B2 ^= T0 + T1;
                    }

//                    store_be(out.data(), B2, B3, B0, B1);

                    return {B2, B3, B0, B1};
                }

                inline void schedule_key(const key_type &key) {
                    std::array<word_type, 4> WK = {0};

                    for (size_t i = 0; i != 4; ++i) {
                        WK[i] = load_be<uint32_t>(key, i);
                    }

                    for (size_t i = 0; i != 16; i += 2) {
                        key_schedule[2 * i] = policy_type::g(WK[0] + WK[2] - policy_type::round_constants[i]);
                        key_schedule[2 * i + 1] =
                                policy_type::g(WK[1] - WK[3] + policy_type::round_constants[i]) ^ key_schedule[2 * i];

                        uint32_t T = (WK[0] & 0xFF) << 24;
                        WK[0] = (WK[0] >> 8) | (get_byte(3, WK[1]) << 24);
                        WK[1] = (WK[1] >> 8) | T;

                        key_schedule[2 * i + 2] = policy_type::g(WK[0] + WK[2] - policy_type::round_constants[i + 1]);
                        key_schedule[2 * i + 3] = policy_type::g(WK[1] - WK[3] + policy_type::round_constants[i + 1]) ^
                                                  key_schedule[2 * i + 2];

                        T = get_byte(0, WK[3]);
                        WK[3] = (WK[3] << 8) | get_byte(0, WK[2]);
                        WK[2] = (WK[2] << 8) | T;
                    }
                }
            };
        }
    }
}

#endif
