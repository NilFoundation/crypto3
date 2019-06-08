//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MISTY1_H_
#define CRYPTO3_MISTY1_H_

#include <nil/crypto3/block/detail/misty1/misty1_functions.hpp>

#include <nil/crypto3/block/detail/block_state_preprocessor.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Misty1. A 64-bit Japanese cipher standardized by NESSIE and ISO.
             * Seemingly secure, but quite slow and saw little adoption. No reason
             * to use it in new code.
             *
             * @ingroup block
             */
            class misty1 {
            protected:
                typedef detail::misty1_functions policy_type;

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

                template<template<typename, typename> class Mode,
                                                      typename StateAccumulator, std::size_t ValueBits,
                                                      typename Padding>
                struct stream_cipher {
                    typedef block_state_preprocessor<Mode<misty1, Padding>, StateAccumulator,
                                                     stream_endian::little_octet_big_bit, ValueBits,
                                                     policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                misty1(const key_type &key) {
                    schedule_key(key);
                }

                ~misty1() {
                    encryption_key.fill(0);
                    decryption_key.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

            protected:
                key_schedule_type encryption_key, decryption_key;

                inline block_type encrypt_block(const block_type &plaintext) {
                    block_type out = {0};

                    uint16_t B0 = load_be<uint16_t>(plaintext.data(), 0);
                    uint16_t B1 = load_be<uint16_t>(plaintext.data(), 1);
                    uint16_t B2 = load_be<uint16_t>(plaintext.data(), 2);
                    uint16_t B3 = load_be<uint16_t>(plaintext.data(), 3);

                    for (size_t j = 0; j != 12; j += 3) {
                        const uint16_t *RK = &encryption_key[8 * j];

                        B1 ^= B0 & RK[0];
                        B0 ^= B1 | RK[1];
                        B3 ^= B2 & RK[2];
                        B2 ^= B3 | RK[3];

                        uint16_t T0, T1;

                        T0 = policy_type::FI(B0 ^ RK[4], RK[5], RK[6]) ^ B1;
                        T1 = policy_type::FI(B1 ^ RK[7], RK[8], RK[9]) ^ T0;
                        T0 = policy_type::FI(T0 ^ RK[10], RK[11], RK[12]) ^ T1;

                        B2 ^= T1 ^ RK[13];
                        B3 ^= T0;

                        T0 = policy_type::FI(B2 ^ RK[14], RK[15], RK[16]) ^ B3;
                        T1 = policy_type::FI(B3 ^ RK[17], RK[18], RK[19]) ^ T0;
                        T0 = policy_type::FI(T0 ^ RK[20], RK[21], RK[22]) ^ T1;

                        B0 ^= T1 ^ RK[23];
                        B1 ^= T0;
                    }

                    B1 ^= B0 & encryption_key[96];
                    B0 ^= B1 | encryption_key[97];
                    B3 ^= B2 & encryption_key[98];
                    B2 ^= B3 | encryption_key[99];

                    store_be(out, B2, B3, B0, B1);

                    return out;
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    block_type out = {0};

                    uint16_t B0 = load_be<uint16_t>(ciphertext.data(), 2);
                    uint16_t B1 = load_be<uint16_t>(ciphertext.data(), 3);
                    uint16_t B2 = load_be<uint16_t>(ciphertext.data(), 0);
                    uint16_t B3 = load_be<uint16_t>(ciphertext.data(), 1);

                    for (size_t j = 0; j != 12; j += 3) {
                        const uint16_t *RK = &decryption_key[8 * j];

                        B2 ^= B3 | RK[0];
                        B3 ^= B2 & RK[1];
                        B0 ^= B1 | RK[2];
                        B1 ^= B0 & RK[3];

                        uint16_t T0, T1;

                        T0 = policy_type::FI(B2 ^ RK[4], RK[5], RK[6]) ^ B3;
                        T1 = policy_type::FI(B3 ^ RK[7], RK[8], RK[9]) ^ T0;
                        T0 = policy_type::FI(T0 ^ RK[10], RK[11], RK[12]) ^ T1;

                        B0 ^= T1 ^ RK[13];
                        B1 ^= T0;

                        T0 = policy_type::FI(B0 ^ RK[14], RK[15], RK[16]) ^ B1;
                        T1 = policy_type::FI(B1 ^ RK[17], RK[18], RK[19]) ^ T0;
                        T0 = policy_type::FI(T0 ^ RK[20], RK[21], RK[22]) ^ T1;

                        B2 ^= T1 ^ RK[23];
                        B3 ^= T0;
                    }

                    B2 ^= B3 | decryption_key[96];
                    B3 ^= B2 & decryption_key[97];
                    B0 ^= B1 | decryption_key[98];
                    B1 ^= B0 & decryption_key[99];

                    store_be(out.data(), B0, B1, B2, B3);

                    return out;
                }

                inline void schedule_key(const key_type &key) {
                    std::array<word_type, 32> schedule = {0};
                    for (size_t i = 0; i != key.size() / 2; ++i) {
                        schedule[i] = load_be<uint16_t>(key, i);
                    }

                    for (size_t i = 0; i != rounds; ++i) {
                        schedule[i + 8] = policy_type::FI(schedule[i], schedule[(i + 1) % 8] >> 9,
                                schedule[(i + 1) % 8] & 0x1FF);
                        schedule[i + 16] = schedule[i + 8] >> 9;
                        schedule[i + 24] = schedule[i + 8] & 0x1FF;
                    }

                    for (size_t i = 0; i != key_schedule_size; ++i) {
                        encryption_key[i] = schedule[policy_type::encryption_key_order[i]];
                        decryption_key[i] = schedule[policy_type::decryption_key_order[i]];
                    }
                }
            };
        }
    }
}
#endif
