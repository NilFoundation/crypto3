//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KASUMI_H_
#define CRYPTO3_KASUMI_H_

#include <nil/crypto3/block/detail/kasumi/kasumi_functions.hpp>

#include <nil/crypto3/block/cipher_state.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Kasumi. A 64-bit cipher used in 3GPP mobile phone protocols.
             * There is no reason to use it outside of this context.
             *
             * @ingroup block
             */
            class kasumi {
            protected:
                typedef detail::kasumi_functions policy_type;

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

                template<template<typename, typename> class Mode, std::size_t ValueBits, typename Padding>
                struct stream_cipher {
                    typedef cipher_state<Mode<kasumi, Padding>, stream_endian::little_octet_big_bit, ValueBits,
                                         policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                kasumi(const key_type &key) {
                    schedule_key(key);
                }

                ~kasumi() {
                    key_schedule.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

            protected:
                inline block_type encrypt_block(const block_type &plaintext) {
                    block_type out = {0};

                    uint16_t B0 = load_be<uint16_t>(plaintext.data(), 0);
                    uint16_t B1 = load_be<uint16_t>(plaintext.data(), 1);
                    uint16_t B2 = load_be<uint16_t>(plaintext.data(), 2);
                    uint16_t B3 = load_be<uint16_t>(plaintext.data(), 3);

                    for (size_t j = 0; j != rounds; j += 2) {
                        const uint16_t *K = &key_schedule[8 * j];

                        uint16_t R = B1 ^(rotl<1>(B0) & K[0]);
                        uint16_t L = B0 ^(rotl<1>(R) | K[1]);

                        L = policy_type::FI(L ^ K[2], K[3]) ^ R;
                        R = policy_type::FI(R ^ K[4], K[5]) ^ L;
                        L = policy_type::FI(L ^ K[6], K[7]) ^ R;

                        R = B2 ^= R;
                        L = B3 ^= L;

                        R = policy_type::FI(R ^ K[10], K[11]) ^ L;
                        L = policy_type::FI(L ^ K[12], K[13]) ^ R;
                        R = policy_type::FI(R ^ K[14], K[15]) ^ L;

                        R ^= (rotl<1>(L) & K[8]);
                        L ^= (rotl<1>(R) | K[9]);

                        B0 ^= L;
                        B1 ^= R;
                    }

                    store_be(out.data(), B0, B1, B2, B3);

                    return out;
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    block_type out = {0};

                    word_type B0 = load_be<uint16_t>(ciphertext.data(), 0);
                    word_type B1 = load_be<uint16_t>(ciphertext.data(), 1);
                    word_type B2 = load_be<uint16_t>(ciphertext.data(), 2);
                    word_type B3 = load_be<uint16_t>(ciphertext.data(), 3);

                    for (size_t j = 0; j != rounds; j += 2) {
                        const word_type *K = &key_schedule[8 * (6 - j)];

                        uint16_t L = B2, R = B3;

                        L = policy_type::FI(L ^ K[10], K[11]) ^ R;
                        R = policy_type::FI(R ^ K[12], K[13]) ^ L;
                        L = policy_type::FI(L ^ K[14], K[15]) ^ R;

                        L ^= (rotl<1>(R) & K[8]);
                        R ^= (rotl<1>(L) | K[9]);

                        R = B0 ^= R;
                        L = B1 ^= L;

                        L ^= (rotl<1>(R) & K[0]);
                        R ^= (rotl<1>(L) | K[1]);

                        R = policy_type::FI(R ^ K[2], K[3]) ^ L;
                        L = policy_type::FI(L ^ K[4], K[5]) ^ R;
                        R = policy_type::FI(R ^ K[6], K[7]) ^ L;

                        B2 ^= L;
                        B3 ^= R;
                    }

                    store_be(out.data(), B0, B1, B2, B3);

                    return out;
                }

                key_schedule_type key_schedule;

                void schedule_key(const key_type &key) {
                    secure_vector<uint16_t> K(16);
                    for (size_t i = 0; i != rounds; ++i) {
                        K[i] = load_be<uint16_t>(key, i);
                        K[i + 8] = K[i] ^ policy_type::round_constants[i];
                    }

                    for (size_t i = 0; i != rounds; ++i) {
                        key_schedule[8 * i] = rotl<2>(K[(i + 0) % 8]);
                        key_schedule[8 * i + 1] = rotl<1>(K[(i + 2) % 8 + 8]);
                        key_schedule[8 * i + 2] = rotl<5>(K[(i + 1) % 8]);
                        key_schedule[8 * i + 3] = K[(i + 4) % 8 + 8];
                        key_schedule[8 * i + 4] = rotl<8>(K[(i + 5) % 8]);
                        key_schedule[8 * i + 5] = K[(i + 3) % 8 + 8];
                        key_schedule[8 * i + 6] = rotl<13>(K[(i + 6) % 8]);
                        key_schedule[8 * i + 7] = K[(i + 7) % 8 + 8];
                    }
                }
            };
        }
    }
}
#endif
