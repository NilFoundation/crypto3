//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CAMELLIA_H_
#define CRYPTO3_CAMELLIA_H_

#include <nil/crypto3/block/detail/camellia/camellia_policy.hpp>

#include <nil/crypto3/block/cipher_state.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @ingroup block
             * @brief Camellia. A Japanese design standardized by ISO, NESSIE and
             * CRYPTREC. Somewhat common. Comes in three variants, Camellia-128,
             * Camellia-192, and Camellia-256. Prefer AES or Serpent in new designs.
             */
            template<std::size_t Size>
            class camellia {
            protected:

                constexpr static const std::size_t version = Size;
                typedef detail::camellia_policy<Size> policy_type;

                constexpr static const std::size_t key_schedule_words = policy_type::key_schedule_words;
                typedef typename policy_type::key_schedule_type key_schedule_type;

            public:

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t rounds = policy_type::rounds;

                template<template<typename, typename> class Mode, std::size_t ValueBits, typename Padding>
                struct stream_cipher {
                    typedef cipher_state<Mode<camellia<Size>, Padding>, stream_endian::little_octet_big_bit, ValueBits,
                                         policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                camellia(const key_type &key) {
                    schedule_key(key);
                }

                virtual ~camellia() {
                    key_schedule.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

            protected:

                key_schedule_type key_schedule;

                inline block_type encrypt_block(const block_type &plaintext) {
                    block_type out = {0};

                    word_type d1, d2;
                    load_be(plaintext.data(), d1, d2);

                    const uint64_t *K = key_schedule.data();

                    d1 ^= *K++;
                    d2 ^= *K++;

                    d2 ^= policy_type::f_slow(d1, *K++);
                    d1 ^= policy_type::f_slow(d2, *K++);

                    for (size_t r = 1; r != rounds / 2 - 1; ++r) {
                        if (r % 3 == 0) {
                            d1 = policy_type::fl(d1, *K++);
                            d2 = policy_type::flinv(d2, *K++);
                        }

                        d2 ^= policy_type::f(d1, *K++);
                        d1 ^= policy_type::f(d2, *K++);
                    }

                    d2 ^= policy_type::f_slow(d1, *K++);
                    d1 ^= policy_type::f_slow(d2, *K++);

                    d2 ^= *K++;
                    d1 ^= *K++;

                    store_be(out.data() + 16, d2, d1);
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    block_type out = {0};

                    word_type d1, d2;
                    load_be(ciphertext.data(), d1, d2);

                    const uint64_t *K = &key_schedule[key_schedule.size() - 1];

                    d2 ^= *K--;
                    d1 ^= *K--;

                    d2 ^= policy_type::f_slow(d1, *K--);
                    d1 ^= policy_type::f_slow(d2, *K--);

                    for (size_t r = 1; r != rounds / 2 - 1; ++r) {
                        if (r % 3 == 0) {
                            d1 = policy_type::fl(d1, *K--);
                            d2 = policy_type::flinv(d2, *K--);
                        }

                        d2 ^= policy_type::f(d1, *K--);
                        d1 ^= policy_type::f(d2, *K--);
                    }

                    d2 ^= policy_type::f_slow(d1, *K--);
                    d1 ^= policy_type::f_slow(d2, *K--);

                    d1 ^= *K--;
                    d2 ^= *K;

                    store_be(out.data(), d2, d1);
                }

                inline uint64_t left_rot_hi(uint64_t h, uint64_t l, size_t shift) {
                    return (h << shift) | (l >> (64 - shift));
                }

                inline uint64_t left_rot_lo(uint64_t h, uint64_t l, size_t shift) {
                    return (h >> (64 - shift)) | (l << shift);
                }

                void schedule_key(const key_type &key) {
                    const word_type KL_H = load_be<uint64_t>(key, 0);
                    const word_type KL_L = load_be<uint64_t>(key, 1);

                    const word_type KR_H = (key.size() >= 24) ? load_be<uint64_t>(key, 2) : 0;
                    const word_type KR_L = (key.size() == 32) ? load_be<uint64_t>(key, 3) : ((key.size() == 24) ? ~KR_H
                                                                                                                : 0);

                    word_type D1 = KL_H ^KR_H;
                    word_type D2 = KL_L ^KR_L;
                    D2 ^= policy_type::f(D1, policy_type::sigma[1]);
                    D1 ^= policy_type::f(D2, policy_type::sigma[2]);
                    D1 ^= KL_H;
                    D2 ^= KL_L;
                    D2 ^= policy_type::f(D1, policy_type::sigma[3]);
                    D1 ^= policy_type::f(D2, policy_type::sigma[4]);

                    const word_type KA_H = D1;
                    const word_type KA_L = D2;

                    D1 = KA_H ^ KR_H;
                    D2 = KA_L ^ KR_L;
                    D2 ^= policy_type::f(D1, policy_type::sigma[5]);
                    D1 ^= policy_type::f(D2, policy_type::sigma[6]);

                    const word_type KB_H = D1;
                    const word_type KB_L = D2;

                    if (key.size() == 16) {
                        key_schedule[0] = KL_H;
                        key_schedule[1] = KL_L;
                        key_schedule[2] = KA_H;
                        key_schedule[3] = KA_L;
                        key_schedule[4] = left_rot_hi(KL_H, KL_L, 15);
                        key_schedule[5] = left_rot_lo(KL_H, KL_L, 15);
                        key_schedule[6] = left_rot_hi(KA_H, KA_L, 15);
                        key_schedule[7] = left_rot_lo(KA_H, KA_L, 15);
                        key_schedule[8] = left_rot_hi(KA_H, KA_L, 30);
                        key_schedule[9] = left_rot_lo(KA_H, KA_L, 30);
                        key_schedule[10] = left_rot_hi(KL_H, KL_L, 45);
                        key_schedule[11] = left_rot_lo(KL_H, KL_L, 45);
                        key_schedule[12] = left_rot_hi(KA_H, KA_L, 45);
                        key_schedule[13] = left_rot_lo(KL_H, KL_L, 60);
                        key_schedule[14] = left_rot_hi(KA_H, KA_L, 60);
                        key_schedule[15] = left_rot_lo(KA_H, KA_L, 60);
                        key_schedule[16] = left_rot_lo(KL_H, KL_L, 77 - 64);
                        key_schedule[17] = left_rot_hi(KL_H, KL_L, 77 - 64);
                        key_schedule[18] = left_rot_lo(KL_H, KL_L, 94 - 64);
                        key_schedule[19] = left_rot_hi(KL_H, KL_L, 94 - 64);
                        key_schedule[20] = left_rot_lo(KA_H, KA_L, 94 - 64);
                        key_schedule[21] = left_rot_hi(KA_H, KA_L, 94 - 64);
                        key_schedule[22] = left_rot_lo(KL_H, KL_L, 111 - 64);
                        key_schedule[23] = left_rot_hi(KL_H, KL_L, 111 - 64);
                        key_schedule[24] = left_rot_lo(KA_H, KA_L, 111 - 64);
                        key_schedule[25] = left_rot_hi(KA_H, KA_L, 111 - 64);
                    } else {
                        key_schedule[0] = KL_H;
                        key_schedule[1] = KL_L;
                        key_schedule[2] = KB_H;
                        key_schedule[3] = KB_L;

                        key_schedule[4] = left_rot_hi(KR_H, KR_L, 15);
                        key_schedule[5] = left_rot_lo(KR_H, KR_L, 15);
                        key_schedule[6] = left_rot_hi(KA_H, KA_L, 15);
                        key_schedule[7] = left_rot_lo(KA_H, KA_L, 15);

                        key_schedule[8] = left_rot_hi(KR_H, KR_L, 30);
                        key_schedule[9] = left_rot_lo(KR_H, KR_L, 30);
                        key_schedule[10] = left_rot_hi(KB_H, KB_L, 30);
                        key_schedule[11] = left_rot_lo(KB_H, KB_L, 30);

                        key_schedule[12] = left_rot_hi(KL_H, KL_L, 45);
                        key_schedule[13] = left_rot_lo(KL_H, KL_L, 45);
                        key_schedule[14] = left_rot_hi(KA_H, KA_L, 45);
                        key_schedule[15] = left_rot_lo(KA_H, KA_L, 45);

                        key_schedule[16] = left_rot_hi(KL_H, KL_L, 60);
                        key_schedule[17] = left_rot_lo(KL_H, KL_L, 60);
                        key_schedule[18] = left_rot_hi(KR_H, KR_L, 60);
                        key_schedule[19] = left_rot_lo(KR_H, KR_L, 60);
                        key_schedule[20] = left_rot_hi(KB_H, KB_L, 60);
                        key_schedule[21] = left_rot_lo(KB_H, KB_L, 60);

                        key_schedule[22] = left_rot_lo(KL_H, KL_L, 77 - 64);
                        key_schedule[23] = left_rot_hi(KL_H, KL_L, 77 - 64);
                        key_schedule[24] = left_rot_lo(KA_H, KA_L, 77 - 64);
                        key_schedule[25] = left_rot_hi(KA_H, KA_L, 77 - 64);

                        key_schedule[26] = left_rot_lo(KR_H, KR_L, 94 - 64);
                        key_schedule[27] = left_rot_hi(KR_H, KR_L, 94 - 64);
                        key_schedule[28] = left_rot_lo(KA_H, KA_L, 94 - 64);
                        key_schedule[29] = left_rot_hi(KA_H, KA_L, 94 - 64);
                        key_schedule[30] = left_rot_lo(KL_H, KL_L, 111 - 64);
                        key_schedule[31] = left_rot_hi(KL_H, KL_L, 111 - 64);
                        key_schedule[32] = left_rot_lo(KB_H, KB_L, 111 - 64);
                        key_schedule[33] = left_rot_hi(KB_H, KB_L, 111 - 64);
                    }
                }
            };
        }
    }
}

#endif