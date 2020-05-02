//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_CAMELLIA_HPP
#define CRYPTO3_BLOCK_CAMELLIA_HPP

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>

#include <nil/crypto3/block/detail/camellia/camellia_policy.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @ingroup block
             * @brief Camellia. A Japanese design standardized by ISO, NESSIE and
             * CRYPTREC. Somewhat common. Comes in three variants, Camellia-128,
             * Camellia-192, and Camellia-256. Prefer AES or Serpent in new designs.
             *
             * @tparam KeyBits Block cipher key bits. Supported values are: 128, 192, 256
             */
            template<std::size_t KeyBits>
            class camellia {
            protected:
                constexpr static const std::size_t version = KeyBits;
                typedef detail::camellia_policy<KeyBits> policy_type;

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

                template<template<typename, typename> class Mode, typename StateAccumulator, std::size_t ValueBits,
                         typename Padding>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian_type;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode<camellia<KeyBits>, Padding>, StateAccumulator, params_type> type_;

                };

                camellia(const key_type &key) {
                    schedule_key(key);
                }

                virtual ~camellia() {
                    key_schedule.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return decrypt_block(ciphertext);
                }

            protected:
                key_schedule_type key_schedule;

                inline block_type encrypt_block(const block_type &plaintext) const {
                    word_type d1 = boost::endian::native_to_big(plaintext[0]);
                    word_type d2 = boost::endian::native_to_big(plaintext[1]);

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

                    return {boost::endian::big_to_native(d2), boost::endian::big_to_native(d1)};
                }

                inline block_type decrypt_block(const block_type &ciphertext) const {
                    word_type d1 = boost::endian::native_to_big(ciphertext[0]);
                    word_type d2 = boost::endian::native_to_big(ciphertext[1]);

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

                    return {boost::endian::big_to_native(d2), boost::endian::big_to_native(d1)};
                }

                inline uint64_t left_rot_hi(uint64_t h, uint64_t l, size_t shift) {
                    return (h << shift) | (l >> (64 - shift));
                }

                inline uint64_t left_rot_lo(uint64_t h, uint64_t l, size_t shift) {
                    return (h >> (64 - shift)) | (l << shift);
                }

                void schedule_key(const key_type &key) {
                    const word_type KL_H = boost::endian::native_to_big(key[0]);
                    const word_type KL_L = boost::endian::native_to_big(key[1]);

                    const word_type KR_H = (key.size() >= 24) ? boost::endian::native_to_big(key[2]) : 0;
                    const word_type KR_L =
                        (key.size() == 32) ? boost::endian::native_to_big(key[3]) : ((key.size() == 24) ? ~KR_H : 0);

                    word_type D1 = KL_H ^ KR_H;
                    word_type D2 = KL_L ^ KR_L;
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
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif