//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SM4_H_
#define CRYPTO3_SM4_H_

#include <nil/crypto3/block/detail/sm4/sm4_policy.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

#include <nil/crypto3/block/cipher_state_preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief SM4. A 128-bit Chinese national cipher, required for use
             * in certain commercial applications in China. Quite slow. Probably
             * no reason to use it outside of legal requirements.
             *
             * @ingroup block
             */
            class sm4 {
            protected:
                typedef detail::sm4_policy policy_type;

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
                    typedef cipher_state<Mode<sm4, Padding>, stream_endian::little_octet_big_bit, ValueBits,
                                         policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                sm4(const key_type &key) {
                    schedule_key(key);
                }

                ~sm4() {
                    key_schedule.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

            protected:

#define SM4_RNDS(k0, k1, k2, k3, F) do {        \
         B0 ^= F(B1 ^ B2 ^ B3 ^ key_schedule[k0]); \
         B1 ^= F(B0 ^ B2 ^ B3 ^ key_schedule[k1]); \
         B2 ^= F(B0 ^ B1 ^ B3 ^ key_schedule[k2]); \
         B3 ^= F(B0 ^ B1 ^ B2 ^ key_schedule[k3]); \
      } while(0)

                key_schedule_type key_schedule;

                inline block_type encrypt_block(const block_type &plaintext) {
                    block_type out = {0};

                    word_type B0 = load_be<uint32_t>(plaintext.data(), 0);
                    word_type B1 = load_be<uint32_t>(plaintext.data(), 1);
                    word_type B2 = load_be<uint32_t>(plaintext.data(), 2);
                    word_type B3 = load_be<uint32_t>(plaintext.data(), 3);

                    SM4_RNDS(0, 1, 2, 3, policy_type::t_slow);
                    SM4_RNDS(4, 5, 6, 7, policy_type::t);
                    SM4_RNDS(8, 9, 10, 11, policy_type::t);
                    SM4_RNDS(12, 13, 14, 15, policy_type::t);
                    SM4_RNDS(16, 17, 18, 19, policy_type::t);
                    SM4_RNDS(20, 21, 22, 23, policy_type::t);
                    SM4_RNDS(24, 25, 26, 27, policy_type::t);
                    SM4_RNDS(28, 29, 30, 31, policy_type::t_slow);

                    store_be(out.data(), B3, B2, B1, B0);

                    return out;
                }

                inline block_type decrypt_block(const block_type &plaintext) {
                    block_type out = {0};

                    word_type B0 = load_be<uint32_t>(plaintext.data(), 0);
                    word_type B1 = load_be<uint32_t>(plaintext.data(), 1);
                    word_type B2 = load_be<uint32_t>(plaintext.data(), 2);
                    word_type B3 = load_be<uint32_t>(plaintext.data(), 3);

                    SM4_RNDS(31, 30, 29, 28, policy_type::t_slow);
                    SM4_RNDS(27, 26, 25, 24, policy_type::t);
                    SM4_RNDS(23, 22, 21, 20, policy_type::t);
                    SM4_RNDS(19, 18, 17, 16, policy_type::t);
                    SM4_RNDS(15, 14, 13, 12, policy_type::t);
                    SM4_RNDS(11, 10, 9, 8, policy_type::t);
                    SM4_RNDS(7, 6, 5, 4, policy_type::t);
                    SM4_RNDS(3, 2, 1, 0, policy_type::t_slow);

                    store_be(out.data(), B3, B2, B1, B0);

                    return out;
                }

                void schedule_key(const key_type &key) {
                    // System parameter or family key
                    const uint32_t FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

                    const uint32_t CK[32] = {
                            0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD,
                            0xC4CBD2D9, 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249, 0x50575E65, 0x6C737A81,
                            0x888F969D, 0xA4ABB2B9, 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229, 0x30373E45,
                            0x4C535A61, 0x686F767D, 0x848B9299, 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
                            0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
                    };

                    std::array<word_type, 4> K = {0};
                    K[0] = load_be<uint32_t>(key, 0) ^ FK[0];
                    K[1] = load_be<uint32_t>(key, 1) ^ FK[1];
                    K[2] = load_be<uint32_t>(key, 2) ^ FK[2];
                    K[3] = load_be<uint32_t>(key, 3) ^ FK[3];

                    for (size_t i = 0; i != 32; ++i) {
                        K[i % 4] ^= policy_type::tp(K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i]);
                        key_schedule[i] = K[i % 4];
                    }
                }
            };
        }
    }
}
#endif
