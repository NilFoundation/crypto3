//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_DES_HPP
#define CRYPTO3_BLOCK_DES_HPP

#include <boost/endian/arithmetic.hpp>

#include <nil/crypto3/block/detail/des/des_functions.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

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

                template<class Mode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode, StateAccumulator, params_type> type;
                };

                typedef typename stream_endian::little_octet_big_bit endian_type;

                des(const key_type &key) {
                    schedule_key(key);
                }

                ~des() {
                    round_key.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return decrypt_block(ciphertext);
                }

            protected:
                key_schedule_type round_key;

                inline void schedule_key(const key_type &key) {
                    policy_type::des_key_schedule(round_key, key);
                }

                inline block_type encrypt_block(const block_type &plaintext) const {
                    block_type out;

                    word_type L, R;
                    policy_type::ip(L, R, plaintext);
                    policy_type::des_encrypt(L, R, round_key);
                    policy_type::fp(L, R, out);

                    return out;
                }

                inline block_type decrypt_block(const block_type &ciphertext) const {
                    block_type out;

                    word_type L, R;
                    policy_type::ip(L, R, ciphertext);
                    policy_type::des_decrypt(L, R, round_key);
                    policy_type::fp(L, R, out);

                    return out;
                }
            };

            template<std::size_t KeyBits>
            class triple_des {
            protected:
                typedef detail::des_functions<detail::triple_des_policy<KeyBits>> policy_type;

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

                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                template<template<typename, typename> class Mode, typename StateAccumulator, std::size_t ValueBits,
                         typename Padding>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian_type;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode<triple_des<KeyBits>, Padding>, StateAccumulator, params_type>
                        type;
                };

                triple_des(const key_type &key) {
                    schedule_key(key);
                }

                ~triple_des() {
                    round_key.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
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

                inline block_type encrypt_block(const block_type &plaintext) const {
                    block_type out;
                    word_type L, R;

                    policy_type::ip(L, R, plaintext);

                    policy_type::des_encrypt(L, R, &round_key[0]);
                    policy_type::des_decrypt(R, L, &round_key[32]);
                    policy_type::des_encrypt(L, R, &round_key[64]);

                    policy_type::fp(L, R, out);

                    return out;
                }

                inline block_type decrypt_block(const block_type &ciphertext) const {
                    block_type out;
                    word_type L, R;

                    policy_type::ip(L, R, ciphertext);

                    policy_type::des_decrypt(L, R, &round_key[64]);
                    policy_type::des_encrypt(R, L, &round_key[32]);
                    policy_type::des_decrypt(L, R, &round_key[0]);

                    policy_type::fp(L, R, out);

                    return out;
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif
