//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_TWOFISH_H_
#define CRYPTO3_TWOFISH_H_

#include <nil/crypto3/block/detail/twofish/twofish_policy.hpp>

#include <nil/crypto3/block/cipher_state_preprocessor.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Twofish. An AES contender. Somewhat complicated key setup
             * and a "kitchen sink" design.
             *
             * @ingroup block
             */
            template<std::size_t KeyBits>
            class twofish {
            protected:
                typedef detail::twofish_policy<KeyBits> policy_type;

                constexpr static const std::size_t key_schedule_size = policy_type::key_schedule_size;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                constexpr static const std::size_t expanded_substitution_size = policy_type::expanded_substitution_size;
                typedef typename policy_type::expanded_substitution_type expanded_substitution_type;

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
                    typedef cipher_state<Mode<twofish<KeyBits>, Padding>, stream_endian::little_octet_big_bit,
                                         ValueBits, policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                twofish(const key_type &key) {
                    schedule_key(key);
                }

                ~twofish() {
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
                expanded_substitution_type expanded_substitution;

                inline block_type encrypt_block(const block_type &plaintext) {
                    block_type out = {0};

                    word_type A, B, C, D;
                    load_le(plaintext.data(), A, B, C, D);

                    A ^= round_key[0];
                    B ^= round_key[1];
                    C ^= round_key[2];
                    D ^= round_key[3];

                    for (size_t k = 8; k != 40; k += 4) {
                        policy_type::tf_e(A, B, C, D, round_key[k], round_key[k + 1], expanded_substitution);
                        policy_type::tf_e(C, D, A, B, round_key[k + 2], round_key[k + 3], expanded_substitution);
                    }

                    C ^= round_key[4];
                    D ^= round_key[5];
                    A ^= round_key[6];
                    B ^= round_key[7];

                    store_le(out.data(), C, D, A, B);

                    return out;
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    block_type out = {0};

                    word_type A, B, C, D;
                    load_le(ciphertext.data(), A, B, C, D);

                    A ^= round_key[4];
                    B ^= round_key[5];
                    C ^= round_key[6];
                    D ^= round_key[7];

                    for (size_t k = 40; k != 8; k -= 4) {
                        policy_type::F_D(A, B, C, D, round_key[k - 2], round_key[k - 1], expanded_substitution);
                        policy_type::F_D(C, D, A, B, round_key[k - 4], round_key[k - 3], expanded_substitution);
                    }

                    C ^= round_key[0];
                    D ^= round_key[1];
                    A ^= round_key[2];
                    B ^= round_key[3];

                    store_le(out, C, D, A, B);

                    return out;
                }

                inline void schedule_key(const key_type &key) {
                    return policy_type::schedule_key(key, expanded_substitution, round_key);
                }
            };
        }
    }
}

#endif
