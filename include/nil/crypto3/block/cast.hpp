//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CAST_H_
#define CRYPTO3_CAST_H_

#include <nil/crypto3/block/detail/cast/cast_policy.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Cast-family ciphers. Variants available: Cast128, Cast256.
             *
             * Cast128. A 64-bit cipher, commonly used in OpenPGP.
             *
             * Cast256. A 128-bit cipher that was a contestent in the NIST AES competition.
             * Rarely used, and now probably would be deprecated in crypto3. Use AES or Serpent instead.
             *
             * @ingroup block
             *
             * @tparam Version Version selector value. Available values are: 128, 256.
             * @tparam KeyBits
             */
            template<std::size_t Version, std::size_t KeyBits>
            class cast {
            protected:

                typedef typename detail::cast_policy<Version, KeyBits> policy_type;

                typedef typename policy_type::rotation_key_schedule_type rotation_key_schedule_type;
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

                template<template<typename, typename> class Mode,
                                                      typename StateAccumulator, std::size_t ValueBits,
                                                      typename Padding>
                struct stream_cipher {
                    typedef block_stream_processor<Mode<cast<Version, KeyBits>, Padding>, StateAccumulator,
                                                     stream_endian::little_octet_big_bit, ValueBits,
                                                     policy_type::word_bits * 2> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                cast(const key_type &key) {
                    schedule_key(key);
                }

                virtual ~cast() {
                    key_schedule.fill(0);
                    rkey_schedule.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

            protected:
                key_schedule_type key_schedule;
                rotation_key_schedule_type rkey_schedule;

                inline block_type encrypt_block(const block_type &plaintext) {
                    return policy_type::encrypt_block(plaintext, key_schedule, rkey_schedule);
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    return policy_type::decrypt_block(ciphertext, key_schedule, rkey_schedule);
                }

                inline void schedule_key(const key_type &key) {
                    policy_type::schedule_key(key, key_schedule, rkey_schedule);
                }
            };
        }
    }
}
#endif
