//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_IDEA_HPP
#define CRYPTO3_IDEA_HPP

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>

#include <nil/crypto3/block/detail/idea/idea_policy.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Idea. An older but still unbroken 64-bit cipher with a
             * 128-bit key. Somewhat common due to its use in PGP. Avoid in new
             * designs.
             *
             * @ingroup block
             */
            class idea {
            protected:
                typedef detail::idea_policy policy_type;

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

                template<template<typename, typename> class Mode, typename StateAccumulator, std::size_t ValueBits,
                         typename Padding>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian_type;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode<idea, Padding>, StateAccumulator, params_type> type_;
#ifdef CRYPTO3_BLOCK_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {};
#endif
                };

                idea(const key_type &key) {
                    schedule_key(key);
                }

                ~idea() {
                    encryption_key.fill(0);
                    decryption_key.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return idea_op(plaintext, encryption_key);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return idea_op(ciphertext, decryption_key);
                }

            protected:
                key_schedule_type encryption_key, decryption_key;

                static inline block_type idea_op(const block_type &input, const key_schedule_type &key) {
                    block_type out = {0};
                    word_type X1 = boost::endian::native_to_big(input[0]);
                    word_type X2 = boost::endian::native_to_big(input[1]);
                    word_type X3 = boost::endian::native_to_big(input[2]);
                    word_type X4 = boost::endian::native_to_big(input[3]);

                    for (size_t j = 0; j != policy_type::rounds; ++j) {
                        X1 = policy_type::mul(X1, key[6 * j + 0]);
                        X2 += key[6 * j + 1];
                        X3 += key[6 * j + 2];
                        X4 = policy_type::mul(X4, key[6 * j + 3]);

                        word_type T0 = X3;
                        X3 = policy_type::mul(X3 ^ X1, key[6 * j + 4]);

                        word_type T1 = X2;
                        X2 = policy_type::mul((X2 ^ X4) + X3, key[6 * j + 5]);
                        X3 += X2;

                        X1 ^= X2;
                        X4 ^= X3;
                        X2 ^= T0;
                        X3 ^= T1;
                    }

                    X1 = policy_type::mul(X1, key[48]);
                    X2 += key[50];
                    X3 += key[49];
                    X4 = policy_type::mul(X4, key[51]);

                    return {boost::endian::big_to_native(X1), boost::endian::big_to_native(X2),
                            boost::endian::big_to_native(X3), boost::endian::big_to_native(X4)};
                }

                inline void schedule_key(const key_type &key) {
                    crypto3::detail::poison(key.data(), 16);
                    crypto3::detail::poison(encryption_key.data(), key_schedule_size);
                    crypto3::detail::poison(decryption_key.data(), key_schedule_size);

                    std::array<uint64_t, 2> K = {0};

                    K[0] = boost::endian::native_to_big(key[0]);
                    K[1] = boost::endian::native_to_big(key[1]);

                    for (size_t off = 0; off != 48; off += 8) {
                        for (size_t i = 0; i != 8; ++i) {
                            encryption_key[off + i] = K[i / 4] >> (48 - 16 * (i % 4));
                        }

                        const uint64_t Kx = (K[0] >> 39);
                        const uint64_t Ky = (K[1] >> 39);

                        K[0] = (K[0] << 25) | Ky;
                        K[1] = (K[1] << 25) | Kx;
                    }

                    for (size_t i = 0; i != 4; ++i) {
                        encryption_key[48 + i] = K[i / 4] >> (48 - 16 * (i % 4));
                    }

                    K.fill(0);

                    decryption_key[0] = policy_type::mul_inv(encryption_key[48]);
                    decryption_key[1] = -encryption_key[49];
                    decryption_key[2] = -encryption_key[50];
                    decryption_key[3] = policy_type::mul_inv(encryption_key[51]);

                    for (size_t i = 0; i != 8 * 6; i += 6) {
                        decryption_key[i + 4] = encryption_key[46 - i];
                        decryption_key[i + 5] = encryption_key[47 - i];
                        decryption_key[i + 6] = policy_type::mul_inv(encryption_key[42 - i]);
                        decryption_key[i + 7] = -encryption_key[44 - i];
                        decryption_key[i + 8] = -encryption_key[43 - i];
                        decryption_key[i + 9] = policy_type::mul_inv(encryption_key[45 - i]);
                    }

                    std::swap(decryption_key[49], decryption_key[50]);

                    crypto3::detail::unpoison(key.data(), 16);
                    crypto3::detail::unpoison(encryption_key.data(), 52);
                    crypto3::detail::unpoison(decryption_key.data(), 52);
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil
#endif
