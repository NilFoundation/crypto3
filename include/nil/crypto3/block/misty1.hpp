//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_MISTY1_HPP
#define CRYPTO3_BLOCK_MISTY1_HPP

#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>

#include <nil/crypto3/block/detail/misty1/misty1_functions.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Misty1. A 64-bit Japanese cipher standardized by NESSIE
             * and ISO. Seemingly secure, but quite slow and saw little
             * adoption. No reason to use it in new code.
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

                template<class Mode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode, StateAccumulator, params_type> type;
                };

                typedef typename stream_endian::little_octet_big_bit endian_type;

                misty1(const key_type &key) {
                    schedule_key(key);
                }

                ~misty1() {
                    encryption_key.fill(0);
                    decryption_key.fill(0);
                }

                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return decrypt_block(ciphertext);
                }

            protected:
                key_schedule_type encryption_key, decryption_key;

                inline block_type encrypt_block(const block_type &plaintext) const {
                    uint16_t B0 = boost::endian::native_to_big(plaintext[0]);
                    uint16_t B1 = boost::endian::native_to_big(plaintext[1]);
                    uint16_t B2 = boost::endian::native_to_big(plaintext[2]);
                    uint16_t B3 = boost::endian::native_to_big(plaintext[3]);

                    for (size_t j = 0; j != 12; j += 3) {
                        const uint16_t *RK = &encryption_key[8 * j];

                        B1 ^= B0 & RK[0];
                        B0 ^= B1 | RK[1];
                        B3 ^= B2 & RK[2];
                        B2 ^= B3 | RK[3];

                        uint16_t T0, T1;

                        T0 = policy_type::fi(B0 ^ RK[4], RK[5], RK[6]) ^ B1;
                        T1 = policy_type::fi(B1 ^ RK[7], RK[8], RK[9]) ^ T0;
                        T0 = policy_type::fi(T0 ^ RK[10], RK[11], RK[12]) ^ T1;

                        B2 ^= T1 ^ RK[13];
                        B3 ^= T0;

                        T0 = policy_type::fi(B2 ^ RK[14], RK[15], RK[16]) ^ B3;
                        T1 = policy_type::fi(B3 ^ RK[17], RK[18], RK[19]) ^ T0;
                        T0 = policy_type::fi(T0 ^ RK[20], RK[21], RK[22]) ^ T1;

                        B0 ^= T1 ^ RK[23];
                        B1 ^= T0;
                    }

                    B1 ^= B0 & encryption_key[96];
                    B0 ^= B1 | encryption_key[97];
                    B3 ^= B2 & encryption_key[98];
                    B2 ^= B3 | encryption_key[99];

                    return {boost::endian::big_to_native(B2), boost::endian::big_to_native(B3),
                            boost::endian::big_to_native(B0), boost::endian::big_to_native(B1)};
                }

                inline block_type decrypt_block(const block_type &ciphertext) const {
                    uint16_t B0 = boost::endian::native_to_big(ciphertext[2]);
                    uint16_t B1 = boost::endian::native_to_big(ciphertext[3]);
                    uint16_t B2 = boost::endian::native_to_big(ciphertext[0]);
                    uint16_t B3 = boost::endian::native_to_big(ciphertext[1]);

                    for (size_t j = 0; j != 12; j += 3) {
                        const uint16_t *RK = &decryption_key[8 * j];

                        B2 ^= B3 | RK[0];
                        B3 ^= B2 & RK[1];
                        B0 ^= B1 | RK[2];
                        B1 ^= B0 & RK[3];

                        uint16_t T0, T1;

                        T0 = policy_type::fi(B2 ^ RK[4], RK[5], RK[6]) ^ B3;
                        T1 = policy_type::fi(B3 ^ RK[7], RK[8], RK[9]) ^ T0;
                        T0 = policy_type::fi(T0 ^ RK[10], RK[11], RK[12]) ^ T1;

                        B0 ^= T1 ^ RK[13];
                        B1 ^= T0;

                        T0 = policy_type::fi(B0 ^ RK[14], RK[15], RK[16]) ^ B1;
                        T1 = policy_type::fi(B1 ^ RK[17], RK[18], RK[19]) ^ T0;
                        T0 = policy_type::fi(T0 ^ RK[20], RK[21], RK[22]) ^ T1;

                        B2 ^= T1 ^ RK[23];
                        B3 ^= T0;
                    }

                    B2 ^= B3 | decryption_key[96];
                    B3 ^= B2 & decryption_key[97];
                    B0 ^= B1 | decryption_key[98];
                    B1 ^= B0 & decryption_key[99];

                    return {boost::endian::big_to_native(B0), boost::endian::big_to_native(B1),
                            boost::endian::big_to_native(B2), boost::endian::big_to_native(B3)};
                }

                inline void schedule_key(const key_type &key) {
                    std::array<word_type, 32> schedule = {0};
                    for (size_t i = 0; i != key.size() / 2; ++i) {
                        schedule[i] = boost::endian::native_to_big(key[i]);
                    }

                    for (size_t i = 0; i != rounds; ++i) {
                        schedule[i + 8] =
                            policy_type::fi(schedule[i], schedule[(i + 1) % 8] >> 9, schedule[(i + 1) % 8] & 0x1FF);
                        schedule[i + 16] = schedule[i + 8] >> 9;
                        schedule[i + 24] = schedule[i + 8] & 0x1FF;
                    }

                    for (size_t i = 0; i != key_schedule_size; ++i) {
                        encryption_key[i] = schedule[policy_type::encryption_key_order[i]];
                        decryption_key[i] = schedule[policy_type::decryption_key_order[i]];
                    }

                    schedule.fill(0);
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil
#endif
