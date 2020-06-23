//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_SEED_HPP
#define CRYPTO3_BLOCK_SEED_HPP

#include <boost/endian/conversion.hpp>

#include <nil/crypto3/block/detail/seed/seed_policy.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Seed. A older South Korean cipher, widely used in industry
             * there.
             *
             * @ingroup block
             */
            class seed {
            protected:
                typedef detail::seed_policy policy_type;

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
                
                seed(const key_type &key) {
                    schedule_key(key);
                }

                ~seed() {
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
                    word_type B0 = boost::endian::native_to_big(plaintext[0]);
                    word_type B1 = boost::endian::native_to_big(plaintext[1]);
                    word_type B2 = boost::endian::native_to_big(plaintext[2]);
                    word_type B3 = boost::endian::native_to_big(plaintext[3]);

                    for (size_t j = 0; j != policy_type::rounds; j += 2) {
                        word_type T0, T1;

                        T0 = B2 ^ key_schedule[2 * j];
                        T1 = policy_type::g(B2 ^ B3 ^ key_schedule[2 * j + 1], policy_type::s0_constants,
                                            policy_type::s1_constants, policy_type::s2_constants,
                                            policy_type::s3_constants);
                        T0 = policy_type::g(T1 + T0, policy_type::s0_constants, policy_type::s1_constants,
                                            policy_type::s2_constants, policy_type::s3_constants);
                        T1 = policy_type::g(T1 + T0, policy_type::s0_constants, policy_type::s1_constants,
                                            policy_type::s2_constants, policy_type::s3_constants);
                        B1 ^= T1;
                        B0 ^= T0 + T1;

                        T0 = B0 ^ key_schedule[2 * j + 2];
                        T1 = policy_type::g(B0 ^ B1 ^ key_schedule[2 * j + 3], policy_type::s0_constants,
                                            policy_type::s1_constants, policy_type::s2_constants,
                                            policy_type::s3_constants);
                        T0 = policy_type::g(T1 + T0, policy_type::s0_constants, policy_type::s1_constants,
                                            policy_type::s2_constants, policy_type::s3_constants);
                        T1 = policy_type::g(T1 + T0, policy_type::s0_constants, policy_type::s1_constants,
                                            policy_type::s2_constants, policy_type::s3_constants);
                        B3 ^= T1;
                        B2 ^= T0 + T1;
                    }

                    return {boost::endian::big_to_native(B2), boost::endian::big_to_native(B3),
                            boost::endian::big_to_native(B0), boost::endian::big_to_native(B1)};
                }

                inline block_type decrypt_block(const block_type &ciphertext) const {
                    word_type B0 = boost::endian::native_to_big(ciphertext[0]);
                    word_type B1 = boost::endian::native_to_big(ciphertext[1]);
                    word_type B2 = boost::endian::native_to_big(ciphertext[2]);
                    word_type B3 = boost::endian::native_to_big(ciphertext[3]);

                    for (size_t j = 0; j != policy_type::rounds; j += 2) {
                        word_type T0, T1;

                        T0 = B2 ^ key_schedule[30 - 2 * j];
                        T1 = policy_type::g(B2 ^ B3 ^ key_schedule[31 - 2 * j], policy_type::s0_constants,
                                            policy_type::s1_constants, policy_type::s2_constants,
                                            policy_type::s3_constants);
                        T0 = policy_type::g(T1 + T0, policy_type::s0_constants, policy_type::s1_constants,
                                            policy_type::s2_constants, policy_type::s3_constants);
                        T1 = policy_type::g(T1 + T0, policy_type::s0_constants, policy_type::s1_constants,
                                            policy_type::s2_constants, policy_type::s3_constants);
                        B1 ^= T1;
                        B0 ^= T0 + T1;

                        T0 = B0 ^ key_schedule[28 - 2 * j];
                        T1 = policy_type::g(B0 ^ B1 ^ key_schedule[29 - 2 * j], policy_type::s0_constants,
                                            policy_type::s1_constants, policy_type::s2_constants,
                                            policy_type::s3_constants);
                        T0 = policy_type::g(T1 + T0, policy_type::s0_constants, policy_type::s1_constants,
                                            policy_type::s2_constants, policy_type::s3_constants);
                        T1 = policy_type::g(T1 + T0, policy_type::s0_constants, policy_type::s1_constants,
                                            policy_type::s2_constants, policy_type::s3_constants);
                        B3 ^= T1;
                        B2 ^= T0 + T1;
                    }

                    return {boost::endian::big_to_native(B2), boost::endian::big_to_native(B3),
                            boost::endian::big_to_native(B0), boost::endian::big_to_native(B1)};
                }

                inline void schedule_key(const key_type &key) {
                    std::array<word_type, 4> WK = {0};

                    for (size_t i = 0; i != 4; ++i) {
                        WK[i] = boost::endian::native_to_big(key[i]);
                    }

                    for (size_t i = 0; i != 16; i += 2) {
                        key_schedule[2 * i] = policy_type::g(WK[0] + WK[2] - policy_type::round_constants[i],
                                                             policy_type::s0_constants, policy_type::s1_constants,
                                                             policy_type::s2_constants, policy_type::s3_constants);
                        key_schedule[2 * i + 1] = policy_type::g(WK[1] - WK[3] + policy_type::round_constants[i],
                                                                 policy_type::s0_constants, policy_type::s1_constants,
                                                                 policy_type::s2_constants, policy_type::s3_constants) ^
                                                  key_schedule[2 * i];

                        uint32_t T = (WK[0] & 0xFF) << 24;
                        WK[0] = (WK[0] >> 8) | (::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(WK[1], 3) << 24);
                        WK[1] = (WK[1] >> 8) | T;

                        key_schedule[2 * i + 2] = policy_type::g(WK[0] + WK[2] - policy_type::round_constants[i + 1],
                                                                 policy_type::s0_constants, policy_type::s1_constants,
                                                                 policy_type::s2_constants, policy_type::s3_constants);
                        key_schedule[2 * i + 3] = policy_type::g(WK[1] - WK[3] + policy_type::round_constants[i + 1],
                                                                 policy_type::s0_constants, policy_type::s1_constants,
                                                                 policy_type::s2_constants, policy_type::s3_constants) ^
                                                  key_schedule[2 * i + 2];

                        T = ::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(WK[3], 0);
                        WK[3] = (WK[3] << 8) | ::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(WK[2], 0);
                        WK[2] = (WK[2] << 8) | T;
                    }
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif
