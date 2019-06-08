//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ARIA_H_
#define CRYPTO3_ARIA_H_

#include <nil/crypto3/block/detail/aria/aria_policy.hpp>

#include <nil/crypto3/block/detail/block_state_preprocessor.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

#include <nil/crypto3/block/detail/utilities/cpuid/cpuid.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Aria. South Korean cipher used in industry there. No reason
             * to use it otherwise.
             * @ingroup block
             *
             * @tparam Size
             *
             * This ARIA implementation is based on the 32-bit implementation by Aaram Yun from the
             * National Security Research Institute, KOREA. Aaram Yun's implementation is based on
             * the 8-bit implementation by Jin Hong. The source files are available in ARIA.zip from
             * the Korea Internet & Security Agency website.
             * [RFC 5794, A Description of the ARIA Encryption Algorithm](https://tools.ietf.org/html/rfc5794),
             * [Korea Internet & Security Agency homepage](http://seed.kisa.or.kr/iwt/ko/bbs/EgovReferenceList.do?bbsId=BBSMSTR_000000000002)
             */
            template<std::size_t Size>
            class aria {
            protected:
                constexpr static const std::size_t version = Size;
                typedef detail::aria_policy<Size> policy_type;

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
                typedef typename policy_type::round_constants_type round_constants_type;

                template<template<typename, typename> class Mode,
                                                      typename StateAccumulator, std::size_t ValueBits,
                                                      typename Padding>
                struct stream_cipher {
                    typedef block_state_preprocessor<Mode<aria<Size>, Padding>, StateAccumulator,
                                                     stream_endian::little_octet_big_bit, ValueBits,
                                                     policy_type::word_bits * 2> type;
                };

            public:

                aria(const key_type &key) {
                    schedule_key(key);
                }

                virtual ~aria() {
                    encryption_round_key.fill(0);
                    decryption_round_key.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &ciphertext) {
                    return decrypt_block(ciphertext);
                }

            protected:
                key_schedule_type encryption_round_key, decryption_round_key;

                inline block_type encrypt_block(const block_type &plaintext) {
                    return transform(plaintext, encryption_round_key);
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    return transform(ciphertext, decryption_round_key);
                }

                void schedule_key(const key_type &key) {
                    const size_t CK0 = (policy_type::key_bits / 64) - 2;
                    const size_t CK1 = (CK0 + 1) % 3;
                    const size_t CK2 = (CK1 + 1) % 3;

                    word_type w0[4];
                    word_type w1[4];
                    word_type w2[4];
                    word_type w3[4];

                    w0[0] = load_be<uint32_t>(key, 0);
                    w0[1] = load_be<uint32_t>(key, 1);
                    w0[2] = load_be<uint32_t>(key, 2);
                    w0[3] = load_be<uint32_t>(key, 3);

                    w1[0] = w0[0] ^ policy_type::round_constants[CK0][0];
                    w1[1] = w0[1] ^ policy_type::round_constants[CK0][1];
                    w1[2] = w0[2] ^ policy_type::round_constants[CK0][2];
                    w1[3] = w0[3] ^ policy_type::round_constants[CK0][3];

                    policy_type::fo(w1[0], w1[1], w1[2], w1[3]);

                    if (policy_type::key_bits / 8 == 24 || policy_type::key_bits / 8 == 32) {
                        w1[0] ^= load_be<uint32_t>(key, 4);
                        w1[1] ^= load_be<uint32_t>(key, 5);
                    }
                    if (policy_type::key_bits / 8 == 32) {
                        w1[2] ^= load_be<uint32_t>(key, 6);
                        w1[3] ^= load_be<uint32_t>(key, 7);
                    }

                    w2[0] = w1[0] ^ policy_type::round_constants[CK1][0];
                    w2[1] = w1[1] ^ policy_type::round_constants[CK1][1];
                    w2[2] = w1[2] ^ policy_type::round_constants[CK1][2];
                    w2[3] = w1[3] ^ policy_type::round_constants[CK1][3];

                    policy_type::fe(w2[0], w2[1], w2[2], w2[3]);

                    w2[0] ^= w0[0];
                    w2[1] ^= w0[1];
                    w2[2] ^= w0[2];
                    w2[3] ^= w0[3];

                    w3[0] = w2[0] ^ policy_type::round_constants[CK2][0];
                    w3[1] = w2[1] ^ policy_type::round_constants[CK2][1];
                    w3[2] = w2[2] ^ policy_type::round_constants[CK2][2];
                    w3[3] = w2[3] ^ policy_type::round_constants[CK2][3];

                    policy_type::fo(w3[0], w3[1], w3[2], w3[3]);

                    w3[0] ^= w1[0];
                    w3[1] ^= w1[1];
                    w3[2] ^= w1[2];
                    w3[3] ^= w1[3];

                    if (policy_type::key_bits / 8 == 16) {
                        encryption_round_key.resize(4 * 13);
                    } else if (policy_type::key_bits / 8 == 24) {
                        encryption_round_key.resize(4 * 15);
                    } else if (policy_type::key_bits / 8 == 32) {
                        encryption_round_key.resize(4 * 17);
                    }

                    policy_type::rol128<19>(w0, w1, &encryption_round_key[0]);
                    policy_type::rol128<19>(w1, w2, &encryption_round_key[4]);
                    policy_type::rol128<19>(w2, w3, &encryption_round_key[8]);
                    policy_type::rol128<19>(w3, w0, &encryption_round_key[12]);
                    policy_type::rol128<31>(w0, w1, &encryption_round_key[16]);
                    policy_type::rol128<31>(w1, w2, &encryption_round_key[20]);
                    policy_type::rol128<31>(w2, w3, &encryption_round_key[24]);
                    policy_type::rol128<31>(w3, w0, &encryption_round_key[28]);
                    policy_type::rol128<67>(w0, w1, &encryption_round_key[32]);
                    policy_type::rol128<67>(w1, w2, &encryption_round_key[36]);
                    policy_type::rol128<67>(w2, w3, &encryption_round_key[40]);
                    policy_type::rol128<67>(w3, w0, &encryption_round_key[44]);
                    policy_type::rol128<97>(w0, w1, &encryption_round_key[48]);

                    if (policy_type::key_bits / CHAR_BIT == 24 || policy_type::key_bits / CHAR_BIT == 32) {
                        policy_type::rol128<97>(w1, w2, &encryption_round_key[52]);
                        policy_type::rol128<97>(w2, w3, &encryption_round_key[56]);

                        if (policy_type::key_bits / 8 == 32) {
                            policy_type::rol128<97>(w3, w0, &encryption_round_key[60]);
                            policy_type::rol128<109>(w0, w1, &encryption_round_key[64]);
                        }
                    }

                    // Now the decryption key gets scheduled

                    for (size_t i = 0; i != decryption_round_key.size(); i += 4) {
                        decryption_round_key[i] = encryption_round_key[encryption_round_key.size() - 4 - i];
                        decryption_round_key[i + 1] = encryption_round_key[encryption_round_key.size() - 3 - i];
                        decryption_round_key[i + 2] = encryption_round_key[encryption_round_key.size() - 2 - i];
                        decryption_round_key[i + 3] = encryption_round_key[encryption_round_key.size() - 1 - i];
                    }

                    for (size_t i = 4; i != decryption_round_key.size() - 4; i += 4) {
                        for (size_t j = 0; j != 4; ++j) {
                            decryption_round_key[i + j] = policy_type::rotr<8>(decryption_round_key[i + j]) ^
                                                          policy_type::rotr<16>(decryption_round_key[i + j]) ^
                                                          policy_type::rotr<24>(decryption_round_key[i + j]);
                        }

                        decryption_round_key[i + 1] ^= decryption_round_key[i + 2];
                        decryption_round_key[i + 2] ^= decryption_round_key[i + 3];
                        decryption_round_key[i + 0] ^= decryption_round_key[i + 1];
                        decryption_round_key[i + 3] ^= decryption_round_key[i + 1];
                        decryption_round_key[i + 2] ^= decryption_round_key[i + 0];
                        decryption_round_key[i + 1] ^= decryption_round_key[i + 2];

                        decryption_round_key[i + 1] = ((decryption_round_key[i + 1] << 8) & 0xFF00FF00) |
                                                      ((decryption_round_key[i + 1] >> 8) & 0x00FF00FF);
                        decryption_round_key[i + 2] = policy_type::rotr<16>(decryption_round_key[i + 2]);
                        decryption_round_key[i + 3] = reverse_bytes(decryption_round_key[i + 3]);

                        decryption_round_key[i + 1] ^= decryption_round_key[i + 2];
                        decryption_round_key[i + 2] ^= decryption_round_key[i + 3];
                        decryption_round_key[i + 0] ^= decryption_round_key[i + 1];
                        decryption_round_key[i + 3] ^= decryption_round_key[i + 1];
                        decryption_round_key[i + 2] ^= decryption_round_key[i + 0];
                        decryption_round_key[i + 1] ^= decryption_round_key[i + 2];
                    }
                }

                block_type transform(const block_type &plaintext, const key_schedule_type &schedule) {
                    // Hit every state line of S1 and S2
                    const size_t cache_line_size = cpuid::cache_line_size();

                    /*
                    * This initializer ensures Z == 0xFFFFFFFF for any state line size
                    * in {32,64,128,256,512}
                    */
                    volatile uint32_t Z = 0x11101010;
                    for (size_t i = 0; i < policy_type::constants_size; i += cache_line_size / sizeof(uint32_t)) {
                        Z |= policy_type::s1[i] | policy_type::s2[i];
                    }

                    word_type t0 = plaintext[0], t1 = plaintext[1], t2 = plaintext[2], t3 = plaintext[3];

                    t0 &= Z;

                    for (size_t r = 0; r < rounds; r += 2) {
                        t0 ^= schedule[4 * r];
                        t1 ^= schedule[4 * r + 1];
                        t2 ^= schedule[4 * r + 2];
                        t3 ^= schedule[4 * r + 3];
                        policy_type::fo(t0, t1, t2, t3);

                        t0 ^= schedule[4 * r + 4];
                        t1 ^= schedule[4 * r + 5];
                        t2 ^= schedule[4 * r + 6];
                        t3 ^= schedule[4 * r + 7];

                        if (r != rounds - 2) {
                            policy_type::fe(t0, t1, t2, t3);
                        }
                    }

                    return {
                            policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(t0, 0)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(, schedule[4 * rounds], 0),
                            policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(t0, 1)] >> 8 ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds], 1),
                            policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(t0, 2)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds], 2),
                            policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(t0, 3)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds], 3),
                            policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(t1, 0)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 1], 0),
                            policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(t1, 1)] >> 8 ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 1], 1),
                            policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(t1, 2)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 1], 2),
                            policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(t1, 3)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 1], 3),
                            policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(t2, 0)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 2], 0),
                            policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(t2, 1)] >> 8 ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 2], 1),
                            policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(t2, 2)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 2], 2),
                            policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(t2, 3)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 2], 3),
                            policy_type::x1[policy_type::extract_uint_t<CHAR_BIT>(t3, 0)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 3], 0),
                            policy_type::x2[policy_type::extract_uint_t<CHAR_BIT>(t3, 1)] >> 8 ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 3], 1),
                            policy_type::s1[policy_type::extract_uint_t<CHAR_BIT>(t3, 2)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 3], 2),
                            policy_type::s2[policy_type::extract_uint_t<CHAR_BIT>(t3, 3)] ^
                            policy_type::extract_uint_t<CHAR_BIT>(schedule[4 * rounds + 3], 3)
                    };
                }
            };
        }
    }
}
#endif
