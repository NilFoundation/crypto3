//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_THREEFISH_HPP
#define CRYPTO3_THREEFISH_HPP

#include <nil/crypto3/block/detail/threefish/threefish_policy.hpp>

#include <nil/crypto3/block/detail/block_state_preprocessor.hpp>
#include <nil/crypto3/block/detail/stream_endian.hpp>

#include <boost/cstdint.hpp>

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
#include <cstdio>
#endif

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Threefish. A variable-key length (512-bit is recommended)
             * tweakable block cipher used in the Skein hash function via
             * Merkle-Damgård construction. Very fast on 64-bit processors.
             *
             * @ingroup block
             *
             * Encrypt implemented directly from the Skein standard as found at
             * http://www.skein-hash.info/sites/default/files/skein1.2.pdf
             *
             * @tparam KeyBits
             */
            template<std::size_t KeyBits>
            class threefish {

                typedef detail::threefish_policy<KeyBits> policy_type;

            public:
                constexpr static const std::size_t version = KeyBits;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t tweak_bits = policy_type::tweak_bits;
                constexpr static const std::size_t tweak_words = policy_type::tweak_words;
                typedef typename policy_type::tweak_type tweak_type;

                static const std::size_t rounds = policy_type::rounds;
                typedef typename policy_type::key_schedule_type key_schedule_type;
                typedef typename policy_type::tweak_schedule_type tweak_schedule_type;

                template<template<typename, typename> class Mode, std::size_t ValueBits, typename Padding>
                struct stream_cipher {
                    typedef block_state_preprocessor<Mode<threefish<KeyBits>, Padding>,
                                                     stream_endian::little_octet_big_bit, ValueBits,
                                                     policy_type::word_bits * 2> type;
                };

                threefish(const key_type &key = key_type(), const tweak_type &tweak = tweak_type()) {
                    schedule_key(key);
                    schedule_tweak(tweak);
                }

                virtual ~threefish() {
                    tweak_schedule.fill(0);
                    key_schedule.fill(0);
                }

                block_type encrypt(const block_type &plaintext) {
                    return encrypt_block(plaintext);
                }

                block_type decrypt(const block_type &plaintext) {
                    return decrypt_block(plaintext);
                }

            protected:
                void schedule_tweak(const tweak_type &t) {
                    tweak_schedule[0] = t[0];
                    tweak_schedule[1] = t[1];
                    tweak_schedule[2] = t[0] ^ t[1];
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    for (unsigned t = 0; t <= tweak_words; ++t) {
                        std::printf("t_%d = %.16lx\n",
                                    t, tweak_schedule[t]);
                    }
#endif
                }

                void schedule_key(const key_type &key) {
                    word_type k_N_w = UINT64_C(0x5555555555555555);
                    for (unsigned t = 0; t < key_words; ++t) {
                        key_schedule[t] = key[t];
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        std::printf("k_%-2d = %.16lx\n",
                                    t, encryption_key[t]);
#endif
                        k_N_w ^= key[t];
                    }
                    key_schedule[key_words] = k_N_w;
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    std::printf("k_%-2d = %.16lx\n",
                                key_words, encryption_key[key_words]);
#endif
                }

                key_schedule_type key_schedule;
                tweak_schedule_type tweak_schedule;

                inline word_type k(unsigned s, unsigned i) {
                    word_type x = key_schedule[(s + i) % (key_words + 1)];
                    switch (i) {
                        default:
                            return x;
                        case block_words - 3:
                            return x + tweak_schedule[s % 3];
                        case block_words - 2:
                            return x + tweak_schedule[(s + 1) % 3];
                        case block_words - 1:
                            return x + s;
                    }
                }

                inline block_type encrypt_block(const block_type &plaintext) {

                    // Initialize working variables with block
                    block_type v = plaintext;

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    for (unsigned t = 0; t < block_words; ++t) {
                        std::printf("v_0,%-2d = %.16lx\n",
                                    t, v[t]);
                    }
#endif

                    // Encipher block
                    for (unsigned d = 0; d < rounds;) {
                        // Add a subkey (when d%4 == 0)
                        for (unsigned i = 0; i < block_words; ++i) {
                            v[i] += k(d / 4, i);
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                            std::printf("e_%d,%-2d = %.16lx\n",
                                        d, i, v[i]);
#endif
                        }

                        // Unrolling by 4 is also useful as the permutations
                        // have a cycle of 2 or 4 (see 8.3)
                        for (unsigned q = 0; q < 4; ++q, ++d) {
                            block_type f = block_type();
                            // MIX into f
                            for (unsigned j = 0; j < block_words / 2; ++j) {
                                word_type x0 = v[2 * j + 0];
                                word_type x1 = v[2 * j + 1];
                                word_type y0 = x0 + x1;
                                std::size_t r = policy_type::rotations[d % 8][j];
                                word_type y1 = policy_type::rotl(x1, r) ^y0;
                                f[2 * j + 0] = y0;
                                f[2 * j + 1] = y1;
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                                std::printf("f_%d,%-2d = %.16lx\n",
                                            d, 2*j+0, f[2*j+0]);
                                std::printf("f_%d,%-2d = %.16lx\n",
                                            d, 2*j+1, f[2*j+1]);
#endif
                            }
                            // PERMUTE back into v
                            for (unsigned i = 0; i < block_words; ++i) {
                                unsigned pi = policy_type::permutation[i];
                                v[i] = f[pi];
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                                std::printf("v_%d,%-2d = %.16lx\n",
                                            d+1, i, v[i]);
#endif
                            }
                        }
                    }

                    block_type ciphertext = block_type();
                    // Add final subkey
                    for (unsigned i = 0; i < block_words; ++i) {
                        ciphertext[i] = v[i] + k(rounds / 4, i);
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        std::printf("c_%-2d = %.16lx\n",
                                    i, ciphertext[i]);
#endif
                    }
                    return ciphertext;
                }

                inline block_type decrypt_block(const block_type &ciphertext) {
                    for (unsigned i = 0; i < block_words; ++i) {
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        std::printf("c_%-2d = %.16lx\n",
                                    i, ciphertext[i]);
#endif
                    }

                    block_type v = block_type();

                    // Remove final subkey
                    for (unsigned i = 0; i < block_words; ++i) {
                        v[i] = ciphertext[i] - k(rounds / 4, i);
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        std::printf("v_%d,%-2d = %.16lx\n",
                                    rounds, i, v[i]);
#endif
                    }

                    // Decipher block
                    for (unsigned d = rounds; d;) {
                        // Unrolling by 4 is also useful as the permutations
                        // have a cycle of 2 or 4 (see 8.3)
                        for (unsigned q = 4; q--;) {
                            --d;

                            block_type f = block_type();
                            // PERMUTE back into f
                            for (unsigned i = 0; i < block_words; ++i) {
                                unsigned pi = policy_type::permutation[i];
                                f[pi] = v[i];
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                                std::printf("f_%d,%-2d = %.16lx\n",
                                            d, pi, f[pi]);
#endif
                            }

                            // UNMIX into v
                            for (unsigned j = 0; j < block_words / 2; ++j) {
                                word_type y0 = f[2 * j + 0];
                                word_type y1 = f[2 * j + 1];

                                std::size_t r = policy_type::rotations[d % 8][j];
                                word_type x1 = policy_type::rotr(y0 ^ y1, r);
                                word_type x0 = y0 - x1;

                                v[2 * j + 0] = x0;
                                v[2 * j + 1] = x1;

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                                std::printf("e_%d,%-2d = %.16lx\n",
                                            d, 2*j+0, v[2*j+0]);
                                std::printf("e_%d,%-2d = %.16lx\n",
                                            d, 2*j+1, v[2*j+1]);
#endif
                            }
                        }

                        // Remove a subkey (when d%4 == 0)
                        for (unsigned i = 0; i < block_words; ++i) {
                            v[i] -= k(d / 4, i);
#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                            std::printf("d_%d,%-2d = %.16lx\n",
                                        d, i, v[i]);
#endif
                        }
                    }

                    return v;
                }
            };
        }
    }
} // namespace nil

#endif // CRYPTO3_THREEFISH_HPP
