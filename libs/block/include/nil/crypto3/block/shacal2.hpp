//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_SHACAL2_HPP
#define CRYPTO3_BLOCK_SHACAL2_HPP

#include <nil/crypto3/block/detail/shacal/shacal2_policy.hpp>

#include <nil/crypto3/block/detail/block_stream_processor.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

#include <boost/static_assert.hpp>

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
#include <cstdio>
#endif

namespace nil {
    namespace crypto3 {
        namespace block {

            /*!
             * @brief Shacal2. Merkle-Damgård construction foundation for
             * @ref nil::crypto3::hashes::sha2 "SHA2" hashes. Accepts
             * up to a 512-bit key. Fast and seemingly very secure, but obscure.
             * Standardized by NESSIE.
             *
             * @ingroup block
             *
             * Encrypt implemented directly from the SHA standard as found at
             * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
             *
             * Decrypt is a straight-forward inverse
             *
             * In SHA terminology:
             * - plaintext = H^(i-1)
             * - ciphertext = H^(i)
             * - key = M^(i)
             * - schedule = W
             *
             * @tparam BlockBits Block cipher block bits. Available values are: 256, 512
             */
            template<std::size_t BlockBits>
            class shacal2 {

                typedef detail::shacal2_policy<BlockBits> policy_type;

            public:
                constexpr static const std::size_t version = BlockBits;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                static const std::size_t rounds = policy_type::rounds;
                typedef typename policy_type::key_schedule_type key_schedule_type;

                template<class Mode, typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = policy_type::word_bits * 2;
                    };

                    typedef block_stream_processor<Mode, StateAccumulator, params_type> type;
                };

                typedef typename stream_endian::little_octet_big_bit endian_type;

                shacal2(const key_type &key) : schedule(build_schedule(key)) {
                }

                shacal2(key_schedule_type s) : schedule((prepare_schedule(s), s)) {
                }

                block_type encrypt(block_type const &plaintext) const {
                    return encrypt_block(plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return decrypt_block(ciphertext);
                }

            protected:
                const key_schedule_type schedule;

                static key_schedule_type build_schedule(const key_type &key) {
                    // Copy key into beginning of round_constants_words
                    key_schedule_type schedule;
                    for (unsigned t = 0; t < key_words; ++t) {
                        schedule[t] = key[t];
                    }
                    prepare_schedule(schedule);
                    return schedule;
                }

                static void prepare_schedule(key_schedule_type &schedule) {
                    for (unsigned t = key_words; t < rounds; ++t) {
                        schedule[t] = policy_type::sigma_1(schedule[t - 2]) + schedule[t - 7] +
                                      policy_type::sigma_0(schedule[t - 15]) + schedule[t - 16];
                    }
                }

                block_type encrypt_block(const block_type &plaintext) const {
                    return encrypt_block(schedule, plaintext);
                }

                inline static block_type encrypt_block(const key_schedule_type &schedule, block_type const &plaintext) {

                    // Initialize working variables with block
                    word_type a = plaintext[0], b = plaintext[1], c = plaintext[2], d = plaintext[3], e = plaintext[4],
                              f = plaintext[5], g = plaintext[6], h = plaintext[7];

                    // Encipher block
#ifdef CRYPTO3_BLOCK_NO_OPTIMIZATION

                    for (unsigned t = 0; t < rounds; ++t) {
                        word_type T1 = h + policy_type::Sigma_1(e) + policy_type::Ch(e, f, g) +
                                       policy_type::constants[t] + round_constants_words[t];
                        word_type T2 = policy_type::Sigma_0(a) + policy_type::Maj(a, b, c);

                        h = g;
                        g = f;
                        f = e;
                        e = d + T1;
                        d = c;
                        c = b;
                        b = a;
                        a = T1 + T2;
                    }

#else    // CRYPTO3_BLOCK_NO_OPTIMIZATION

                    BOOST_STATIC_ASSERT(rounds % block_words == 0);
                    for (unsigned t = 0; t < rounds;) {
                        for (int n = block_words; n--; ++t) {
                            word_type T1 = h + policy_type::Sigma_1(e) + policy_type::Ch(e, f, g) +
                                           policy_type::constants[t] + schedule[t];
                            word_type T2 = policy_type::Sigma_0(a) + policy_type::Maj(a, b, c);

                            h = g;
                            g = f;
                            f = e;
                            e = d + T1;
                            d = c;
                            c = b;
                            b = a;
                            a = T1 + T2;
                        }
                    }

#endif

                    return {{a, b, c, d, e, f, g, h}};
                }

                block_type decrypt_block(const block_type &ciphertext) const {
                    return decrypt_block(schedule, ciphertext);
                }

                inline static block_type decrypt_block(const key_schedule_type &schedule,
                                                       const block_type &ciphertext) {
                    // Initialize working variables with block
                    word_type a = ciphertext[0], b = ciphertext[1], c = ciphertext[2], d = ciphertext[3],
                              e = ciphertext[4], f = ciphertext[5], g = ciphertext[6], h = ciphertext[7];

                    // Decipher block
                    for (unsigned t = rounds; t--;) {
                        word_type T2 = policy_type::Sigma_0(b) + policy_type::Maj(b, c, d);
                        word_type T1 = a - T2;

                        a = b;
                        b = c;
                        c = d;
                        d = e - T1;
                        e = f;
                        f = g;
                        g = h;
                        h = T1 - policy_type::Sigma_1(e) - policy_type::Ch(e, f, g) - policy_type::constants[t] -
                            schedule[t];
                    }
                    return {{a, b, c, d, e, f, g, h}};
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHERS_SHACAL2_HPP
