//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_BLOCK_BASIC_SHACAL_HPP
#define CRYPTO3_BLOCK_BASIC_SHACAL_HPP

#include <nil/crypto3/block/detail/shacal/shacal_policy.hpp>
#include <nil/crypto3/block/detail/shacal/shacal1_policy.hpp>

#include <boost/static_assert.hpp>

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
#include <cstdio>
#endif

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
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
             * The algorithms for SHA(-0) and SHA-1 are identical apart from the
             * key scheduling, so encapsulate that as a class that takes an
             * already-prepared schedule.  (Constructor is protected to help keep
             * people from accidentally giving it just a key in a schedule.)
             */
            class basic_shacal {
            protected:
                typedef detail::shacal_policy policy_type;

            public:
                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef policy_type::word_type word_type;

                constexpr static const std::size_t key_bits = policy_type::key_bits;
                constexpr static const std::size_t key_words = policy_type::key_words;
                typedef policy_type::key_type key_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef policy_type::block_type block_type;

                constexpr static const std::size_t rounds = policy_type::rounds;
                typedef policy_type::schedule_type schedule_type;

            protected:
                basic_shacal(const schedule_type &s) : schedule(s) {
                }

                virtual ~basic_shacal() {
                    schedule.fill(0);
                }

            public:
                inline block_type encrypt(const block_type &plaintext) const {
                    return encrypt_block(schedule, plaintext);
                }

                inline block_type decrypt(const block_type &ciphertext) const {
                    return decrypt_block(schedule, ciphertext);
                }

            private:
                schedule_type schedule;

                inline static block_type encrypt_block(const schedule_type &schedule, const block_type &plaintext) {

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    for (unsigned t = 0; t < block_words; ++t) {
                        std::printf(word_bits == 32 ? "H[%d] = %.8x\n" : "H[%d] = %.16lx\n", t, plaintext[t]);
                    }
#endif

                    // Initialize working variables with block
                    word_type a = plaintext[0], b = plaintext[1], c = plaintext[2], d = plaintext[3], e = plaintext[4];

                    // Encipher block
#ifdef CRYPTO3_BLOCK_NO_OPTIMIZATION

                    for (unsigned t = 0; t < rounds; ++t) {
                        word_type T = policy_type::rotl<5>(a) + policy_type::f(t, b, c, d) + e +
                                      policy_type::constants[t] + round_constants_words[t];

                        e = d;
                        d = c;
                        c = policy_type::rotl<30>(b);
                        b = a;
                        a = T;

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        printf(word_bits == 32 ? "t = %2d: %.8x %.8x %.8x %.8x %.8x\n" :
                                                 "t = %2d: %.16lx %.16lx %.16lx %.16lx %.16lx\n",
                               t, a, b, c, d, e);
#endif
                    }

#else    // CRYPTO3_BLOCK_NO_OPTIMIZATION

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
#define CRYPTO3_BLOCK_SHACAL1_TRANSFORM_PROGRESS                                                                      \
    printf(word_bits == 32 ? "t = %2d: %.8x %.8x %.8x %.8x %.8x\n" : "t = %2d: %.16lx %.16lx %.16lx %.16lx %.16lx\n", \
           t, a, b, c, d, e);
#else
#define CRYPTO3_BLOCK_SHACAL1_TRANSFORM_PROGRESS
#endif

#define CRYPTO3_BLOCK_SHACAL1_TRANSFORM                                                                               \
    word_type T = policy_type::rotl<5>(a) + policy_type::f(t, b, c, d) + e + policy_type::constants[t] + schedule[t]; \
    e = d;                                                                                                            \
    d = c;                                                                                                            \
    c = policy_type::rotl<30>(b);                                                                                     \
    b = a;                                                                                                            \
    a = T;                                                                                                            \
    CRYPTO3_BLOCK_SHACAL1_TRANSFORM_PROGRESS

                    BOOST_STATIC_ASSERT(rounds == 80);
                    BOOST_STATIC_ASSERT(rounds % block_words == 0);
                    for (unsigned t = 0; t < 20;) {
                        for (int n = block_words; n--; ++t) {
                            CRYPTO3_BLOCK_SHACAL1_TRANSFORM
                        }
                    }
                    for (unsigned t = 20; t < 40;) {
                        for (int n = block_words; n--; ++t) {
                            CRYPTO3_BLOCK_SHACAL1_TRANSFORM
                        }
                    }
                    for (unsigned t = 40; t < 60;) {
                        for (int n = block_words; n--; ++t) {
                            CRYPTO3_BLOCK_SHACAL1_TRANSFORM
                        }
                    }
                    for (unsigned t = 60; t < 80;) {
                        for (int n = block_words; n--; ++t) {
                            CRYPTO3_BLOCK_SHACAL1_TRANSFORM
                        }
                    }

#endif

                    return {{a, b, c, d, e}};
                }

                inline static block_type decrypt_block(const schedule_type &schedule, const block_type &ciphertext) {

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                    for (unsigned t = 0; t < block_words; ++t) {
                        std::printf(word_bits == 32 ? "H[%d] = %.8x\n" : "H[%d] = %.16lx\n", t, ciphertext[t]);
                    }
#endif

                    // Initialize working variables with block
                    word_type a = ciphertext[0], b = ciphertext[1], c = ciphertext[2], d = ciphertext[3],
                              e = ciphertext[4];

                    // Decipher block
                    for (unsigned t = rounds; t--;) {
                        word_type T = a;

                        a = b;
                        b = policy_type::rotr<30>(c);
                        c = d;
                        d = e;
                        e = T - policy_type::rotl<5>(a) - policy_type::f(t, b, c, d) - policy_type::constants[t] -
                            schedule[t];

#ifdef CRYPTO3_BLOCK_SHOW_PROGRESS
                        std::printf(word_bits == 32 ? "t = %2d: %.8x %.8x %.8x %.8x %.8x\n" :
                                                      "t = %2d: %.16lx %.16lx %.16lx %.16lx %.16lx\n",
                                    t, a, b, c, d, e);
#endif
                    }

                    return {{a, b, c, d, e}};
                }
            };
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHERS_BASIC_SHACAL_HPP
