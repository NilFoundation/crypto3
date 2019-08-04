//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_DETAIL_CUBEHASH_POLICY_HPP
#define CRYPTO3_HASH_DETAIL_CUBEHASH_POLICY_HPP

#include <array>

#include <nil/crypto3/hash/detail/basic_functions.hpp>
#include <nil/crypto3/hash/detail/static_digest.hpp>

#include <boost/static_assert.hpp>

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
#include <cstdio>
#endif

#ifndef CRYPTO3_HASH_NO_OPTIMIZATION
#ifdef __SSE2__
#define CRYPTO3_HASH_CUBEHASH_USE_INTRINSICS
#endif
#endif

#ifdef CRYPTO3_HASH_CUBEHASH_USE_INTRINSICS

#include <emmintrin.h>

#endif

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {

                //
                // For details, see http://cubehash.cr.yp.to/
                //

                struct basic_cubehash_policy : public basic_functions<32> {

                    // Note that this is a policy for a compressor,
                    // so it used different terminology from the c policies

                    // CubeHash always uses a 1024-bit internal state
                    constexpr static const std::size_t state_words = 32;
                    constexpr static const std::size_t state_bits = state_words * word_bits;
                    typedef std::array<word_type, state_words> state_type;

                    static inline void word_swap(word_type &a, word_type &b) {
                        word_type t = a;
                        a = b;
                        b = t;
                    }

#ifdef CRYPTO3_HASH_CUBEHASH_USE_INTRINSICS

                    static inline void multiword_swap(__m128i &a, __m128i &b) {
                        __m128i t = a;
                        a = b;
                        b = t;
                    }

#endif

                    static void transform(state_type &state, unsigned n) {
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
                        printf("About to run %d CubeHash transform(s) on the following:\n", n);
                        for (unsigned i = 0; i < state.size(); ++i) {
                            printf("%.8x%c", state[i], (i + 1) % 8 ? ' ' : '\n');
                        }
#endif

#ifdef CRYPTO3_HASH_NO_OPTIMIZATION
                        // From simple.c in the submission packet,
                        // the "reference" implementation
                        state_type &x = state;
                        state_type y;
                        while (n--) {
                            unsigned i;
                            for (i = 0; i < 16; ++i)
                                x[i + 16] += x[i];
                            for (i = 0; i < 16; ++i)
                                y[i ^ 8] = x[i];
                            for (i = 0; i < 16; ++i)
                                x[i] = rotl<7>(y[i]);
                            for (i = 0; i < 16; ++i)
                                x[i] ^= x[i + 16];
                            for (i = 0; i < 16; ++i)
                                y[i ^ 2] = x[i + 16];
                            for (i = 0; i < 16; ++i)
                                x[i + 16] = y[i];
                            for (i = 0; i < 16; ++i)
                                x[i + 16] += x[i];
                            for (i = 0; i < 16; ++i)
                                y[i ^ 4] = x[i];
                            for (i = 0; i < 16; ++i)
                                x[i] = rotl<11>(y[i]);
                            for (i = 0; i < 16; ++i)
                                x[i] ^= x[i + 16];
                            for (i = 0; i < 16; ++i)
                                y[i ^ 1] = x[i + 16];
                            for (i = 0; i < 16; ++i)
                                x[i + 16] = y[i];
                        }
#else

#ifdef CRYPTO3_HASH_CUBEHASH_USE_INTRINSICS

                        __m128i x0 = _mm_loadu_si128((__m128i *)&state[0]);
                        __m128i x1 = _mm_loadu_si128((__m128i *)&state[4]);
                        __m128i x2 = _mm_loadu_si128((__m128i *)&state[8]);
                        __m128i x3 = _mm_loadu_si128((__m128i *)&state[12]);
                        __m128i x4 = _mm_loadu_si128((__m128i *)&state[16]);
                        __m128i x5 = _mm_loadu_si128((__m128i *)&state[20]);
                        __m128i x6 = _mm_loadu_si128((__m128i *)&state[24]);
                        __m128i x7 = _mm_loadu_si128((__m128i *)&state[28]);

                        while (n--) {

                            x4 = _mm_add_epi32(x0, x4);
                            x5 = _mm_add_epi32(x1, x5);
                            x6 = _mm_add_epi32(x2, x6);
                            x7 = _mm_add_epi32(x3, x7);

                            multiword_swap(x0, x2);
                            multiword_swap(x1, x3);

                            x0 = _mm_xor_si128(_mm_slli_epi32(x0, 7), _mm_srli_epi32(x0, 25));
                            x1 = _mm_xor_si128(_mm_slli_epi32(x1, 7), _mm_srli_epi32(x1, 25));
                            x2 = _mm_xor_si128(_mm_slli_epi32(x2, 7), _mm_srli_epi32(x2, 25));
                            x3 = _mm_xor_si128(_mm_slli_epi32(x3, 7), _mm_srli_epi32(x3, 25));

                            x0 = _mm_xor_si128(x0, x4);
                            x1 = _mm_xor_si128(x1, x5);
                            x2 = _mm_xor_si128(x2, x6);
                            x3 = _mm_xor_si128(x3, x7);

                            x4 = _mm_shuffle_epi32(x4, 0x4e);
                            x5 = _mm_shuffle_epi32(x5, 0x4e);
                            x6 = _mm_shuffle_epi32(x6, 0x4e);
                            x7 = _mm_shuffle_epi32(x7, 0x4e);

                            x4 = _mm_add_epi32(x0, x4);
                            x5 = _mm_add_epi32(x1, x5);
                            x6 = _mm_add_epi32(x2, x6);
                            x7 = _mm_add_epi32(x3, x7);

                            multiword_swap(x0, x1);
                            multiword_swap(x2, x3);

                            x0 = _mm_xor_si128(_mm_slli_epi32(x0, 11), _mm_srli_epi32(x0, 21));
                            x1 = _mm_xor_si128(_mm_slli_epi32(x1, 11), _mm_srli_epi32(x1, 21));
                            x2 = _mm_xor_si128(_mm_slli_epi32(x2, 11), _mm_srli_epi32(x2, 21));
                            x3 = _mm_xor_si128(_mm_slli_epi32(x3, 11), _mm_srli_epi32(x3, 21));

                            x0 = _mm_xor_si128(x0, x4);
                            x1 = _mm_xor_si128(x1, x5);
                            x2 = _mm_xor_si128(x2, x6);
                            x3 = _mm_xor_si128(x3, x7);

                            x4 = _mm_shuffle_epi32(x4, 0xb1);
                            x5 = _mm_shuffle_epi32(x5, 0xb1);
                            x6 = _mm_shuffle_epi32(x6, 0xb1);
                            x7 = _mm_shuffle_epi32(x7, 0xb1);
                        }

                        _mm_storeu_si128((__m128i *)&state[0], x0);
                        _mm_storeu_si128((__m128i *)&state[4], x1);
                        _mm_storeu_si128((__m128i *)&state[8], x2);
                        _mm_storeu_si128((__m128i *)&state[12], x3);
                        _mm_storeu_si128((__m128i *)&state[16], x4);
                        _mm_storeu_si128((__m128i *)&state[20], x5);
                        _mm_storeu_si128((__m128i *)&state[24], x6);
                        _mm_storeu_si128((__m128i *)&state[28], x7);

#else

                        //
                        // The fully-unrolled version is about 2.5x slower than the SSE2
                        // version on amd64, but that's still about 50 times faster than
                        // the unoptimized reference version, at negligible size cost.
                        //

                        //         ijklm
                        word_type x00000 = state[0];
                        word_type x00001 = state[1];
                        word_type x00010 = state[2];
                        word_type x00011 = state[3];
                        word_type x00100 = state[4];
                        word_type x00101 = state[5];
                        word_type x00110 = state[6];
                        word_type x00111 = state[7];
                        word_type x01000 = state[8];
                        word_type x01001 = state[9];
                        word_type x01010 = state[10];
                        word_type x01011 = state[11];
                        word_type x01100 = state[12];
                        word_type x01101 = state[13];
                        word_type x01110 = state[14];
                        word_type x01111 = state[15];
                        word_type x10000 = state[16];
                        word_type x10001 = state[17];
                        word_type x10010 = state[18];
                        word_type x10011 = state[19];
                        word_type x10100 = state[20];
                        word_type x10101 = state[21];
                        word_type x10110 = state[22];
                        word_type x10111 = state[23];
                        word_type x11000 = state[24];
                        word_type x11001 = state[25];
                        word_type x11010 = state[26];
                        word_type x11011 = state[27];
                        word_type x11100 = state[28];
                        word_type x11101 = state[29];
                        word_type x11110 = state[30];
                        word_type x11111 = state[31];

                        while (n--) {
                            // Add x0jklm into x1jklm modulo 2**32
                            x10000 += x00000;
                            x10001 += x00001;
                            x10010 += x00010;
                            x10011 += x00011;
                            x10100 += x00100;
                            x10101 += x00101;
                            x10110 += x00110;
                            x10111 += x00111;
                            x11000 += x01000;
                            x11001 += x01001;
                            x11010 += x01010;
                            x11011 += x01011;
                            x11100 += x01100;
                            x11101 += x01101;
                            x11110 += x01110;
                            x11111 += x01111;

                            // Rotate x0jkml upward by 7 bits
                            x00000 = rotl<7>(x00000);
                            x00001 = rotl<7>(x00001);
                            x00010 = rotl<7>(x00010);
                            x00011 = rotl<7>(x00011);
                            x00100 = rotl<7>(x00100);
                            x00101 = rotl<7>(x00101);
                            x00110 = rotl<7>(x00110);
                            x00111 = rotl<7>(x00111);
                            x01000 = rotl<7>(x01000);
                            x01001 = rotl<7>(x01001);
                            x01010 = rotl<7>(x01010);
                            x01011 = rotl<7>(x01011);
                            x01100 = rotl<7>(x01100);
                            x01101 = rotl<7>(x01101);
                            x01110 = rotl<7>(x01110);
                            x01111 = rotl<7>(x01111);

                            // Swap x00klm with x01klm
                            word_swap(x00000, x01000);
                            word_swap(x00001, x01001);
                            word_swap(x00010, x01010);
                            word_swap(x00011, x01011);
                            word_swap(x00100, x01100);
                            word_swap(x00101, x01101);
                            word_swap(x00110, x01110);
                            word_swap(x00111, x01111);

                            // Xor x1jklm into x0jklm
                            x00000 ^= x10000;
                            x00001 ^= x10001;
                            x00010 ^= x10010;
                            x00011 ^= x10011;
                            x00100 ^= x10100;
                            x00101 ^= x10101;
                            x00110 ^= x10110;
                            x00111 ^= x10111;
                            x01000 ^= x11000;
                            x01001 ^= x11001;
                            x01010 ^= x11010;
                            x01011 ^= x11011;
                            x01100 ^= x11100;
                            x01101 ^= x11101;
                            x01110 ^= x11110;
                            x01111 ^= x11111;

                            // Swap x1jk0m with x1jk1m
                            word_swap(x10000, x10010);
                            word_swap(x10001, x10011);
                            word_swap(x10100, x10110);
                            word_swap(x10101, x10111);
                            word_swap(x11000, x11010);
                            word_swap(x11001, x11011);
                            word_swap(x11100, x11110);
                            word_swap(x11101, x11111);

                            // Add x0jklm into x1jklm modulo 2**32
                            x10000 += x00000;
                            x10001 += x00001;
                            x10010 += x00010;
                            x10011 += x00011;
                            x10100 += x00100;
                            x10101 += x00101;
                            x10110 += x00110;
                            x10111 += x00111;
                            x11000 += x01000;
                            x11001 += x01001;
                            x11010 += x01010;
                            x11011 += x01011;
                            x11100 += x01100;
                            x11101 += x01101;
                            x11110 += x01110;
                            x11111 += x01111;

                            // Rotate x0jkml upward by 11 bits
                            x00000 = rotl<11>(x00000);
                            x00001 = rotl<11>(x00001);
                            x00010 = rotl<11>(x00010);
                            x00011 = rotl<11>(x00011);
                            x00100 = rotl<11>(x00100);
                            x00101 = rotl<11>(x00101);
                            x00110 = rotl<11>(x00110);
                            x00111 = rotl<11>(x00111);
                            x01000 = rotl<11>(x01000);
                            x01001 = rotl<11>(x01001);
                            x01010 = rotl<11>(x01010);
                            x01011 = rotl<11>(x01011);
                            x01100 = rotl<11>(x01100);
                            x01101 = rotl<11>(x01101);
                            x01110 = rotl<11>(x01110);
                            x01111 = rotl<11>(x01111);

                            // Swap x0j0lm with x0j1lm
                            word_swap(x00000, x00100);
                            word_swap(x00001, x00101);
                            word_swap(x00010, x00110);
                            word_swap(x00011, x00111);
                            word_swap(x01000, x01100);
                            word_swap(x01001, x01101);
                            word_swap(x01010, x01110);
                            word_swap(x01011, x01111);

                            // Xor x1jklm into x0jklm
                            x00000 ^= x10000;
                            x00001 ^= x10001;
                            x00010 ^= x10010;
                            x00011 ^= x10011;
                            x00100 ^= x10100;
                            x00101 ^= x10101;
                            x00110 ^= x10110;
                            x00111 ^= x10111;
                            x01000 ^= x11000;
                            x01001 ^= x11001;
                            x01010 ^= x11010;
                            x01011 ^= x11011;
                            x01100 ^= x11100;
                            x01101 ^= x11101;
                            x01110 ^= x11110;
                            x01111 ^= x11111;

                            // Swap x1jkl0 with x1jkl1
                            word_swap(x10000, x10001);
                            word_swap(x10010, x10011);
                            word_swap(x10100, x10101);
                            word_swap(x10110, x10111);
                            word_swap(x11000, x11001);
                            word_swap(x11010, x11011);
                            word_swap(x11100, x11101);
                            word_swap(x11110, x11111);
                        }

                        state[0] = x00000;
                        state[1] = x00001;
                        state[2] = x00010;
                        state[3] = x00011;
                        state[4] = x00100;
                        state[5] = x00101;
                        state[6] = x00110;
                        state[7] = x00111;
                        state[8] = x01000;
                        state[9] = x01001;
                        state[10] = x01010;
                        state[11] = x01011;
                        state[12] = x01100;
                        state[13] = x01101;
                        state[14] = x01110;
                        state[15] = x01111;
                        state[16] = x10000;
                        state[17] = x10001;
                        state[18] = x10010;
                        state[19] = x10011;
                        state[20] = x10100;
                        state[21] = x10101;
                        state[22] = x10110;
                        state[23] = x10111;
                        state[24] = x11000;
                        state[25] = x11001;
                        state[26] = x11010;
                        state[27] = x11011;
                        state[28] = x11100;
                        state[29] = x11101;
                        state[30] = x11110;
                        state[31] = x11111;

#endif

#endif

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
                        printf("Resulting state:\n");
                        for (unsigned i = 0; i < state.size(); ++i) {
                            printf("%.8x%c", state[i], (i + 1) % 8 ? ' ' : '\n');
                        }
#endif
                    }
                };

                template<unsigned r, unsigned b, unsigned h>
                struct cubehash_policy : basic_cubehash_policy {

                    // CubeHash is only defined for r in {1, 2, 3, ..., 128}
                    BOOST_STATIC_ASSERT(r != 0);
                    BOOST_STATIC_ASSERT(r <= 128);

                    // CubeHash is only defined for b in {1, 2, 3, ..., 128}
                    BOOST_STATIC_ASSERT(b != 0);
                    BOOST_STATIC_ASSERT(b <= 128);

                    // This implementation of CubeHash only handles b a multiple of 4,
                    // so that input is a multiple of the size of a word
                    BOOST_STATIC_ASSERT(b % 4 == 0);

                    // CubeHash is only defined for h in {8, 16, 24, ..., 512}
                    BOOST_STATIC_ASSERT(h != 0);
                    BOOST_STATIC_ASSERT(h <= 512);
                    BOOST_STATIC_ASSERT(h % 8 == 0);

                    constexpr static const std::size_t block_bits = b * 8;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t digest_bits = h;
                    typedef hash::static_digest<digest_bits> digest_type;

                    inline static void transform_r(state_type &state) {
                        transform(state, r);
                    }

                    inline static void transform_10r(state_type &state) {
                        transform(state, 10 * r);
                    }

                    struct iv_generator {
#ifdef CRYPTO3_HASH_NO_OPTIMIZATION
                        state_type operator()() const {
                            state_type state = {{}};
                            state[0] = h / 8;
                            state[1] = b;
                            state[2] = r;
                            transform_10r(state);
                            return state;
                        }
#else

                        inline state_type const &operator()() const {
                            static state_type const H0 = gen();
                            return H0;
                        }

                    private:
                        inline static state_type gen() {
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
                            printf("Generating static IV for CubeHash%d/%d-%d.\n", r, b, h);
#endif
                            state_type state = {{h / 8, b, r}};
                            transform_10r(state);
                            return state;
                        }

#endif
                    };
                };

            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_CUBEHASH_POLICY_HPP
