//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_STREAM_CHACHA_SSE2_IMPL_HPP
#define CRYPTO3_STREAM_CHACHA_SSE2_IMPL_HPP

#include <nil/crypto3/detail/config.hpp>

#include <nil/crypto3/stream/detail/chacha/chacha_policy.hpp>

#include <emmintrin.h>

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<std::size_t Round, std::size_t IVSize, std::size_t KeyBits>
                struct chacha_sse2_impl {
                    typedef chacha_policy<Round, IVSize, KeyBits> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t rounds = policy_type::rounds;

                    constexpr static const std::size_t min_key_schedule_bits = policy_type::key_schedule_bits;
                    constexpr static const std::size_t min_key_schedule_size = policy_type::key_schedule_size;
                    typedef typename policy_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_size = policy_type::block_size;
                    typedef typename policy_type::block_type block_type;

                    inline static void chacha_x8(const std::array<std::uint8_t, block_size * 8> &block,
                                                 key_schedule_type &schedule) {
                        chacha_x4(block, schedule);
                        chacha_x4(std::array<std::uint8_t, block_size * 4>(block.begin() + block_size * 4, block.end()),
                                  schedule);
                    }

                    static BOOST_ATTRIBUTE_TARGET("sse2") void chacha_x4(
                        const std::array<std::uint8_t, block_size * 4> &block,
                        key_schedule_type &schedule) {
                        const __m128i *input_mm = reinterpret_cast<const __m128i *>(schedule);
                        __m128i *output_mm = reinterpret_cast<__m128i *>(block);

                        __m128i input0 = _mm_loadu_si128(input_mm);
                        __m128i input1 = _mm_loadu_si128(input_mm + 1);
                        __m128i input2 = _mm_loadu_si128(input_mm + 2);
                        __m128i input3 = _mm_loadu_si128(input_mm + 3);

                        // TODO: try transposing, which would avoid the permutations each round

#define mm_rotl(r, n) _mm_or_si128(_mm_slli_epi32(r, n), _mm_srli_epi32(r, 32 - (n)))

                        __m128i r0_0 = input0;
                        __m128i r0_1 = input1;
                        __m128i r0_2 = input2;
                        __m128i r0_3 = input3;

                        __m128i r1_0 = input0;
                        __m128i r1_1 = input1;
                        __m128i r1_2 = input2;
                        __m128i r1_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 1));

                        __m128i r2_0 = input0;
                        __m128i r2_1 = input1;
                        __m128i r2_2 = input2;
                        __m128i r2_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 2));

                        __m128i r3_0 = input0;
                        __m128i r3_1 = input1;
                        __m128i r3_2 = input2;
                        __m128i r3_3 = _mm_add_epi64(r0_3, _mm_set_epi32(0, 0, 0, 3));

                        for (size_t r = 0; r != rounds / 2; ++r) {
                            r0_0 = _mm_add_epi32(r0_0, r0_1);
                            r1_0 = _mm_add_epi32(r1_0, r1_1);
                            r2_0 = _mm_add_epi32(r2_0, r2_1);
                            r3_0 = _mm_add_epi32(r3_0, r3_1);

                            r0_3 = _mm_xor_si128(r0_3, r0_0);
                            r1_3 = _mm_xor_si128(r1_3, r1_0);
                            r2_3 = _mm_xor_si128(r2_3, r2_0);
                            r3_3 = _mm_xor_si128(r3_3, r3_0);

                            r0_3 = mm_rotl(r0_3, 16);
                            r1_3 = mm_rotl(r1_3, 16);
                            r2_3 = mm_rotl(r2_3, 16);
                            r3_3 = mm_rotl(r3_3, 16);

                            r0_2 = _mm_add_epi32(r0_2, r0_3);
                            r1_2 = _mm_add_epi32(r1_2, r1_3);
                            r2_2 = _mm_add_epi32(r2_2, r2_3);
                            r3_2 = _mm_add_epi32(r3_2, r3_3);

                            r0_1 = _mm_xor_si128(r0_1, r0_2);
                            r1_1 = _mm_xor_si128(r1_1, r1_2);
                            r2_1 = _mm_xor_si128(r2_1, r2_2);
                            r3_1 = _mm_xor_si128(r3_1, r3_2);

                            r0_1 = mm_rotl(r0_1, 12);
                            r1_1 = mm_rotl(r1_1, 12);
                            r2_1 = mm_rotl(r2_1, 12);
                            r3_1 = mm_rotl(r3_1, 12);

                            r0_0 = _mm_add_epi32(r0_0, r0_1);
                            r1_0 = _mm_add_epi32(r1_0, r1_1);
                            r2_0 = _mm_add_epi32(r2_0, r2_1);
                            r3_0 = _mm_add_epi32(r3_0, r3_1);

                            r0_3 = _mm_xor_si128(r0_3, r0_0);
                            r1_3 = _mm_xor_si128(r1_3, r1_0);
                            r2_3 = _mm_xor_si128(r2_3, r2_0);
                            r3_3 = _mm_xor_si128(r3_3, r3_0);

                            r0_3 = mm_rotl(r0_3, 8);
                            r1_3 = mm_rotl(r1_3, 8);
                            r2_3 = mm_rotl(r2_3, 8);
                            r3_3 = mm_rotl(r3_3, 8);

                            r0_2 = _mm_add_epi32(r0_2, r0_3);
                            r1_2 = _mm_add_epi32(r1_2, r1_3);
                            r2_2 = _mm_add_epi32(r2_2, r2_3);
                            r3_2 = _mm_add_epi32(r3_2, r3_3);

                            r0_1 = _mm_xor_si128(r0_1, r0_2);
                            r1_1 = _mm_xor_si128(r1_1, r1_2);
                            r2_1 = _mm_xor_si128(r2_1, r2_2);
                            r3_1 = _mm_xor_si128(r3_1, r3_2);

                            r0_1 = mm_rotl(r0_1, 7);
                            r1_1 = mm_rotl(r1_1, 7);
                            r2_1 = mm_rotl(r2_1, 7);
                            r3_1 = mm_rotl(r3_1, 7);

                            r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(0, 3, 2, 1));
                            r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
                            r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(2, 1, 0, 3));

                            r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(0, 3, 2, 1));
                            r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
                            r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(2, 1, 0, 3));

                            r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(0, 3, 2, 1));
                            r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
                            r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(2, 1, 0, 3));

                            r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(0, 3, 2, 1));
                            r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
                            r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(2, 1, 0, 3));

                            r0_0 = _mm_add_epi32(r0_0, r0_1);
                            r1_0 = _mm_add_epi32(r1_0, r1_1);
                            r2_0 = _mm_add_epi32(r2_0, r2_1);
                            r3_0 = _mm_add_epi32(r3_0, r3_1);

                            r0_3 = _mm_xor_si128(r0_3, r0_0);
                            r1_3 = _mm_xor_si128(r1_3, r1_0);
                            r2_3 = _mm_xor_si128(r2_3, r2_0);
                            r3_3 = _mm_xor_si128(r3_3, r3_0);

                            r0_3 = mm_rotl(r0_3, 16);
                            r1_3 = mm_rotl(r1_3, 16);
                            r2_3 = mm_rotl(r2_3, 16);
                            r3_3 = mm_rotl(r3_3, 16);

                            r0_2 = _mm_add_epi32(r0_2, r0_3);
                            r1_2 = _mm_add_epi32(r1_2, r1_3);
                            r2_2 = _mm_add_epi32(r2_2, r2_3);
                            r3_2 = _mm_add_epi32(r3_2, r3_3);

                            r0_1 = _mm_xor_si128(r0_1, r0_2);
                            r1_1 = _mm_xor_si128(r1_1, r1_2);
                            r2_1 = _mm_xor_si128(r2_1, r2_2);
                            r3_1 = _mm_xor_si128(r3_1, r3_2);

                            r0_1 = mm_rotl(r0_1, 12);
                            r1_1 = mm_rotl(r1_1, 12);
                            r2_1 = mm_rotl(r2_1, 12);
                            r3_1 = mm_rotl(r3_1, 12);

                            r0_0 = _mm_add_epi32(r0_0, r0_1);
                            r1_0 = _mm_add_epi32(r1_0, r1_1);
                            r2_0 = _mm_add_epi32(r2_0, r2_1);
                            r3_0 = _mm_add_epi32(r3_0, r3_1);

                            r0_3 = _mm_xor_si128(r0_3, r0_0);
                            r1_3 = _mm_xor_si128(r1_3, r1_0);
                            r2_3 = _mm_xor_si128(r2_3, r2_0);
                            r3_3 = _mm_xor_si128(r3_3, r3_0);

                            r0_3 = mm_rotl(r0_3, 8);
                            r1_3 = mm_rotl(r1_3, 8);
                            r2_3 = mm_rotl(r2_3, 8);
                            r3_3 = mm_rotl(r3_3, 8);

                            r0_2 = _mm_add_epi32(r0_2, r0_3);
                            r1_2 = _mm_add_epi32(r1_2, r1_3);
                            r2_2 = _mm_add_epi32(r2_2, r2_3);
                            r3_2 = _mm_add_epi32(r3_2, r3_3);

                            r0_1 = _mm_xor_si128(r0_1, r0_2);
                            r1_1 = _mm_xor_si128(r1_1, r1_2);
                            r2_1 = _mm_xor_si128(r2_1, r2_2);
                            r3_1 = _mm_xor_si128(r3_1, r3_2);

                            r0_1 = mm_rotl(r0_1, 7);
                            r1_1 = mm_rotl(r1_1, 7);
                            r2_1 = mm_rotl(r2_1, 7);
                            r3_1 = mm_rotl(r3_1, 7);

                            r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(2, 1, 0, 3));
                            r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
                            r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(0, 3, 2, 1));

                            r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(2, 1, 0, 3));
                            r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
                            r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(0, 3, 2, 1));

                            r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(2, 1, 0, 3));
                            r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
                            r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(0, 3, 2, 1));

                            r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(2, 1, 0, 3));
                            r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
                            r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(0, 3, 2, 1));
                        }

                        r0_0 = _mm_add_epi32(r0_0, input0);
                        r0_1 = _mm_add_epi32(r0_1, input1);
                        r0_2 = _mm_add_epi32(r0_2, input2);
                        r0_3 = _mm_add_epi32(r0_3, input3);

                        r1_0 = _mm_add_epi32(r1_0, input0);
                        r1_1 = _mm_add_epi32(r1_1, input1);
                        r1_2 = _mm_add_epi32(r1_2, input2);
                        r1_3 = _mm_add_epi32(r1_3, input3);
                        r1_3 = _mm_add_epi64(r1_3, _mm_set_epi32(0, 0, 0, 1));

                        r2_0 = _mm_add_epi32(r2_0, input0);
                        r2_1 = _mm_add_epi32(r2_1, input1);
                        r2_2 = _mm_add_epi32(r2_2, input2);
                        r2_3 = _mm_add_epi32(r2_3, input3);
                        r2_3 = _mm_add_epi64(r2_3, _mm_set_epi32(0, 0, 0, 2));

                        r3_0 = _mm_add_epi32(r3_0, input0);
                        r3_1 = _mm_add_epi32(r3_1, input1);
                        r3_2 = _mm_add_epi32(r3_2, input2);
                        r3_3 = _mm_add_epi32(r3_3, input3);
                        r3_3 = _mm_add_epi64(r3_3, _mm_set_epi32(0, 0, 0, 3));

                        _mm_storeu_si128(output_mm + 0, r0_0);
                        _mm_storeu_si128(output_mm + 1, r0_1);
                        _mm_storeu_si128(output_mm + 2, r0_2);
                        _mm_storeu_si128(output_mm + 3, r0_3);

                        _mm_storeu_si128(output_mm + 4, r1_0);
                        _mm_storeu_si128(output_mm + 5, r1_1);
                        _mm_storeu_si128(output_mm + 6, r1_2);
                        _mm_storeu_si128(output_mm + 7, r1_3);

                        _mm_storeu_si128(output_mm + 8, r2_0);
                        _mm_storeu_si128(output_mm + 9, r2_1);
                        _mm_storeu_si128(output_mm + 10, r2_2);
                        _mm_storeu_si128(output_mm + 11, r2_3);

                        _mm_storeu_si128(output_mm + 12, r3_0);
                        _mm_storeu_si128(output_mm + 13, r3_1);
                        _mm_storeu_si128(output_mm + 14, r3_2);
                        _mm_storeu_si128(output_mm + 15, r3_3);

#undef mm_rotl

                        schedule[12] += 4;
                        if (schedule[12] < 4) {
                            schedule[13]++;
                        }
                    }
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CHACHA_SSE2_IMPL_HPP
