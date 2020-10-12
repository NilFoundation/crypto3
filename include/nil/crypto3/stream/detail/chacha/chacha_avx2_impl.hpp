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

#ifndef CRYPTO3_STREAM_CHACHA_AVX2_IMPL_HPP
#define CRYPTO3_STREAM_CHACHA_AVX2_IMPL_HPP

#include <nil/crypto3/detail/config.hpp>

#include <nil/crypto3/stream/detail/chacha/chacha_policy.hpp>

#include <immintrin.h>

namespace nil {
    namespace crypto3 {
        namespace stream {
            namespace detail {
                template<std::size_t Round, std::size_t IVSize, std::size_t KeyBits>
                struct chacha_avx2_impl {
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

                    static BOOST_ATTRIBUTE_TARGET("avx2") void chacha_x8(
                        const std::array<std::uint8_t, block_size * 8> &block,
                        key_schedule_type &schedule) {
                        _mm256_zeroupper();

                        const __m256i CTR0 = _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0);

                        const word_type C = 0xFFFFFFFF - schedule[12];
                        const __m256i CTR1 = _mm256_set_epi32(C < 7, C < 6, C < 5, C < 4, C < 3, C < 2, C < 1, 0);

                        __m256i R00 = _mm256_set1_epi32(schedule[0]);
                        __m256i R01 = _mm256_set1_epi32(schedule[1]);
                        __m256i R02 = _mm256_set1_epi32(schedule[2]);
                        __m256i R03 = _mm256_set1_epi32(schedule[3]);
                        __m256i R04 = _mm256_set1_epi32(schedule[4]);
                        __m256i R05 = _mm256_set1_epi32(schedule[5]);
                        __m256i R06 = _mm256_set1_epi32(schedule[6]);
                        __m256i R07 = _mm256_set1_epi32(schedule[7]);
                        __m256i R08 = _mm256_set1_epi32(schedule[8]);
                        __m256i R09 = _mm256_set1_epi32(schedule[9]);
                        __m256i R10 = _mm256_set1_epi32(schedule[10]);
                        __m256i R11 = _mm256_set1_epi32(schedule[11]);
                        __m256i R12 = _mm256_set1_epi32(schedule[12]) + CTR0;
                        __m256i R13 = _mm256_set1_epi32(schedule[13]) + CTR1;
                        __m256i R14 = _mm256_set1_epi32(schedule[14]);
                        __m256i R15 = _mm256_set1_epi32(schedule[15]);

                        for (size_t r = 0; r != rounds / 2; ++r) {
                            R00 += R04;
                            R01 += R05;
                            R02 += R06;
                            R03 += R07;

                            R12 ^= R00;
                            R13 ^= R01;
                            R14 ^= R02;
                            R15 ^= R03;

                            const __m256i shuf_rotl_16 =
                                _mm256_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9,
                                                8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2);

                            R12 = _mm256_shuffle_epi8(R12, shuf_rotl_16);
                            R13 = _mm256_shuffle_epi8(R13, shuf_rotl_16);
                            R14 = _mm256_shuffle_epi8(R14, shuf_rotl_16);
                            R15 = _mm256_shuffle_epi8(R15, shuf_rotl_16);

                            R08 += R12;
                            R09 += R13;
                            R10 += R14;
                            R11 += R15;

                            R04 ^= R08;
                            R05 ^= R09;
                            R06 ^= R10;
                            R07 ^= R11;

                            R04 = _mm256_or_si256(_mm256_slli_epi32(R04, 12), _mm256_srli_epi32(R04, 32 - 12));
                            R05 = _mm256_or_si256(_mm256_slli_epi32(R05, 12), _mm256_srli_epi32(R05, 32 - 12));
                            R06 = _mm256_or_si256(_mm256_slli_epi32(R06, 12), _mm256_srli_epi32(R06, 32 - 12));
                            R07 = _mm256_or_si256(_mm256_slli_epi32(R07, 12), _mm256_srli_epi32(R07, 32 - 12));

                            R00 += R04;
                            R01 += R05;
                            R02 += R06;
                            R03 += R07;

                            R12 ^= R00;
                            R13 ^= R01;
                            R14 ^= R02;
                            R15 ^= R03;

                            const __m256i shuf_rotl_8 =
                                _mm256_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3, 14, 13, 12, 15,
                                                10, 9, 8, 11, 6, 5, 4, 7, 2, 1, 0, 3);

                            R12 = _mm256_shuffle_epi8(R12, shuf_rotl_8);
                            R13 = _mm256_shuffle_epi8(R13, shuf_rotl_8);
                            R14 = _mm256_shuffle_epi8(R14, shuf_rotl_8);
                            R15 = _mm256_shuffle_epi8(R15, shuf_rotl_8);

                            R08 += R12;
                            R09 += R13;
                            R10 += R14;
                            R11 += R15;

                            R04 ^= R08;
                            R05 ^= R09;
                            R06 ^= R10;
                            R07 ^= R11;

                            R04 = _mm256_or_si256(_mm256_slli_epi32(R04, 7), _mm256_srli_epi32(R04, 32 - 7));
                            R05 = _mm256_or_si256(_mm256_slli_epi32(R05, 7), _mm256_srli_epi32(R05, 32 - 7));
                            R06 = _mm256_or_si256(_mm256_slli_epi32(R06, 7), _mm256_srli_epi32(R06, 32 - 7));
                            R07 = _mm256_or_si256(_mm256_slli_epi32(R07, 7), _mm256_srli_epi32(R07, 32 - 7));

                            R00 += R05;
                            R01 += R06;
                            R02 += R07;
                            R03 += R04;

                            R15 ^= R00;
                            R12 ^= R01;
                            R13 ^= R02;
                            R14 ^= R03;

                            R15 = _mm256_shuffle_epi8(R15, shuf_rotl_16);
                            R12 = _mm256_shuffle_epi8(R12, shuf_rotl_16);
                            R13 = _mm256_shuffle_epi8(R13, shuf_rotl_16);
                            R14 = _mm256_shuffle_epi8(R14, shuf_rotl_16);

                            R10 += R15;
                            R11 += R12;
                            R08 += R13;
                            R09 += R14;

                            R05 ^= R10;
                            R06 ^= R11;
                            R07 ^= R08;
                            R04 ^= R09;

                            R05 = _mm256_or_si256(_mm256_slli_epi32(R05, 12), _mm256_srli_epi32(R05, 32 - 12));
                            R06 = _mm256_or_si256(_mm256_slli_epi32(R06, 12), _mm256_srli_epi32(R06, 32 - 12));
                            R07 = _mm256_or_si256(_mm256_slli_epi32(R07, 12), _mm256_srli_epi32(R07, 32 - 12));
                            R04 = _mm256_or_si256(_mm256_slli_epi32(R04, 12), _mm256_srli_epi32(R04, 32 - 12));

                            R00 += R05;
                            R01 += R06;
                            R02 += R07;
                            R03 += R04;

                            R15 ^= R00;
                            R12 ^= R01;
                            R13 ^= R02;
                            R14 ^= R03;

                            R15 = _mm256_shuffle_epi8(R15, shuf_rotl_8);
                            R12 = _mm256_shuffle_epi8(R12, shuf_rotl_8);
                            R13 = _mm256_shuffle_epi8(R13, shuf_rotl_8);
                            R14 = _mm256_shuffle_epi8(R14, shuf_rotl_8);

                            R10 += R15;
                            R11 += R12;
                            R08 += R13;
                            R09 += R14;

                            R05 ^= R10;
                            R06 ^= R11;
                            R07 ^= R08;
                            R04 ^= R09;

                            R05 = _mm256_or_si256(_mm256_slli_epi32(R05, 7), _mm256_srli_epi32(R05, 32 - 7));
                            R06 = _mm256_or_si256(_mm256_slli_epi32(R06, 7), _mm256_srli_epi32(R06, 32 - 7));
                            R07 = _mm256_or_si256(_mm256_slli_epi32(R07, 7), _mm256_srli_epi32(R07, 32 - 7));
                            R04 = _mm256_or_si256(_mm256_slli_epi32(R04, 7), _mm256_srli_epi32(R04, 32 - 7));
                        }

                        R00 += _mm256_set1_epi32(schedule[0]);
                        R01 += _mm256_set1_epi32(schedule[1]);
                        R02 += _mm256_set1_epi32(schedule[2]);
                        R03 += _mm256_set1_epi32(schedule[3]);
                        R04 += _mm256_set1_epi32(schedule[4]);
                        R05 += _mm256_set1_epi32(schedule[5]);
                        R06 += _mm256_set1_epi32(schedule[6]);
                        R07 += _mm256_set1_epi32(schedule[7]);
                        R08 += _mm256_set1_epi32(schedule[8]);
                        R09 += _mm256_set1_epi32(schedule[9]);
                        R10 += _mm256_set1_epi32(schedule[10]);
                        R11 += _mm256_set1_epi32(schedule[11]);
                        R12 += _mm256_set1_epi32(schedule[12]) + CTR0;
                        R13 += _mm256_set1_epi32(schedule[13]) + CTR1;
                        R14 += _mm256_set1_epi32(schedule[14]);
                        R15 += _mm256_set1_epi32(schedule[15]);

                        __m256i T0 = _mm256_unpacklo_epi32(R00, R01);
                        __m256i T1 = _mm256_unpacklo_epi32(R02, R03);
                        __m256i T2 = _mm256_unpackhi_epi32(R00, R01);
                        __m256i T3 = _mm256_unpackhi_epi32(R02, R03);

                        R00 = _mm256_unpacklo_epi64(T0, T1);
                        R01 = _mm256_unpackhi_epi64(T0, T1);
                        R02 = _mm256_unpacklo_epi64(T2, T3);
                        R03 = _mm256_unpackhi_epi64(T2, T3);

                        T0 = _mm256_unpacklo_epi32(R04, R05);
                        T1 = _mm256_unpacklo_epi32(R06, R07);
                        T2 = _mm256_unpackhi_epi32(R04, R05);
                        T3 = _mm256_unpackhi_epi32(R06, R07);

                        R04 = _mm256_unpacklo_epi64(T0, T1);
                        R05 = _mm256_unpackhi_epi64(T0, T1);
                        R06 = _mm256_unpacklo_epi64(T2, T3);
                        R07 = _mm256_unpackhi_epi64(T2, T3);

                        T0 = _mm256_unpacklo_epi32(R08, R09);
                        T1 = _mm256_unpacklo_epi32(R10, R11);
                        T2 = _mm256_unpackhi_epi32(R08, R09);
                        T3 = _mm256_unpackhi_epi32(R10, R11);

                        R08 = _mm256_unpacklo_epi64(T0, T1);
                        R09 = _mm256_unpackhi_epi64(T0, T1);
                        R10 = _mm256_unpacklo_epi64(T2, T3);
                        R11 = _mm256_unpackhi_epi64(T2, T3);

                        T0 = _mm256_unpacklo_epi32(R12, R13);
                        T1 = _mm256_unpacklo_epi32(R14, R15);
                        T2 = _mm256_unpackhi_epi32(R12, R13);
                        T3 = _mm256_unpackhi_epi32(R14, R15);

                        R12 = _mm256_unpacklo_epi64(T0, T1);
                        R13 = _mm256_unpackhi_epi64(T0, T1);
                        R14 = _mm256_unpacklo_epi64(T2, T3);
                        R15 = _mm256_unpackhi_epi64(T2, T3);

                        __m256i *output_mm = reinterpret_cast<__m256i *>(block.data());

                        _mm256_storeu_si256(output_mm, _mm256_permute2x128_si256(R00, R04, 0 + (2 << 4)));
                        _mm256_storeu_si256(output_mm + 1, _mm256_permute2x128_si256(R08, R12, 0 + (2 << 4)));
                        _mm256_storeu_si256(output_mm + 2, _mm256_permute2x128_si256(R01, R05, 0 + (2 << 4)));
                        _mm256_storeu_si256(output_mm + 3, _mm256_permute2x128_si256(R09, R13, 0 + (2 << 4)));
                        _mm256_storeu_si256(output_mm + 4, _mm256_permute2x128_si256(R02, R06, 0 + (2 << 4)));
                        _mm256_storeu_si256(output_mm + 5, _mm256_permute2x128_si256(R10, R14, 0 + (2 << 4)));
                        _mm256_storeu_si256(output_mm + 6, _mm256_permute2x128_si256(R03, R07, 0 + (2 << 4)));
                        _mm256_storeu_si256(output_mm + 7, _mm256_permute2x128_si256(R11, R15, 0 + (2 << 4)));

                        _mm256_storeu_si256(output_mm + 8, _mm256_permute2x128_si256(R00, R04, 1 + (3 << 4)));
                        _mm256_storeu_si256(output_mm + 9, _mm256_permute2x128_si256(R08, R12, 1 + (3 << 4)));
                        _mm256_storeu_si256(output_mm + 10, _mm256_permute2x128_si256(R01, R05, 1 + (3 << 4)));
                        _mm256_storeu_si256(output_mm + 11, _mm256_permute2x128_si256(R09, R13, 1 + (3 << 4)));
                        _mm256_storeu_si256(output_mm + 12, _mm256_permute2x128_si256(R02, R06, 1 + (3 << 4)));
                        _mm256_storeu_si256(output_mm + 13, _mm256_permute2x128_si256(R10, R14, 1 + (3 << 4)));
                        _mm256_storeu_si256(output_mm + 14, _mm256_permute2x128_si256(R03, R07, 1 + (3 << 4)));
                        _mm256_storeu_si256(output_mm + 15, _mm256_permute2x128_si256(R11, R15, 1 + (3 << 4)));

                        _mm256_zeroall();

                        schedule[12] += 8;
                        if (schedule[12] < 8)
                            schedule[13]++;
                    }
                };
            }    // namespace detail
        }        // namespace stream
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CHACHA_AVX2_IMPL_HPP
