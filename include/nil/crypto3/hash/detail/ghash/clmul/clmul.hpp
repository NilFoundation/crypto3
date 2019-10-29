//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_GCM_CLMUL_HPP
#define CRYPTO3_GCM_CLMUL_HPP

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                CRYPTO3_FUNC_ISA("sse2")

                inline __m128i gcm_reduce(const __m128i &B0, const __m128i &B1) {
                    __m128i T0, T1, T2, T3;

                    T0 = _mm_srli_epi32(B1, 31);
                    T1 = _mm_slli_epi32(B1, 1);
                    T2 = _mm_srli_epi32(B0, 31);
                    T3 = _mm_slli_epi32(B0, 1);

                    T3 = _mm_or_si128(T3, _mm_srli_si128(T0, 12));
                    T3 = _mm_or_si128(T3, _mm_slli_si128(T2, 4));
                    T1 = _mm_or_si128(T1, _mm_slli_si128(T0, 4));

                    T0 = _mm_xor_si128(_mm_slli_epi32(T1, 31), _mm_slli_epi32(T1, 30));
                    T0 = _mm_xor_si128(T0, _mm_slli_epi32(T1, 25));

                    T1 = _mm_xor_si128(T1, _mm_slli_si128(T0, 12));

                    T0 = _mm_xor_si128(T3, _mm_srli_si128(T0, 4));
                    T0 = _mm_xor_si128(T0, T1);
                    T0 = _mm_xor_si128(T0, _mm_srli_epi32(T1, 7));
                    T0 = _mm_xor_si128(T0, _mm_srli_epi32(T1, 1));
                    T0 = _mm_xor_si128(T0, _mm_srli_epi32(T1, 2));
                    return T0;
                }

                CRYPTO3_FUNC_ISA("pclmul,sse2")

                inline __m128i gcm_multiply(const __m128i &H, const __m128i &x) {
                    __m128i T0, T1, T2, T3;

                    T0 = _mm_clmulepi64_si128(x, H, 0x11);
                    T1 = _mm_clmulepi64_si128(x, H, 0x10);
                    T2 = _mm_clmulepi64_si128(x, H, 0x01);
                    T3 = _mm_clmulepi64_si128(x, H, 0x00);

                    T1 = _mm_xor_si128(T1, T2);
                    T0 = _mm_xor_si128(T0, _mm_srli_si128(T1, 8));
                    T3 = _mm_xor_si128(T3, _mm_slli_si128(T1, 8));

                    return gcm_reduce(T0, T3);
                }

                CRYPTO3_FUNC_ISA("ssse3")

                void gcm_multiply_ssse3(uint8_t x[16], const uint64_t HM[256], const uint8_t input_bytes[],
                                        size_t blocks) {
                    const __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

                    const __m128i *HM_mm = reinterpret_cast<const __m128i *>(HM);

                    __m128i X = _mm_loadu_si128(reinterpret_cast<__m128i *>(x));
                    X = _mm_shuffle_epi8(X, BSWAP_MASK);

                    const __m128i ones = _mm_set1_epi8(-1);

                    for (size_t b = 0; b != blocks; ++b) {
                        __m128i M = _mm_loadu_si128(reinterpret_cast<const __m128i *>(input_bytes) + b);
                        M = _mm_shuffle_epi8(M, BSWAP_MASK);

                        X = _mm_xor_si128(X, M);

                        __m128i Z = _mm_setzero_si128();

                        for (size_t i = 0; i != 64; i += 2) {
                            const __m128i HM0 = _mm_loadu_si128(HM_mm + 2 * i);
                            const __m128i HM1 = _mm_loadu_si128(HM_mm + 2 * i + 1);
                            const __m128i HM2 = _mm_loadu_si128(HM_mm + 2 * i + 2);
                            const __m128i HM3 = _mm_loadu_si128(HM_mm + 2 * i + 3);

                            const __m128i XMASK1 = _mm_add_epi64(_mm_srli_epi64(X, 63), ones);
                            X = _mm_slli_epi64(X, 1);
                            const __m128i XMASK2 = _mm_add_epi64(_mm_srli_epi64(X, 63), ones);
                            X = _mm_slli_epi64(X, 1);

                            Z = _mm_xor_si128(Z, _mm_andnot_si128(_mm_unpackhi_epi64(XMASK1, XMASK1), HM0));
                            Z = _mm_xor_si128(Z, _mm_andnot_si128(_mm_unpacklo_epi64(XMASK1, XMASK1), HM1));
                            Z = _mm_xor_si128(Z, _mm_andnot_si128(_mm_unpackhi_epi64(XMASK2, XMASK2), HM2));
                            Z = _mm_xor_si128(Z, _mm_andnot_si128(_mm_unpacklo_epi64(XMASK2, XMASK2), HM3));
                        }

                        X = _mm_shuffle_epi32(Z, _MM_SHUFFLE(1, 0, 3, 2));
                    }

                    X = _mm_shuffle_epi8(X, BSWAP_MASK);
                    _mm_storeu_si128(reinterpret_cast<__m128i *>(x), X);
                }

                CRYPTO3_FUNC_ISA("pclmul,sse2")

                inline __m128i gcm_multiply_x4(const __m128i &H1, const __m128i &H2, const __m128i &H3,
                                               const __m128i &H4, const __m128i &X1, const __m128i &X2,
                                               const __m128i &X3, const __m128i &X4) {
                    /*
                     * Mutiply with delayed reduction, algorithm by Krzysztof Jankowski
                     * and Pierre Laurent of Intel
                     */

                    const __m128i H1_X1_lo = _mm_clmulepi64_si128(H1, X1, 0x00);
                    const __m128i H2_X2_lo = _mm_clmulepi64_si128(H2, X2, 0x00);
                    const __m128i H3_X3_lo = _mm_clmulepi64_si128(H3, X3, 0x00);
                    const __m128i H4_X4_lo = _mm_clmulepi64_si128(H4, X4, 0x00);

                    const __m128i lo =
                        _mm_xor_si128(_mm_xor_si128(H1_X1_lo, H2_X2_lo), _mm_xor_si128(H3_X3_lo, H4_X4_lo));

                    const __m128i H1_X1_hi = _mm_clmulepi64_si128(H1, X1, 0x11);
                    const __m128i H2_X2_hi = _mm_clmulepi64_si128(H2, X2, 0x11);
                    const __m128i H3_X3_hi = _mm_clmulepi64_si128(H3, X3, 0x11);
                    const __m128i H4_X4_hi = _mm_clmulepi64_si128(H4, X4, 0x11);

                    const __m128i hi =
                        _mm_xor_si128(_mm_xor_si128(H1_X1_hi, H2_X2_hi), _mm_xor_si128(H3_X3_hi, H4_X4_hi));

                    __m128i T0 = _mm_xor_si128(lo, hi);
                    __m128i T1, T2, T3, T4;

                    T1 = _mm_xor_si128(_mm_srli_si128(H1, 8), H1);
                    T2 = _mm_xor_si128(_mm_srli_si128(X1, 8), X1);
                    T3 = _mm_xor_si128(_mm_srli_si128(H2, 8), H2);
                    T4 = _mm_xor_si128(_mm_srli_si128(X2, 8), X2);
                    T0 = _mm_xor_si128(T0, _mm_clmulepi64_si128(T1, T2, 0x00));
                    T0 = _mm_xor_si128(T0, _mm_clmulepi64_si128(T3, T4, 0x00));

                    T1 = _mm_xor_si128(_mm_srli_si128(H3, 8), H3);
                    T2 = _mm_xor_si128(_mm_srli_si128(X3, 8), X3);
                    T3 = _mm_xor_si128(_mm_srli_si128(H4, 8), H4);
                    T4 = _mm_xor_si128(_mm_srli_si128(X4, 8), X4);
                    T0 = _mm_xor_si128(T0, _mm_clmulepi64_si128(T1, T2, 0x00));
                    T0 = _mm_xor_si128(T0, _mm_clmulepi64_si128(T3, T4, 0x00));

                    T1 = _mm_xor_si128(_mm_srli_si128(T0, 8), hi);
                    T2 = _mm_xor_si128(_mm_slli_si128(T0, 8), lo);

                    return gcm_reduce(T1, T2);
                }

                CRYPTO3_FUNC_ISA("ssse3")
                void gcm_clmul_precompute(const uint8_t H[16], uint64_t H_pow[4 * 2]) {
                    const __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

                    const __m128i H =
                        _mm_shuffle_epi8(_mm_loadu_si128(reinterpret_cast<const __m128i *>(H_bytes)), BSWAP_MASK);
                    const __m128i H2 = gcm_multiply(H, H);
                    const __m128i H3 = gcm_multiply(H, H2);
                    const __m128i H4 = gcm_multiply(H, H3);

                    __m128i *H_pow_mm = reinterpret_cast<__m128i *>(H_pow);

                    _mm_storeu_si128(H_pow_mm + 0, H);
                    _mm_storeu_si128(H_pow_mm + 1, H2);
                    _mm_storeu_si128(H_pow_mm + 2, H3);
                    _mm_storeu_si128(H_pow_mm + 3, H4);
                }

                CRYPTO3_FUNC_ISA("ssse3")
                void gcm_multiply_clmul(uint8_t x[16], const uint64_t H_pow[4 * 2], const uint8_t input[],
                                        size_t blocks) {
                    /*
                     * Algorithms 1 and 5 from Intel's CLMUL guide
                     */
                    const __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

                    const __m128i *input = reinterpret_cast<const __m128i *>(input_bytes);

                    const __m128i *H_pow_mm = reinterpret_cast<const __m128i *>(H_pow);

                    const __m128i H = _mm_loadu_si128(H_pow_mm);

                    __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i *>(x));
                    a = _mm_shuffle_epi8(a, BSWAP_MASK);

                    if (blocks >= 4) {
                        const __m128i H2 = _mm_loadu_si128(H_pow_mm + 1);
                        const __m128i H3 = _mm_loadu_si128(H_pow_mm + 2);
                        const __m128i H4 = _mm_loadu_si128(H_pow_mm + 3);

                        while (blocks >= 4) {
                            const __m128i m0 = _mm_shuffle_epi8(_mm_loadu_si128(input + 0), BSWAP_MASK);
                            const __m128i m1 = _mm_shuffle_epi8(_mm_loadu_si128(input + 1), BSWAP_MASK);
                            const __m128i m2 = _mm_shuffle_epi8(_mm_loadu_si128(input + 2), BSWAP_MASK);
                            const __m128i m3 = _mm_shuffle_epi8(_mm_loadu_si128(input + 3), BSWAP_MASK);

                            a = _mm_xor_si128(a, m0);
                            a = gcm_multiply_x4(H, H2, H3, H4, m3, m2, m1, a);

                            input += 4;
                            blocks -= 4;
                        }
                    }

                    for (size_t i = 0; i != blocks; ++i) {
                        const __m128i m = _mm_shuffle_epi8(_mm_loadu_si128(input + i), BSWAP_MASK);

                        a = _mm_xor_si128(a, m);
                        a = gcm_multiply(H, a);
                    }

                    a = _mm_shuffle_epi8(a, BSWAP_MASK);
                    _mm_storeu_si128(reinterpret_cast<__m128i *>(x), a);
                }
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif
