//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_KECCAK_AVX2_IMPL_HPP
#define CRYPTO3_KECCAK_AVX2_IMPL_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>
#include <nil/crypto3/hash/detail/keccak/keccak_impl.hpp>

#include <immintrin.h>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename PolicyType>
                struct keccak_1600_avx2_impl {
                    typedef PolicyType policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t round_constants_size = policy_type::rounds;
                    typedef typename std::array<word_type, round_constants_size> round_constants_type;
                    constexpr static const round_constants_type round_constants = {
                        UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082), UINT64_C(0x800000000000808a),
                        UINT64_C(0x8000000080008000), UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
                        UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009), UINT64_C(0x000000000000008a),
                        UINT64_C(0x0000000000000088), UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
                        UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b), UINT64_C(0x8000000000008089),
                        UINT64_C(0x8000000000008003), UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
                        UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a), UINT64_C(0x8000000080008081),
                        UINT64_C(0x8000000000008080), UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)};

// To suppress `warning: ignoring attributes on template argument ‘__m256i’`.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"
                    constexpr static const std::array<__m256i, round_constants_size> round_constants_v = {
                        {{static_cast<long long>(round_constants[0]), static_cast<long long>(round_constants[0]),
                          static_cast<long long>(round_constants[0]), static_cast<long long>(round_constants[0])},
                         {static_cast<long long>(round_constants[1]), static_cast<long long>(round_constants[1]),
                          static_cast<long long>(round_constants[1]), static_cast<long long>(round_constants[1])},
                         {static_cast<long long>(round_constants[2]), static_cast<long long>(round_constants[2]),
                          static_cast<long long>(round_constants[2]), static_cast<long long>(round_constants[2])},
                         {static_cast<long long>(round_constants[3]), static_cast<long long>(round_constants[3]),
                          static_cast<long long>(round_constants[3]), static_cast<long long>(round_constants[3])},
                         {static_cast<long long>(round_constants[4]), static_cast<long long>(round_constants[4]),
                          static_cast<long long>(round_constants[4]), static_cast<long long>(round_constants[4])},
                         {static_cast<long long>(round_constants[5]), static_cast<long long>(round_constants[5]),
                          static_cast<long long>(round_constants[5]), static_cast<long long>(round_constants[5])},
                         {static_cast<long long>(round_constants[6]), static_cast<long long>(round_constants[6]),
                          static_cast<long long>(round_constants[6]), static_cast<long long>(round_constants[6])},
                         {static_cast<long long>(round_constants[7]), static_cast<long long>(round_constants[7]),
                          static_cast<long long>(round_constants[7]), static_cast<long long>(round_constants[7])},
                         {static_cast<long long>(round_constants[8]), static_cast<long long>(round_constants[8]),
                          static_cast<long long>(round_constants[8]), static_cast<long long>(round_constants[8])},
                         {static_cast<long long>(round_constants[9]), static_cast<long long>(round_constants[9]),
                          static_cast<long long>(round_constants[9]), static_cast<long long>(round_constants[9])},
                         {static_cast<long long>(round_constants[10]), static_cast<long long>(round_constants[10]),
                          static_cast<long long>(round_constants[10]), static_cast<long long>(round_constants[10])},
                         {static_cast<long long>(round_constants[11]), static_cast<long long>(round_constants[11]),
                          static_cast<long long>(round_constants[11]), static_cast<long long>(round_constants[11])},
                         {static_cast<long long>(round_constants[12]), static_cast<long long>(round_constants[12]),
                          static_cast<long long>(round_constants[12]), static_cast<long long>(round_constants[12])},
                         {static_cast<long long>(round_constants[13]), static_cast<long long>(round_constants[13]),
                          static_cast<long long>(round_constants[13]), static_cast<long long>(round_constants[13])},
                         {static_cast<long long>(round_constants[14]), static_cast<long long>(round_constants[14]),
                          static_cast<long long>(round_constants[14]), static_cast<long long>(round_constants[14])},
                         {static_cast<long long>(round_constants[15]), static_cast<long long>(round_constants[15]),
                          static_cast<long long>(round_constants[15]), static_cast<long long>(round_constants[15])},
                         {static_cast<long long>(round_constants[16]), static_cast<long long>(round_constants[16]),
                          static_cast<long long>(round_constants[16]), static_cast<long long>(round_constants[16])},
                         {static_cast<long long>(round_constants[17]), static_cast<long long>(round_constants[17]),
                          static_cast<long long>(round_constants[17]), static_cast<long long>(round_constants[17])},
                         {static_cast<long long>(round_constants[18]), static_cast<long long>(round_constants[18]),
                          static_cast<long long>(round_constants[18]), static_cast<long long>(round_constants[18])},
                         {static_cast<long long>(round_constants[19]), static_cast<long long>(round_constants[19]),
                          static_cast<long long>(round_constants[19]), static_cast<long long>(round_constants[19])},
                         {static_cast<long long>(round_constants[20]), static_cast<long long>(round_constants[20]),
                          static_cast<long long>(round_constants[20]), static_cast<long long>(round_constants[20])},
                         {static_cast<long long>(round_constants[21]), static_cast<long long>(round_constants[21]),
                          static_cast<long long>(round_constants[21]), static_cast<long long>(round_constants[21])},
                         {static_cast<long long>(round_constants[22]), static_cast<long long>(round_constants[22]),
                          static_cast<long long>(round_constants[22]), static_cast<long long>(round_constants[22])},
                         {static_cast<long long>(round_constants[23]), static_cast<long long>(round_constants[23]),
                          static_cast<long long>(round_constants[23]), static_cast<long long>(round_constants[23])}}};

                    constexpr static const std::array<__m256i, 6> rho_l = {{{3, 18, 36, 41},
                                                                            {1, 62, 28, 27},
                                                                            {45, 6, 56, 39},
                                                                            {10, 61, 55, 8},
                                                                            {2, 15, 25, 20},
                                                                            {44, 43, 21, 14}}};

                    constexpr static const std::array<__m256i, 6> rho_r = {
                        {{word_bits - 3, word_bits - 18, word_bits - 36, word_bits - 41},
                         {word_bits - 1, word_bits - 62, word_bits - 28, word_bits - 27},
                         {word_bits - 45, word_bits - 6, word_bits - 56, word_bits - 39},
                         {word_bits - 10, word_bits - 61, word_bits - 55, word_bits - 8},
                         {word_bits - 2, word_bits - 15, word_bits - 25, word_bits - 20},
                         {word_bits - 44, word_bits - 43, word_bits - 21, word_bits - 14}}};
#pragma GCC diagnostic pop

                    static inline void permute(state_type &A) {

                        register __m256i A0 asm("ymm0") = _mm256_set_epi64x(A[0], A[0], A[0], A[0]);
                        register __m256i A1 asm("ymm1") = _mm256_set_epi64x(A[4], A[3], A[2], A[1]);
                        register __m256i A2 asm("ymm2") = _mm256_set_epi64x(A[15], A[5], A[20], A[10]);
                        register __m256i A3 asm("ymm3") = _mm256_set_epi64x(A[14], A[23], A[7], A[16]);
                        register __m256i A4 asm("ymm4") = _mm256_set_epi64x(A[19], A[8], A[22], A[11]);
                        register __m256i A5 asm("ymm5") = _mm256_set_epi64x(A[9], A[13], A[17], A[21]);
                        register __m256i A6 asm("ymm6") = _mm256_set_epi64x(A[24], A[18], A[12], A[6]);

                        __asm__ volatile(
                            "lea %[rho_l], %%r8;"
                            "lea %[rho_r], %%r9;"
                            "lea %[c], %%r10;"
                            "movq %[rounds], %%rbx;"

                            "1:"
                            // Calculate C
                            "vpshufd	$0b01001110,%%ymm2,%%ymm13;"
                            "vpxor		%%ymm3,%%ymm5,%%ymm12;"
                            "vpxor		%%ymm6,%%ymm4,%%ymm9;"
                            "vpxor		%%ymm1,%%ymm12,%%ymm12;"
                            "vpxor		%%ymm9,%%ymm12,%%ymm12;"

                            "vpermq		$0b10010011,%%ymm12,%%ymm11;"
                            "vpxor		%%ymm2,%%ymm13,%%ymm13;"
                            "vpermq		$0b01001110,%%ymm13,%%ymm7;"

                            // Calculate rotl<1>(C)
                            "vpsrlq		$63,%%ymm12,%%ymm8;"
                            "vpaddq		%%ymm12,%%ymm12,%%ymm9;"
                            "vpor		%%ymm9,%%ymm8,%%ymm8;"

                            // Calculate Dzero
                            "vpermq		$0b00111001,%%ymm8,%%ymm15;"
                            "vpxor		%%ymm11,%%ymm8,%%ymm14;"
                            "vpermq		$0b00000000,%%ymm14,%%ymm14;"

                            // Calculate Czero
                            "vpxor		%%ymm0,%%ymm13,%%ymm13;"
                            "vpxor		%%ymm7,%%ymm13,%%ymm13;"

                            // Calculate rotl<1>(Czero)
                            "vpsrlq		$63,%%ymm13,%%ymm7;"
                            "vpaddq		%%ymm13,%%ymm13,%%ymm8;"
                            "vpor		%%ymm7,%%ymm8,%%ymm8;"

                            // Calculate D
                            "vpblendd	$0b11000000,%%ymm8,%%ymm15,%%ymm15;"
                            "vpblendd	$0b00000011,%%ymm13,%%ymm11,%%ymm11;"
                            "vpxor		%%ymm11,%%ymm15,%%ymm15;"

                            // xor all with D
                            "vpxor		%%ymm14,%%ymm0,%%ymm0;"
                            "vpxor		%%ymm15,%%ymm1,%%ymm1;"
                            "vpxor		%%ymm14,%%ymm2,%%ymm2;"
                            "vpxor		%%ymm15,%%ymm3,%%ymm3;"
                            "vpxor		%%ymm15,%%ymm4,%%ymm4;"
                            "vpxor		%%ymm15,%%ymm5,%%ymm5;"
                            "vpxor		%%ymm15,%%ymm6,%%ymm6;"

                            // Start circle shift res = ((x << rho_l) | (x >> rho_r))
                            "vpsllvq	(%%r8),%%ymm2,%%ymm10;"
                            "vpsrlvq	(%%r9),%%ymm2,%%ymm2;"
                            "vpor		%%ymm10,%%ymm2,%%ymm2;"

                            "vpsllvq	1*32(%%r8),%%ymm1,%%ymm10;"
                            "vpsrlvq	1*32(%%r9),%%ymm1,%%ymm9;"
                            "vpor		%%ymm10,%%ymm9,%%ymm9;"

                            "vpsllvq	2*32(%%r8),%%ymm3,%%ymm10;"
                            "vpsrlvq	2*32(%%r9),%%ymm3,%%ymm3;"
                            "vpor		%%ymm10,%%ymm3,%%ymm3;"

                            "vpsllvq	3*32(%%r8),%%ymm4,%%ymm10;"
                            "vpsrlvq	3*32(%%r9),%%ymm4,%%ymm4;"
                            "vpor		%%ymm10,%%ymm4,%%ymm4;"

                            "vpsllvq	4*32(%%r8),%%ymm5,%%ymm10;"
                            "vpsrlvq	4*32(%%r9),%%ymm5,%%ymm5;"
                            "vpor		%%ymm10,%%ymm5,%%ymm5;"

                            "vpsllvq	5*32(%%r8),%%ymm6,%%ymm10;"
                            "vpsrlvq	5*32(%%r9),%%ymm6,%%ymm8;"
                            "vpor		%%ymm10,%%ymm8,%%ymm8;"

                            // We already have new A1, A2, but still need new A3, A4, A5, A6
                            "vpermq		$0b10001101,%%ymm2,%%ymm10;"
                            "vpermq		$0b10001101,%%ymm3,%%ymm11;"
                            "vpermq		$0b00011011,%%ymm4,%%ymm12;"
                            "vpermq		$0b01110010,%%ymm5,%%ymm13;"

                            // Start calculating B, return A to form in the beginning
                            "vpsrldq	$8,%%ymm8,%%ymm14;"
                            "vpandn		%%ymm14,%%ymm8,%%ymm7;"

                            "vpblendd	$0b00001100,%%ymm9,%%ymm11,%%ymm15;"
                            "vpblendd	$0b00110000,%%ymm12,%%ymm15,%%ymm15;"
                            "vpblendd	$0b11000000,%%ymm13,%%ymm15,%%ymm15;"

                            "vpblendd	$0b00001100,%%ymm10,%%ymm9,%%ymm14;"
                            "vpblendd	$0b00110000,%%ymm13,%%ymm14,%%ymm14;"
                            "vpblendd	$0b11000000,%%ymm11,%%ymm14,%%ymm14;"

                            "vpblendd	$0b00001100,%%ymm13,%%ymm9,%%ymm3;"
                            "vpblendd	$0b00110000,%%ymm11,%%ymm3,%%ymm3;"
                            "vpblendd	$0b11000000,%%ymm12,%%ymm3,%%ymm3;"

                            "vpblendd	$0b00001100,%%ymm11,%%ymm10,%%ymm5;"
                            "vpblendd	$0b00110000,%%ymm9,%%ymm5,%%ymm5;"
                            "vpblendd	$0b11000000,%%ymm13,%%ymm5,%%ymm5;"

                            "vpandn		%%ymm14,%%ymm5,%%ymm5;"
                            "vpandn		%%ymm15,%%ymm3,%%ymm3;"

                            "vpblendd	$0b00001100,%%ymm9,%%ymm12,%%ymm6;"
                            "vpblendd	$0b00110000,%%ymm10,%%ymm6,%%ymm6;"
                            "vpblendd	$0b11000000,%%ymm11,%%ymm6,%%ymm6;"

                            "vpblendd	$0b00001100,%%ymm12,%%ymm10,%%ymm15;"
                            "vpblendd	$0b00110000,%%ymm11,%%ymm15,%%ymm15;"
                            "vpblendd	$0b11000000,%%ymm9,%%ymm15,%%ymm15;"

                            "vpandn		%%ymm15,%%ymm6,%%ymm6;"
                            "vpxor		%%ymm13,%%ymm6,%%ymm6;"

                            "vpermq	    $0b00011110,%%ymm8,%%ymm4;"
                            "vpblendd	$0b00110000,%%ymm0,%%ymm4,%%ymm15;"
                            "vpermq	    $0b00111001,%%ymm8,%%ymm1;"
                            "vpblendd	$0b11000000,%%ymm0,%%ymm1,%%ymm1;"
                            "vpandn	    %%ymm15,%%ymm1,%%ymm1;"

                            "vpblendd	$0b00001100,%%ymm12,%%ymm11,%%ymm2;"
                            "vpblendd	$0b00110000,%%ymm13,%%ymm2,%%ymm2;"
                            "vpblendd	$0b11000000,%%ymm10,%%ymm2,%%ymm2;"

                            "vpblendd	$0b00001100,%%ymm11,%%ymm13,%%ymm14;"
                            "vpblendd	$0b00110000,%%ymm10,%%ymm14,%%ymm14;"
                            "vpblendd	$0b11000000,%%ymm12,%%ymm14,%%ymm14;"

                            "vpandn		%%ymm14,%%ymm2,%%ymm2;"

                            "vpblendd	$0b00001100,%%ymm10,%%ymm13,%%ymm4;"
                            "vpblendd	$0b00110000,%%ymm12,%%ymm4,%%ymm4;"
                            "vpblendd	$0b11000000,%%ymm9,%%ymm4,%%ymm4;"
                            "vpblendd	$0b00001100,%%ymm13,%%ymm12,%%ymm14;"
                            "vpblendd	$0b00110000,%%ymm9,%%ymm14,%%ymm14;"
                            "vpblendd	$0b11000000,%%ymm10,%%ymm14,%%ymm14;"

                            "vpandn		%%ymm14,%%ymm4,%%ymm4;"

                            "vpxor		%%ymm9,%%ymm2,%%ymm2;"
                            "vpxor		%%ymm10,%%ymm3,%%ymm3;"
                            "vpxor		%%ymm12,%%ymm5,%%ymm5;"

                            "vpermq		$0b00000000,%%ymm7,%%ymm7;"
                            "vpermq		$0b00011011,%%ymm3,%%ymm3;"
                            "vpermq		$0b10001101,%%ymm5,%%ymm5;"
                            "vpermq		$0b01110010,%%ymm6,%%ymm6;"

                            "vpxor		%%ymm7,%%ymm0,%%ymm0;"
                            "vpxor		%%ymm8,%%ymm1,%%ymm1;"
                            "vpxor		%%ymm11,%%ymm4,%%ymm4;"

                            // Calculate A0 ^ c
                            "vpxor (%%r10), %%ymm0, %%ymm0;"
                            "lea 32(%%r10), %%r10;"

                            "dec %%rbx;"
                            "jnz 1b;"

                            : [A0] "+v"(A0), [A1] "+v"(A1), [A2] "+v"(A2), [A3] "+v"(A3), [A4] "+v"(A4), [A5] "+v"(A5),
                              [A6] "+v"(A6)
                            : [rounds] "r"(round_constants_size), [rho_l] "o"(rho_l), [rho_r] "o"(rho_r),
                              [c] "o"(round_constants_v)
                            : "cc", "memory",                              // it's A0, A1, A2, A3, A4, A5, A6
                              "ymm7", "ymm8", "ymm9", "ymm10", "ymm11",    // tmp variables
                              "ymm12", "ymm13", "ymm14", "ymm15",          // C, Czero, D, Dzero
                              "rbx"                                        // Circle
                        );

                        A[0] = A0[0];
                        A[1] = A1[0];
                        A[2] = A1[1];
                        A[3] = A1[2];
                        A[4] = A1[3];
                        A[5] = A2[2];
                        A[6] = A6[0];
                        A[7] = A3[1];
                        A[8] = A4[2];
                        A[9] = A5[3];
                        A[10] = A2[0];
                        A[11] = A4[0];
                        A[12] = A6[1];
                        A[13] = A5[2];
                        A[14] = A3[3];
                        A[15] = A2[3];
                        A[16] = A3[0];
                        A[17] = A5[1];
                        A[18] = A6[2];
                        A[19] = A4[3];
                        A[20] = A2[1];
                        A[21] = A5[0];
                        A[22] = A4[1];
                        A[23] = A3[2];
                        A[24] = A6[3];
                    }
                };

                template<typename PolicyType>
                constexpr typename keccak_1600_avx2_impl<PolicyType>::round_constants_type const
                    keccak_1600_avx2_impl<PolicyType>::round_constants;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_AVX2_IMPL_HPP
