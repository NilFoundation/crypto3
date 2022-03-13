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

#ifndef CRYPTO3_KECCAK_AVX512_IMPL_HPP
#define CRYPTO3_KECCAK_AVX512_IMPL_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>
#include <nil/crypto3/hash/detail/keccak/keccak_impl.hpp>
#include <immintrin.h>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename PolicyType>
                struct keccak_1600_avx512_impl {
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

                    constexpr static const std::array<__m512i, 5> rho_0 = {{{0, 1, 62, 28, 27, 0, 0, 0},
                                                                            {36, 44, 6, 55, 20, 0, 0, 0},
                                                                            {3, 10, 43, 25, 39, 0, 0, 0},
                                                                            {41, 45, 15, 21, 8, 0, 0, 0},
                                                                            {18, 2, 61, 56, 14, 0, 0, 0}}};

                    constexpr static const std::array<__m512i, 5> rho_1 = {{{0, 44, 43, 21, 14, 0, 0, 0},
                                                                            {18, 1, 6, 25, 8, 0, 0, 0},
                                                                            {41, 2, 62, 55, 39, 0, 0, 0},
                                                                            {3, 45, 61, 28, 20, 0, 0, 0},
                                                                            {36, 10, 15, 56, 27, 0, 0, 0}}};

                    constexpr static const std::array<__m512i, 5> pi0_perm = {{{0, 3, 1, 4, 2, 5, 6, 7},
                                                                               {1, 4, 2, 0, 3, 5, 6, 7},
                                                                               {2, 0, 3, 1, 4, 5, 6, 7},
                                                                               {3, 1, 4, 2, 0, 5, 6, 7},
                                                                               {4, 2, 0, 3, 1, 5, 6, 7}}};

                    constexpr static const std::array<__m512i, 5> theta_perm = {{{0, 1, 2, 3, 4, 5, 6, 7},
                                                                                 {4, 0, 1, 2, 3, 5, 6, 7},
                                                                                 {3, 4, 0, 1, 2, 5, 6, 7},
                                                                                 {2, 3, 4, 0, 1, 5, 6, 7},
                                                                                 {1, 2, 3, 4, 0, 5, 6, 7}}};

                    static inline void permute(state_type &A) {

                        register __m512i A0 asm("zmm0") = _mm512_set_epi64(A[4], A[3], A[2], A[1], A[0], 0, 0, 0);
                        register __m512i A1 asm("zmm1") = _mm512_set_epi64(A[9], A[8], A[7], A[6], A[5], 0, 0, 0);
                        register __m512i A2 asm("zmm2") = _mm512_set_epi64(A[14], A[13], A[12], A[11], A[10], 0, 0, 0);
                        register __m512i A3 asm("zmm3") = _mm512_set_epi64(A[19], A[18], A[17], A[16], A[15], 0, 0, 0);
                        register __m512i A4 asm("zmm4") = _mm512_set_epi64(A[24], A[23], A[22], A[21], A[20], 0, 0, 0);

                        register __m512i theta1 asm("zmm13") = theta_perm[1];
                        register __m512i theta2 asm("zmm14") = theta_perm[2];
                        register __m512i theta3 asm("zmm15") = theta_perm[3];
                        register __m512i theta4 asm("zmm16") = theta_perm[4];

                        register __m512i pi0 asm("zmm17") = pi0_perm[0];
                        register __m512i pi1 asm("zmm18") = pi0_perm[1];
                        register __m512i pi2 asm("zmm19") = pi0_perm[2];
                        register __m512i pi3 asm("zmm20") = pi0_perm[3];
                        register __m512i pi4 asm("zmm21") = pi0_perm[4];

                        register __m512i rho00 asm("zmm22") = rho_0[0];
                        register __m512i rho01 asm("zmm23") = rho_0[1];
                        register __m512i rho02 asm("zmm24") = rho_0[2];
                        register __m512i rho03 asm("zmm25") = rho_0[3];
                        register __m512i rho04 asm("zmm26") = rho_0[4];

                        register __m512i rho10 asm("zmm27") = rho_1[0];
                        register __m512i rho11 asm("zmm28") = rho_1[1];
                        register __m512i rho12 asm("zmm29") = rho_1[2];
                        register __m512i rho13 asm("zmm30") = rho_1[3];
                        register __m512i rho14 asm("zmm31") = rho_1[4];

                        __asm__ volatile(
                            "lea %[c], %%r10\n"
                            "mov $12,%eax\n"
                            "1:"
                            // Calculate first round_constants
                            "vmovdqa64	%%zmm0,%%zmm5\n"
                            "vpternlogq	$0x96,%%zmm2,%%zmm1,%%zmm0\n"
                            "vpternlogq	$0x96,%%zmm4,%%zmm3,%%zmm0\n"
                            "vprolq		$1,%%zmm0,%%zmm6\n"
                            "vpermq		%%zmm0,%%zmm13,%%zmm0\n"
                            "vpermq		%%zmm6,%%zmm16,%%zmm6\n"
                            "vpternlogq	$0x96,%%zmm0,%%zmm6,%%zmm5\n"
                            "vpternlogq	$0x96,%%zmm0,%%zmm6,%%zmm1\n"
                            "vpternlogq	$0x96,%%zmm0,%%zmm6,%%zmm2\n"
                            "vpternlogq	$0x96,%%zmm0,%%zmm6,%%zmm3\n"
                            "vpternlogq	$0x96,%%zmm0,%%zmm6,%%zmm4\n"
                            // Using rh0
                            "vprolvq		%%zmm22,%%zmm5,%%zmm0\n"
                            "vprolvq		%%zmm23,%%zmm1,%%zmm1\n"
                            "vprolvq		%%zmm24,%%zmm2,%%zmm2\n"
                            "vprolvq		%%zmm25,%%zmm3,%%zmm3\n"
                            "vprolvq		%%zmm26,%%zmm4,%%zmm4\n"
                            // Calculate C,D
                            "vpermq		%%zmm0,%%zmm17,%%zmm0\n"
                            "vpermq		%%zmm1,%%zmm18,%%zmm1\n"
                            "vpermq		%%zmm2,%%zmm19,%%zmm2\n"
                            "vpermq		%%zmm3,%%zmm20,%%zmm3\n"
                            "vpermq		%%zmm4,%%zmm21,%%zmm4\n"

                            "vmovdqa64	%%zmm0,%%zmm5\n"
                            "vmovdqa64	%%zmm1,%%zmm6\n"
                            "vpternlogq	$0xD2,%%zmm2,%%zmm1,%%zmm0\n"
                            "vpternlogq	$0xD2,%%zmm3,%%zmm2,%%zmm1\n"
                            "vpternlogq	$0xD2,%%zmm4,%%zmm3,%%zmm2\n"
                            "vpternlogq	$0xD2,%%zmm5,%%zmm4,%%zmm3\n"
                            "vpternlogq	$0xD2,%%zmm6,%%zmm5,%%zmm4\n"
                            // Xor on [c]
                            "vpxorq		(%r10),%%zmm0,%%zmm0{%%k1}"
                            "lea		16(%r10),%r10\n"
                            // Prepare for next round
                            "vpblendmq	%%zmm2,%%zmm1,%%zmm6{%%k2}\n"
                            "vpblendmq	%%zmm3,%%zmm2,%%zmm7{%%k2}\n"
                            "vpblendmq	%%zmm4,%%zmm3,%%zmm8{%%k2}\n"
                            "vpblendmq	%%zmm1,%%zmm0,%%zmm5{%%k2}\n"
                            "vpblendmq	%%zmm0,%%zmm4,%%zmm9{%%k2}\n"
                            "vpblendmq	%%zmm3,%%zmm6,%%zmm6{%%k3}\n"
                            "vpblendmq	%%zmm4,%%zmm7,%%zmm7{%%k3}\n"
                            "vpblendmq	%%zmm2,%%zmm5,%%zmm5{%%k3}\n"
                            "vpblendmq	%%zmm0,%%zmm8,%%zmm8{%%k3}\n"
                            "vpblendmq	%%zmm1,%%zmm9,%%zmm9{%%k3}\n"
                            "vpblendmq	%%zmm4,%%zmm6,%%zmm6{%%k4}\n"
                            "vpblendmq	%%zmm3,%%zmm5,%%zmm5{%%k4}\n"
                            "vpblendmq	%%zmm0,%%zmm7,%%zmm7{%%k4}\n"
                            "vpblendmq	%%zmm1,%%zmm8,%%zmm8{%%k4}\n"
                            "vpblendmq	%%zmm2,%%zmm9,%%zmm9{%%k4}\n"
                            "vpblendmq	%%zmm4,%%zmm5,%%zmm5{%%k5}\n"
                            "vpblendmq	%%zmm0,%%zmm6,%%zmm6{%%k5}\n"
                            "vpblendmq	%%zmm1,%%zmm7,%%zmm7{%%k5}\n"
                            "vpblendmq	%%zmm2,%%zmm8,%%zmm8{%%k5}\n"
                            "vpblendmq	%%zmm3,%%zmm9,%%zmm9{%%k5}\n"

                            "vpermq		%%zmm6,%%zmm13,%%zmm1\n"
                            "vpermq		%%zmm7,%%zmm14,%%zmm2\n"
                            "vpermq		%%zmm8,%%zmm15,%%zmm3\n"
                            "vpermq		%%zmm9,%%zmm16,%%zmm4\n"
                            // Round where we xor with 8[c]
                            "vmovdqa64	$%%zmm5,%%zmm0\n"
                            "vpternlogq	$0x96,%%zmm2,%%zmm1,%%zmm5\n"
                            "vpternlogq	$0x96,%%zmm4,%%zmm3,%%zmm5\n"
                            "vprolq		$1,%%zmm5,%%zmm6\n"
                            "vpermq		%%zmm5,%%zmm13,%%zmm5\n"
                            "vpermq		%%zmm6,%%zmm16,%%zmm6\n"
                            "vpternlogq	$0x96,%%zmm5,%%zmm6,%%zmm0\n"
                            "vpternlogq	$0x96,%%zmm5,%%zmm6,%%zmm3\n"
                            "vpternlogq	$0x96,%%zmm5,%%zmm6,%%zmm1\n"
                            "vpternlogq	$0x96,%%zmm5,%%zmm6,%%zmm4\n"
                            "vpternlogq	$0x96,%%zmm5,%%zmm6,%%zmm2\n"
                            // Same rh0
                            "vprolvq	%%zmm27,%%zmm0,%%zmm0\n"
                            "vprolvq	%%zmm30,%%zmm3,%%zmm6\n"
                            "vprolvq	%%zmm28,%%zmm1,%%zmm7\n"
                            "vprolvq	%%zmm31,%%zmm4,%%zmm8\n"
                            "vprolvq	%%zmm29,%%zmm2,%%zmm9\n"
                            "vpermq		%%zmm0,%%zmm16,%%zmm10\n"
                            "vpermq		%%zmm0,%%zmm15,%%zmm11\n"
                            // Xor on 8[c]
                            "vpxorq		-8(%r10),%%zmm0,%%zmm0{%%k1}\n"

                            "vpermq		%%zmm6,%%zmm14,%%zmm1\n"
                            "vpermq		%%zmm7,%%zmm16,%%zmm2\n"
                            "vpermq		%%zmm8,%%zmm13,%%zmm3\n"
                            "vpermq		%%zmm9,%%zmm15,%%zmm4\n"

                            "vpternlogq	$0xD2,%%zmm11,%%zmm10,%%zmm0\n"
                            "vpermq		%%zmm6,%%zmm13,%%zmm12\n"
                            "vpternlogq	$0xD2,%%zmm6,%%zmm12,%%zmm1\n"
                            "vpermq		%%zmm7,%%zmm15,%%zmm5\n"
                            "vpermq		%%zmm7,%%zmm14,%%zmm7\n"
                            "vpternlogq	$0xD2,%%zmm7,%%zmm5,%%zmm2\n"
                            "vpermq		%%zmm8,%%zmm16,%%zmm6\n"
                            "vpternlogq	$0xD2,%%zmm6,%%zmm8,%%zmm3\n"
                            "vpermq		%%zmm9,%%zmm14,%%zmm5\n"
                            "vpermq		%%zmm9,%%zmm13,%%zmm9\n"
                            "vpternlogq	$0xD2,%%zmm9,%%zmm5,%%zmm4\n"
                            "dec		%eax\n"
                            "jnz		1b\n"

                            : "+v"(A0), "+v"(A1), "+v"(A2), "+v"(A3), "+v"(A4), "+v"(theta1), "+v"(theta2),
                              "+v"(theta3), "+v"(theta4), "+v"(pi0), "+v"(pi1), "+v"(pi2), "+x"(pi3), "+v"(pi4),
                              "+v"(rho00), "+v"(rho01), "+v"(rho02), "+v"(rho03), "+v"(rho04), "+v"(rho10), "+v"(rho11),
                              "+v"(rho12), "+v"(rho13), "+v"(rho14)
                            : [c] "o"(round_constants)
                            : "cc", "memory", "%eax", "%r10", "%zmm5", "%zmm6", "%zmm7", "%zmm8", "%zmm9", "%zmm10",
                              "%zmm11", "%zmm12"    // T

                        );

                        A[0] = A0[0];
                        A[1] = A0[1];
                        A[2] = A0[2];
                        A[3] = A0[3];
                        A[4] = A0[4];
                        A[5] = A1[0];
                        A[6] = A1[1];
                        A[7] = A1[2];
                        A[8] = A1[3];
                        A[9] = A1[4];
                        A[10] = A2[0];
                        A[11] = A2[1];
                        A[12] = A2[2];
                        A[13] = A2[3];
                        A[14] = A2[4];
                        A[15] = A3[0];
                        A[16] = A3[1];
                        A[17] = A3[2];
                        A[18] = A3[3];
                        A[19] = A3[4];
                        A[20] = A4[0];
                        A[21] = A4[1];
                        A[22] = A4[2];
                        A[23] = A4[3];
                        A[24] = A4[4];
                    }
                };

                template<typename PolicyType>
                constexpr typename keccak_1600_avx512_impl<PolicyType>::round_constants_type const
                    keccak_1600_avx512_impl<PolicyType>::round_constants;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_AVX512_IMPL_HPP
