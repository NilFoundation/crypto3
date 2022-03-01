//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef CRYPTO3_KECCAK_ARMV8_IMPL_HPP
#define CRYPTO3_KECCAK_ARMV8_IMPL_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>
#include <nil/crypto3/hash/detail/keccak/keccak_impl.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename PolicyType>
                struct keccak_1600_armv8_impl {
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

                    static inline void permute(state_type &A) {
                        for (typename round_constants_type::value_type c : round_constants) {
                            std::array<word_type, 10> C, D;
                            std::array<word_type, 25> B;

                            register word_type A0 asm('x0') = A[0];
                            register word_type A1 asm('x1') = A[1];
                            register word_type A2 asm('x2') = A[2];
                            register word_type A3 asm('x3') = A[3];
                            register word_type A4 asm('x4') = A[4];
                            register word_type A5 asm('x5') = A[5];
                            register word_type A6 asm('x6') = A[6];
                            register word_type A7 asm('x7') = A[7];
                            register word_type A8 asm('x8') = A[8];
                            register word_type A9 asm('x9') = A[9];
                            register word_type A10 asm('x10') = A[10];
                            register word_type A11 asm('x11') = A[11];
                            register word_type A12 asm('x12') = A[12];
                            register word_type A13 asm('x13') = A[13];
                            register word_type A14 asm('x14') = A[14];
                            register word_type A15 asm('x15') = A[15];
                            register word_type A16 asm('x16') = A[16];
                            register word_type A17 asm('x17') = A[17];
                            register word_type A18 asm('x18') = A[18];
                            register word_type A19 asm('x19') = A[19];
                            register word_type A20 asm('x20') = A[20];
                            register word_type A21 asm('x21') = A[21];
                            register word_type A22 asm('x22') = A[22];
                            register word_type A23 asm('x23') = A[23];
                            register word_type A24 asm('x24') = A[24];

                            __asm__(
                                "mov [%[C], #0], %x0\n"
                                "eor [%[C], #0], [%[C], #0], %x5\n"
                                "eor [%[C], #0], [%[C], #0], %x10\n"
                                "eor [%[C], #0], [%[C], #0], %x15\n"
                                "eor [%[C], #0], [%[C], #0], %x20\n"

                                "mov [%[C], #8], %x1\n"
                                "eor [%[C], #8],[%[C], #8], %x6\n"
                                "eor [%[C], #8],[%[C], #8], %x11\n"
                                "eor [%[C], #8],[%[C], #8], %x16\n"
                                "eor [%[C], #8],[%[C], #8], %x21\n"

                                "mov [%[C], #16], %x2\n"
                                "eor [%[C], #16],[%[C], #16], %x7\n"
                                "eor [%[C], #16],[%[C], #16], %x12\n"
                                "eor [%[C], #16],[%[C], #16], %x17\n"
                                "eor [%[C], #16],[%[C], #16], %x22\n"

                                "mov [%[C], #24], %x3\n"
                                "eor [%[C], #24],[%[C], #24], %x8\n"
                                "eor [%[C], #24],[%[C], #24], %x13\n"
                                "eor [%[C], #24],[%[C], #24], %x18\n"
                                "eor [%[C], #24],[%[C], #24], %x23\n"

                                "mov [%[C], #32], %x4\n"
                                "eor [%[C], #32],[%[C], #32], %x9\n"
                                "eor [%[C], #32],[%[C], #32], %x14\n"
                                "eor [%[C], #32],[%[C], #32], %x19\n"
                                "eor [%[C], #32],[%[C], #32], %x24\n"
                                // Calculate D
                                "mov %x25, [%[C], #0]\n"
                                "mov %x26, [%[C], #24]\n"
                                "mov [%[D], #0], %x25\n"
                                "ror [%[D], #0], [%[D], #0], #63\n"
                                "eor [%[D], #0], [%[D], #0], %x26\n"

                                "mov %x25, [%[C], #8]\n"
                                "mov %x26, [%[C], #32]\n"
                                "mov [%[D], #8], %x25\n"
                                "ror [%[D], #8],[%[D], #8], #63\n"
                                "eor [%[D], #8],[%[D], #8], %x26\n"

                                "mov %x25, [%[C], #16]\n"
                                "mov %x26, [%[C], #0]\n"
                                "mov [%[D], #16], %x25\n"
                                "ror [%[D], #16],[%[D], #16], #63\n"
                                "eor [%[D], #16],[%[D], #16], %x26\n"

                                "mov %x25, [%[C], #24]\n"
                                "mov %x26, [%[C], #8]\n"
                                "mov [%[D], #24], %x25\n"
                                "ror [%[D], #24],[%[D], #24], #63\n"
                                "eor [%[D], #24],[%[D], #24], %x26\n"

                                "mov %x25, [%[C], #32]\n"
                                "mov %x26, [%[C], #16]\n"
                                "mov [%[D], #32], %x25\n"
                                "ror [%[D], #32],[%[D], #32], #63\n"
                                "eor [%[D], #32],[%[D], #32], %x26\n"
                                //Calculate B
                                "mov %x25, [%[D], #8]\n"
                                "ror %x0, %x0, #64\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #0], %x25\n"

                                "mov %x25, [%[D], #16]\n"
                                "ror %x1, %x1, #63\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #80], %x25\n"

                                "mov %x25, [%[D], #24]\n"
                                "ror %x2, %x2, #2\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #160], %x25\n"

                                "mov %x25, [%[D], #32]\n"
                                "ror %x3, %x3, #36\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #40], %x25\n"

                                "mov %x25, [%[D], #0]\n"
                                "ror %x4, %x4, #37\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #120], %x25\n"

                                "mov %x25, [%[D], #8]\n"
                                "ror %x5, %x5, #28\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #128], %x25\n"

                                "mov %x25, [%[D], #16]\n"
                                "ror %x6, %x6, #20\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #8], %x25\n"

                                "mov %x25, [%[D], #24]\n"
                                "ror %x7, %x7, #58\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #88], %x25\n"

                                "mov %x25, [%[D], #32]\n"
                                "ror %x8, %x8, #9\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #168], %x25\n"

                                "mov %x25, [%[D], #0]\n"
                                "ror %x9, %x9, #44\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #48], %x25\n"

                                "mov %x25, [%[D], #8]\n"
                                "ror %x10, %x10, #61\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #56], %x25\n"

                                "mov %x25, [%[D], #16]\n"
                                "ror %x11, %x11, #45\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #136], %x25\n"

                                "mov %x25, [%[D], #24]\n"
                                "ror %x12, %x12, #21\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #16], %x25\n"

                                "mov %x25, [%[D], #32]\n"
                                "ror %x13, %x13, #39\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #96], %x25\n"

                                "mov %x25, [%[D], #0]\n"
                                "ror %x14, %x14, #25\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #176], %x25\n"

                                "mov %x25, [%[D], #8]\n"
                                "ror %x15, %x15, #23\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #184], %x25\n"

                                "mov %x25, [%[D], #16]\n"
                                "ror %x16, %x16, #19\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #64], %x25\n"

                                "mov %x25, [%[D], #24]\n"
                                "ror %x17, %x17, #49\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #144], %x25\n"

                                "mov %x25, [%[D], #32]\n"
                                "ror %x18, %x18, #43\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #24], %x25\n"

                                "mov %x25, [%[D], #0]\n"
                                "ror %x19, %x19, #64 - #8\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #104], %x25\n"

                                "mov %x25, [%[D], #8]\n"
                                "ror %x20, %x20, #64 - #18\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #112], %x25\n"

                                "mov %x25, [%[D], #16]\n"
                                "ror %x21, %x21, #64 - #2\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #192], %x25\n"

                                "mov %x25, [%[D], #24]\n"
                                "ror %x22, %x22, #64 - #61\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #72], %x25\n"

                                "mov %x25, [%[D], #32]\n"
                                "ror %x23, %x23, #64 - #56\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #152], %x25\n"

                                "mov %x25, [%[D], #0]\n"
                                "ror %x24,  %x24, #64 - #14\n"
                                "eor %x25, %x25, %x0\n"
                                "mov [%[B], #32], %x25\n"
                                // Start calculate ending A
                                "mov %x0, [%[B], #0]\n"
                                "mov %x1, [%[B], #8]\n"
                                "mov %x2, [%[B], #16]\n"
                                "mov %x3, [%[B], #24]\n"
                                "mov %x4, [%[B], #32]\n"
                                "mov %x5, [%[B], #40]\n"
                                "mov %x6, [%[B], #48]\n"
                                "mov %x7, [%[B], #56]\n"
                                "mov %x8, [%[B], #64]\n"
                                "mov %x9, [%[B], #72]\n"
                                "mov %x10, [%[B], #80]\n"
                                "mov %x11, [%[B], #88]\n"
                                "mov %x12, [%[B], #96]\n"
                                "mov %x13, [%[B], #104]\n"
                                "mov %x14, [%[B], #112]\n"
                                "mov %x15, [%[B], #120]\n"
                                "mov %x16, [%[B], #128]\n"
                                "mov %x17, [%[B], #136]\n"
                                "mov %x18, [%[B], #144]\n"
                                "mov %x19, [%[B], #152]\n"
                                "mov %x20, [%[B], #160]\n"
                                "mov %x21, [%[B], #168]\n"
                                "mov %x22, [%[B], #176]\n"
                                "mov %x23, [%[B], #184]\n"
                                "mov %x24, [%[B], #192]\n"
                                // End left part
                                "mov %x25, [%[B], #8]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #16]\n"
                                "eor %x0, %x0, %x25\n"

                                "mov %x25, [%[B], #16]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #24]\n"
                                "eor %x1, %x1, %x25\n"

                                "mov %x25, [%[B], #24]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #32]\n"
                                "eor %x2, %x2, %x25\n"

                                "mov %x25, [%[B], #32]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #0]\n"
                                "eor %x3, %x3, %x25\n"

                                "mov %x25, [%[B], #0]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #8]\n"
                                "eor %x4, %x4, %x25\n"
                                //a5
                                "mov %x25, [%[B], #48]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #56]\n"
                                "eor %x5, %x5, %x25\n"

                                "mov %x25, [%[B], #56]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #64]\n"
                                "eor %x6, %x6, %x25\n"

                                "mov %x25, [%[B], #64]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #72]\n"
                                "eor %x7, %x7, %x25\n"

                                "mov %x25, [%[B], #72]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #40]\n"
                                "eor %x8, %x8, %x25\n"

                                "mov %x25, [%[B], #40]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #48]\n"
                                "eor %x9, %x9, %x25\n"
                                //a10
                                "mov %x25, [%[B], #88]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #96]\n"
                                "eor %x10, %x10, %x25\n"

                                "mov %x25, [%[B], #96]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #104]\n"
                                "eor %x11, %x11, %x25\n"

                                "mov %x25, [%[B], #104]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #112]\n"
                                "eor %x12, %x12, %x25\n"

                                "mov %x25, [%[B], #112]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #80]\n"
                                "eor %x13, %x13, %x25\n"

                                "mov %x25, [%[B], #80]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #88]\n"
                                "eor %x14, %x14, %x25\n"
                                //a15
                                "mov %x25, [%[B], #128]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #136]\n"
                                "eor %x15, %x15, %x25\n"

                                "mov %x25, [%[B], #136]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #144]\n"
                                "eor %x16, %x16, %x25\n"

                                "mov %x25, [%[B], #144]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #152]\n"
                                "eor %x17, %x17, %x25\n"

                                "mov %x25, [%[B], #152]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #120]\n"
                                "eor %x18, %x18, %x25\n"

                                "mov %x25, [%[B], #120]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #128]\n"
                                "eor %x19, %x19, %x25\n"
                                //a20
                                "mov %x25, [%[B], #168]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #176]\n"
                                "eor %x20, %x20, %x25\n"

                                "mov %x25, [%[B], #176]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #184]\n"
                                "eor %x21, %x21, %x25\n"

                                "mov %x25, [%[B], #184]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #192]\n"
                                "eor %x22, %x22, %x25\n"

                                "mov %x25, [%[B], #192]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #160]\n"
                                "eor %x23, %x23, %x25\n"

                                "mov %x25, [%[B], #160]\n"
                                "mvn %x25, %x25\n"
                                "and %x25, %x25, [%[B], #168]\n"
                                "eor %x24, %x24, %x25\n"

                                :
                                : [D] "r" (D.begin()), [C] "r"(C.begin()), [B] "r"(B.begin())
                                : "cc", "memory", "%x25", "%x26"
                            );
                            A[0] = A0 ^ c;
                            A[1] = A1;
                            A[2] = A2;
                            A[3] = A3;
                            A[4] = A4;
                            A[5] = A5;
                            A[6] = A6;
                            A[7] = A7;
                            A[8] = A8;
                            A[9] = A9;
                            A[10] = A10;
                            A[11] = A11;
                            A[12] = A12;
                            A[13] = A13;
                            A[14] = A14;
                            A[15] = A15;
                            A[16] = A16;
                            A[17] = A17;
                            A[18] = A18;
                            A[19] = A19;
                            A[20] = A20;
                            A[21] = A21;
                            A[22] = A22;
                            A[23] = A23;
                            A[24] = A24;
                        }
//                        __asm__(
//                            "1:\n"
//                            "eor	%x26,[%[A], #0],[%[A], #40]\n"
//                            "stp	[%[A], #32],[%[A], #72],[sp,#0]\n"
//                            "eor	%x27,[%[A], #8],[%[A], #48]"
//                            "eor	%x28,[%[A], #16]],[%[A], #56]\n"
//                            "eor	%x29,[%[A], #24]],[%[A], #64]\n"
//
//                            "eor	%x30,[%[A], #32],[%[A], #72]\n"
//                            "eor	%x26,%x26,[%[A], #80]\n"
//                            "eor	%x27,%x27,[%[A], #88]\n"
//                            "eor	%x28,%x28,[%[A], #96]\n"
//                            "eor	%x29,%x29,[%[A], #104]\n"
//                            "eor	%x30,%x30,[%[A], #112]\n"
//                            "eor	%x26,%x26,[%[A], #120]\n"
//                            "eor	%x27,%x27,[%[A], #128]\n"
//                            "eor	%x28,%x28,[%[A], #136]\n"
//                            "eor	%x29,%x29,[%[A], #144]\n"
//                            "eor	%x30,%x30,[%[A], #152]\n"
//                            "eor	%x26,%x26,[%[A], #160]\n"
//                            "eor	%x28,%x28,[%[A], #176]\n"
//                            "eor	%x27,%x27,[%[A], #168]\n"
//                            "eor	%x29,%x29,[%[A], #184]\n"
//                            "eor	%x30,%x30,[%[A], #192]\n"
//                            "eor	$C[5],%x26,%x28,ror#63\n"
//                            "eor	[%[A], #8],[%[A], #8],$C[5]\n"
//                            "eor	[%[A], #48],[%[A], #48],$C[5]\n"
//                            "eor	[%[A], #88],[%[A], #88],$C[5]\n"
//                            "eor	[%[A], #128],[%[A], #128],$C[5]\n"
//                            "eor	[%[A], #168],[%[A], #168],$C[5]\n"
//                            "eor	$C[5],%x27,%x29,ror#63\n"
//                            "eor	%x28,%x28,%x30,ror#63\n"
//                            "eor	%x29,%x29,%x26,ror#63\n"
//                            "eor	%x30,%x30,%x27,ror#63\n"
//                            "eor	%x27,   [%[A], #16]],$C[5]\n"
//                            "eor	[%[A], #56],[%[A], #56],$C[5]\n"
//                            "eor	[%[A], #96],[%[A], #96],$C[5]\n"
//                            "eor	[%[A], #136],[%[A], #136],$C[5]\n"
//                            "eor	[%[A], #176],[%[A], #176],$C[5]\n"
//                            "eor	[%[A], #0],[%[A], #0],%x30\n"
//                            "eor	[%[A], #40],[%[A], #40],%x30\n"
//                            "eor	[%[A], #80],[%[A], #80],%x30\n"
//                            "eor	[%[A], #120],[%[A], #120],%x30\n"
//                            "eor	[%[A], #160],[%[A], #160],%x30\n"
//
//                            "ldp	[%[A], #32],[%[A], #72],[sp,#0]\n"
//                            "eor	%x26, [%[A], #24]],%x28  \n"
//                            "eor	[%[A], #64],[%[A], #64],%x28\n"
//                            "eor	[%[A], #104],[%[A], #104],%x28\n"
//                            "eor	[%[A], #144],[%[A], #144],%x28\n"
//                            "eor	[%[A], #184],[%[A], #184],%x28\n"
//                            "eor	%x28, [%[A], #32],%x29  \n"
//                            "eor	[%[A], #72],[%[A], #72],%x29\n"
//                            "eor	[%[A], #112],[%[A], #112],%x29\n"
//                            "eor	[%[A], #152],[%[A], #152],%x29\n"
//                            "eor	[%[A], #192],[%[A], #192],%x29\n"
//
//                            "mov	%x29,[%[A], #8]\n"
//                            "ror	[%[A], #8],[%[A], #48],#20\n"
//                            "ror	[%[A], #16]],[%[A], #96],#21\n"
//                            "ror	[%[A], #24]],[%[A], #144],#43\n"
//                            "ror	[%[A], #32],[%[A], #192],#50\n"
//                            "ror	[%[A], #48],[%[A], #72],#44\n"
//                            "ror	[%[A], #96],[%[A], #104],#39\n"
//                            "ror	[%[A], #144],[%[A], #136],#49\n"
//                            "ror	[%[A], #192],[%[A], #168],#62\n"
//                            "ror	[%[A], #72],[%[A], #176],#3\n"
//                            "ror	[%[A], #104],[%[A], #152],#56\n"
//                            "ror	[%[A], #136],[%[A], #88],#54\n"
//                            "ror	[%[A], #168],[%[A], #64],#9\n"
//                            "ror	[%[A], #176],[%[A], #112],#25\n"
//                            "ror	[%[A], #152],[%[A], #184],#8\n"
//                            "ror	[%[A], #88],[%[A], #56],#58\n"
//                            "ror	[%[A], #64],[%[A], #128],#19\n"
//                            "ror	[%[A], #112],[%[A], #160],#46\n"
//                            "ror	[%[A], #184],[%[A], #120],#23\n"
//                            "ror	[%[A], #56],[%[A], #80],#61\n"
//                            "ror	[%[A], #128],[%[A], #40],#28\n"
//                            "ror	[%[A], #40],%x26,#36\n"
//                            "ror	[%[A], #80],%x29,#63\n"
//                            "ror	[%[A], #120],%x28,#37\n"
//                            "ror	[%[A], #160],%x27,#2\n"
//
//                            "bic	%x26,[%[A], #16]],[%[A], #8]\n"
//                            "bic	%x27,[%[A], #24]],[%[A], #16]]\n"
//                            "bic	%x28,[%[A], #0],[%[A], #32]\n"
//                            "bic	%x29,[%[A], #8],[%[A], #0]\n"
//                            "eor	[%[A], #0],[%[A], #0],%x26\n"
//                            "bic	%x26,[%[A], #32],[%[A], #24]]\n"
//                            "eor	[%[A], #8],[%[A], #8],%x27\n"
//                            "ldr	%x27,[sp,#16]\n"
//                            "eor	[%[A], #24]],[%[A], #24]],%x28\n"
//                            "eor	[%[A], #32],[%[A], #32],%x29\n"
//                            "eor	[%[A], #16]],[%[A], #16]],%x26\n"
//                            "ldr	%x29,[%x27],#8\n"
//                            "bic	%x26,[%[A], #56],[%[A], #48]\n"
//                            //                            "tst	%x27,#255\n"
//                            //                            "str	%x27,[sp,#16]\n"
//                            "bic	%x27,[%[A], #64],[%[A], #56]\n"
//                            "bic	%x28,[%[A], #40],[%[A], #72]\n"
//                            "eor	[%[A], #0],[%[A], #0],%x29\n"
//                            "bic	%x29,[%[A], #48],[%[A], #40]\n"
//                            "eor	[%[A], #40],[%[A], #40],%x26\n"
//                            "bic	%x26,[%[A], #72],[%[A], #64]\n"
//                            "eor	[%[A], #48],[%[A], #48],%x27\n"
//                            "eor	[%[A], #64],[%[A], #64],%x28\n"
//                            "eor	[%[A], #72],[%[A], #72],%x29\n"
//                            "eor	[%[A], #56],[%[A], #56],%x26\n"
//                            "bic	%x26,[%[A], #96],[%[A], #88]\n"
//                            "bic	%x27,[%[A], #104],[%[A], #96]\n"
//                            "bic	%x28,[%[A], #80],[%[A], #112]\n"
//                            "bic	%x29,[%[A], #88],[%[A], #80]\n"
//                            "eor	[%[A], #80],[%[A], #80],%x26\n"
//                            "bic	%x26,[%[A], #112],[%[A], #104]\n"
//                            "eor	[%[A], #88],[%[A], #88],%x27\n"
//                            "eor	[%[A], #104],[%[A], #104],%x28\n"
//                            "eor	[%[A], #112],[%[A], #112],%x29\n"
//                            "eor	[%[A], #96],[%[A], #96],%x26\n"
//                            "bic	%x26,[%[A], #136],[%[A], #128]\n"
//                            "bic	%x27,[%[A], #144],[%[A], #136]\n"
//                            "bic	%x28,[%[A], #120],[%[A], #152]\n"
//                            "bic	%x29,[%[A], #128],[%[A], #120]\n"
//                            "eor	[%[A], #120],[%[A], #120],%x26\n"
//                            "bic	%x26,[%[A], #152],[%[A], #144]\n"
//                            "eor	[%[A], #128],[%[A], #128],%x27\n"
//                            "eor	[%[A], #144],[%[A], #144],%x28\n"
//                            "eor	[%[A], #152],[%[A], #152],%x29\n"
//                            "eor	[%[A], #136],[%[A], #136],%x26\n"
//                            "bic	%x26,[%[A], #176],[%[A], #168]\n"
//                            "bic	%x27,[%[A], #184],[%[A], #176]\n"
//                            "bic	%x28,[%[A], #160],[%[A], #192]\n"
//                            "bic	%x29,[%[A], #168],[%[A], #160]\n"
//                            "eor	[%[A], #160],[%[A], #160],%x26\n"
//                            "bic	%x26,[%[A], #192],[%[A], #184]\n"
//                            "eor	[%[A], #168],[%[A], #168],%x27\n"
//                            "eor	[%[A], #184],[%[A], #184],%x28\n"
//                            "eor	[%[A], #192],[%[A], #192],%x29\n"
//                            "eor	[%[A], #176],[%[A], #176],%x26\n"
//                            //                            "bne	1b\n"
//
//                            :
//                            : [A] "r"(A.begin()), [rounds] "r"(round_constants_size), [c] "r"(round_constants.begin())
//                            : "cc", "memory", "%x26", "%x27", "%x28", "%x29", "%x30"    // C0, C1, C2, C3
//                        );
                    }
                };

                template<typename PolicyType>
                constexpr typename keccak_1600_armv8_impl<PolicyType>::round_constants_type const
                    keccak_1600_armv8_impl<PolicyType>::round_constants;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_ARMV8_IMPL_HPP
