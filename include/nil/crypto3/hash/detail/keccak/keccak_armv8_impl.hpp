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
                            std::array<word_type, 10> CD;
                            std::array<word_type, 25> B;

                            //                            register word_type A0 asm("x0") = A[0];
                            //                            register word_type A1 asm("x1") = A[1];
                            //                            register word_type A2 asm("x2") = A[2];
                            //                            register word_type A3 asm("x3") = A[3];
                            //                            register word_type A4 asm("x4") = A[4];
                            //                            register word_type A5 asm("x5") = A[5];
                            //                            register word_type A6 asm("x6") = A[6];
                            //                            register word_type A7 asm("x7") = A[7];
                            //                            register word_type A8 asm("x8") = A[8];
                            //                            register word_type A9 asm("x9") = A[9];
                            //                            register word_type A10 asm("x10") = A[10];
                            //                            register word_type A11 asm("x11") = A[11];
                            //                            register word_type A12 asm("x12") = A[12];
                            //                            register word_type A13 asm("x13") = A[13];
                            //                            register word_type A14 asm("x14") = A[14];
                            //                            register word_type A15 asm("x15") = A[15];
                            //                            register word_type A16 asm("x16") = A[16];
                            //                            register word_type A17 asm("x17") = A[17];
                            //                            register word_type A18 asm("x18") = A[18];
                            //                            register word_type A19 asm("x19") = A[19];
                            //                            register word_type A20 asm("x20") = A[20];
                            //                            register word_type A21 asm("x21") = A[21];
                            //                            register word_type A22 asm("x22") = A[22];
                            //                            register word_type A23 asm("x23") = A[23];
                            //                            register word_type A24 asm("x24") = A[24];

                            //                            word_type z[4] = {4, 3, 2, 1};
                            //                            register word_type out asm("x2") = 0;
                            //                            __asm__ (
                            //                                "mov x1, #16\n\t"
                            //                                "ldr %[OUT], [%[ARGV],#8]\n\t"
                            //                                : [OUT] "=r" (out)
                            //                                : [ARGV] "r" (z)
                            //                                : "x1"
                            //                            );

                            //                            std::array<word_type, 4> z = {4, 3, 2, 1};
                            //                            register word_type out asm("x2") = 30;
                            //                            __asm__ (
                            //                                "str %[OUT], [%[ARGV],#8]\n\t"
                            //                                :
                            //                                : [OUT] "r" (out), [ARGV] "r" (z.begin())
                            //                                : "x1"
                            //                            );
                            //                            std::cout << z[1] << std::endl;
                            __asm__(
                                "ldr x0, [%[A], #0]\n"
                                "ldr x1, [%[A], #8]\n"
                                "ldr x2, [%[A], #16]\n"
                                "ldr x3, [%[A], #24]\n"
                                "ldr x4, [%[A], #32]\n"
                                "ldr x5, [%[A], #40]\n"
                                "ldr x6, [%[A], #48]\n"
                                "ldr x7, [%[A], #56]\n"
                                "ldr x8, [%[A], #64]\n"
                                "ldr x9, [%[A], #72]\n"
                                "ldr x10, [%[A], #80]\n"
                                "ldr x11, [%[A], #88]\n"
                                "ldr x12, [%[A], #96]\n"
                                "ldr x13, [%[A], #104]\n"
                                "ldr x14, [%[A], #112]\n"
                                "ldr x15, [%[A], #120]\n"
                                "ldr x16, [%[A], #128]\n"
                                "ldr x17, [%[A], #136]\n"
                                "ldr x18, [%[A], #144]\n"
                                "ldr x19, [%[A], #152]\n"
                                "ldr x20, [%[A], #160]\n"
                                "ldr x21, [%[A], #168]\n"
                                "ldr x22, [%[A], #176]\n"
                                "ldr x23, [%[A], #184]\n"
                                "ldr x24, [%[A], #192]\n"

                                "mov x25, x0\n"
                                "eor x25, x25, x5\n"
                                "eor x25, x25, x10\n"
                                "eor x25, x25, x15\n"
                                "eor x25, x25, x20\n"
                                "str x25, [%[CD], #0]\n"

                                "mov x25, x1\n"
                                "eor x25, x25, x6\n"
                                "eor x25, x25, x11\n"
                                "eor x25, x25, x16\n"
                                "eor x25, x25, x21\n"
                                "str x25, [%[CD], #8]\n"

                                "mov x25, x2\n"
                                "eor x25, x25, x7\n"
                                "eor x25, x25, x12\n"
                                "eor x25, x25, x17\n"
                                "eor x25, x25, x22\n"
                                "str x25, [%[CD], #16]\n"

                                "mov x25, x3\n"
                                "eor x25, x25, x8\n"
                                "eor x25, x25, x13\n"
                                "eor x25, x25, x18\n"
                                "eor x25, x25, x23\n"
                                "str x25, [%[CD], #24]\n"

                                "mov x25, x4\n"
                                "eor x25, x25, x9\n"
                                "eor x25, x25, x14\n"
                                "eor x25, x25, x19\n"
                                "eor x25, x25, x24\n"
                                "str x25, [%[CD], #32]\n"
                                // Calculate D
                                "ldr x25, [%[CD], #0]\n"
                                "ldr x26, [%[CD], #24]\n"
                                "ror x25, x25, #63\n"
                                "eor x25, x25, x26\n"
                                "str x25, [%[CD], #40]\n"

                                "ldr x25, [%[CD], #8]\n"
                                "ldr x26, [%[CD], #32]\n"
                                "ror x25, x25, #63\n"
                                "eor x25, x25, x26\n"
                                "str x25, [%[CD], #48]\n"

                                "ldr x25, [%[CD], #16]\n"
                                "ldr x26, [%[CD], #0]\n"
                                "ror x25, x25, #63\n"
                                "eor x25, x25, x26\n"
                                "str x25, [%[CD], #56]\n"

                                "ldr x25, [%[CD], #24]\n"
                                "ldr x26, [%[CD], #8]\n"
                                "ror x25, x25, #63\n"
                                "eor x25, x25, x26\n"
                                "str x25, [%[CD], #64]\n"

                                "ldr x25, [%[CD], #32]\n"
                                "ldr x26, [%[CD], #16]\n"
                                "ror x25, x25, #63\n"
                                "eor x25, x25, x26\n"
                                "str x25, [%[CD], #72]\n"
                                // Calculate B
                                "ldr x25, [%[CD], #48]\n"
                                "eor x25, x25, x0\n"
                                "ror x25, x25, #0\n"
                                "str x25, [%[B], #0]\n"

                                "ldr x25, [%[CD], #56]\n"
                                "eor x25, x25, x1\n"
                                "ror x25, x25, #63\n"
                                "str x25, [%[B], #80]\n"

                                "ldr x25, [%[CD], #64]\n"
                                "eor x25, x25, x2\n"
                                "ror x25, x25, #2\n"
                                "str x25, [%[B], #160]\n"

                                "ldr x25, [%[CD], #72]\n"
                                "eor x25, x25, x3\n"
                                "ror x25, x25, #36\n"
                                "str x25, [%[B], #40]\n"

                                "ldr x25, [%[CD], #40]\n"
                                "eor x25, x25, x4\n"
                                "ror x25, x25, #37\n"
                                "str x25, [%[B], #120]\n"

                                "ldr x25, [%[CD], #48]\n"
                                "eor x25, x25, x5\n"
                                "ror x25, x25, #28\n"
                                "str x25, [%[B], #128]\n"

                                "ldr x25, [%[CD], #56]\n"
                                "eor x25, x25, x6\n"
                                "ror x25, x25, #20\n"
                                "str x25, [%[B], #8]\n"

                                "ldr x25, [%[CD], #64]\n"
                                "eor x25, x25, x7\n"
                                "ror x25, x25, #58\n"
                                "str x25, [%[B], #88]\n"

                                "ldr x25, [%[CD], #72]\n"
                                "eor x25, x25, x8\n"
                                "ror x25, x25, #9\n"
                                "str x25, [%[B], #168]\n"

                                "ldr x25, [%[CD], #40]\n"
                                "eor x25, x25, x9\n"
                                "ror x25, x25, #44\n"
                                "str x25, [%[B], #48]\n"

                                "ldr x25, [%[CD], #48]\n"
                                "eor x25, x25, x10\n"
                                "ror x25, x25, #61\n"
                                "str x25, [%[B], #56]\n"

                                "ldr x25, [%[CD], #56]\n"
                                "eor x25, x25, x11\n"
                                "ror x25, x25, #54\n"
                                "str x25, [%[B], #136]\n"

                                "ldr x25, [%[CD], #64]\n"
                                "eor x25, x25, x12\n"
                                "ror x25, x25, #21\n"
                                "str x25, [%[B], #16]\n"

                                "ldr x25, [%[CD], #72]\n"
                                "eor x25, x25, x13\n"
                                "ror x25, x25, #39\n"
                                "str x25, [%[B], #96]\n"

                                "ldr x25, [%[CD], #40]\n"
                                "eor x25, x25, x14\n"
                                "ror x25, x25, #25\n"
                                "str x25, [%[B], #176]\n"

                                "ldr x25, [%[CD], #48]\n"
                                "eor x25, x25, x15\n"
                                "ror x25, x25, #23\n"
                                "str x25, [%[B], #184]\n"

                                "ldr x25, [%[CD], #56]\n"
                                "eor x25, x25, x16\n"
                                "ror x25, x25, #19\n"
                                "str x25, [%[B], #64]\n"

                                "ldr x25, [%[CD], #64]\n"
                                "eor x25, x25, x17\n"
                                "ror x25, x25, #49\n"
                                "str x25, [%[B], #144]\n"

                                "ldr x25, [%[CD], #72]\n"
                                "eor x25, x25, x18\n"
                                "ror x25, x25, #43\n"
                                "str x25, [%[B], #24]\n"

                                "ldr x25, [%[CD], #40]\n"
                                "eor x25, x25, x19\n"
                                "ror x25, x25, #56\n"
                                "str x25, [%[B], #104]\n"

                                "ldr x25, [%[CD], #48]\n"
                                "eor x25, x25, x20\n"
                                "ror x25, x25, #46\n"
                                "str x25, [%[B], #112]\n"

                                "ldr x25, [%[CD], #56]\n"
                                "eor x25, x25, x21\n"
                                "ror x25, x25, #62\n"
                                "str x25, [%[B], #192]\n"

                                "ldr x25, [%[CD], #64]\n"
                                "eor x25, x25, x22\n"
                                "ror x25, x25, #3\n"
                                "str x25, [%[B], #72]\n"

                                "ldr x25, [%[CD], #72]\n"
                                "eor x25, x25, x23\n"
                                "ror x25, x25, #8\n"
                                "str x25, [%[B], #152]\n"

                                "ldr x25, [%[CD], #40]\n"
                                "eor x25, x25, x24\n"
                                "ror x25, x25, #50\n"
                                "str x25, [%[B], #32]\n"
                                // Start calculate ending A
                                // -----------
                                "ldr x0, [%[B], #0]\n"
                                "ldr x1, [%[B], #8]\n"
                                "ldr x2, [%[B], #16]\n"
                                "ldr x3, [%[B], #24]\n"
                                "ldr x4, [%[B], #32]\n"
                                "ldr x5, [%[B], #40]\n"
                                "ldr x6, [%[B], #48]\n"
                                "ldr x7, [%[B], #56]\n"
                                "ldr x8, [%[B], #64]\n"
                                "ldr x9, [%[B], #72]\n"
                                "ldr x10, [%[B], #80]\n"
                                "ldr x11, [%[B], #88]\n"
                                "ldr x12, [%[B], #96]\n"
                                "ldr x13, [%[B], #104]\n"
                                "ldr x14, [%[B], #112]\n"
                                "ldr x15, [%[B], #120]\n"
                                "ldr x16, [%[B], #128]\n"
                                "ldr x17, [%[B], #136]\n"
                                "ldr x18, [%[B], #144]\n"
                                "ldr x19, [%[B], #152]\n"
                                "ldr x20, [%[B], #160]\n"
                                "ldr x21, [%[B], #168]\n"
                                "ldr x22, [%[B], #176]\n"
                                "ldr x23, [%[B], #184]\n"
                                "ldr x24, [%[B], #192]\n"
                                // End left part
                                "ldr x25, [%[B], #8]\n"
                                "ldr x26, [%[B], #16]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x0, x0, x25\n"

                                "ldr x25, [%[B], #16]\n"
                                "ldr x26, [%[B], #24]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x1, x1, x25\n"

                                "ldr x25, [%[B], #24]\n"
                                "ldr x26, [%[B], #32]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x2, x2, x25\n"

                                "ldr x25, [%[B], #32]\n"
                                "ldr x26, [%[B], #0]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x3, x3, x25\n"

                                "ldr x25, [%[B], #0]\n"
                                "ldr x26, [%[B], #8]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x4, x4, x25\n"
                                //a5
                                "ldr x25, [%[B], #48]\n"
                                "ldr x26, [%[B], #56]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x5, x5, x25\n"

                                "ldr x25, [%[B], #56]\n"
                                "ldr x26, [%[B], #64]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x6, x6, x25\n"

                                "ldr x25, [%[B], #64]\n"
                                "ldr x26, [%[B], #72]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x7, x7, x25\n"

                                "ldr x25, [%[B], #72]\n"
                                "ldr x26, [%[B], #40]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x8, x8, x25\n"

                                "ldr x25, [%[B], #40]\n"
                                "ldr x26, [%[B], #48]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x9, x9, x25\n"
                                //a10
                                "ldr x25, [%[B], #88]\n"
                                "ldr x26, [%[B], #96]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x10, x10, x25\n"

                                "ldr x25, [%[B], #96]\n"
                                "ldr x26, [%[B], #104]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x11, x11, x25\n"

                                "ldr x25, [%[B], #104]\n"
                                "ldr x26, [%[B], #112]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x12, x12, x25\n"

                                "ldr x25, [%[B], #112]\n"
                                "ldr x26, [%[B], #80]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x13, x13, x25\n"

                                "ldr x25, [%[B], #80]\n"
                                "ldr x26, [%[B], #88]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x14, x14, x25\n"
                                //a15
                                "ldr x25, [%[B], #128]\n"
                                "ldr x26, [%[B], #136]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x15, x15, x25\n"

                                "ldr x25, [%[B], #136]\n"
                                "ldr x26, [%[B], #144]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x16, x16, x25\n"

                                "ldr x25, [%[B], #144]\n"
                                "ldr x26, [%[B], #152]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x17, x17, x25\n"

                                "ldr x25, [%[B], #152]\n"
                                "ldr x26, [%[B], #120]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x18, x18, x25\n"

                                "ldr x25, [%[B], #120]\n"
                                "ldr x26, [%[B], #128]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x19, x19, x25\n"
                                //a20
                                "ldr x25, [%[B], #168]\n"
                                "ldr x26, [%[B], #176]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x20, x20, x25\n"

                                "ldr x25, [%[B], #176]\n"
                                "ldr x26, [%[B], #184]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x21, x21, x25\n"

                                "ldr x25, [%[B], #184]\n"
                                "ldr x26, [%[B], #192]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x22, x22, x25\n"

                                "ldr x25, [%[B], #192]\n"
                                "ldr x26, [%[B], #160]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x23, x23, x25\n"

                                "ldr x25, [%[B], #160]\n"
                                "ldr x26, [%[B], #168]\n"
                                "mvn x25, x25\n"
                                "and x25, x25, x26\n"
                                "eor x24, x24, x25\n"

                                "str x0, [%[A], #0]\n"
                                "str x1, [%[A], #8]\n"
                                "str x2, [%[A], #16]\n"
                                "str x3, [%[A], #24]\n"
                                "str x4, [%[A], #32]\n"
                                "str x5, [%[A], #40]\n"
                                "str x6, [%[A], #48]\n"
                                "str x7, [%[A], #56]\n"
                                "str x8, [%[A], #64]\n"
                                "str x9, [%[A], #72]\n"
                                "str x10, [%[A], #80]\n"
                                "str x11, [%[A], #88]\n"
                                "str x12, [%[A], #96]\n"
                                "str x13, [%[A], #104]\n"
                                "str x14, [%[A], #112]\n"
                                "str x15, [%[A], #120]\n"
                                "str x16, [%[A], #128]\n"
                                "str x17, [%[A], #136]\n"
                                "str x18, [%[A], #144]\n"
                                "str x19, [%[A], #152]\n"
                                "str x20, [%[A], #160]\n"
                                "str x21, [%[A], #168]\n"
                                "str x22, [%[A], #176]\n"
                                "str x23, [%[A], #184]\n"
                                "str x24, [%[A], #192]\n"

                                :
//                                : [D] "r"(D.begin()), [C] "r"(C.begin()), [B] "r"(B.begin()), [A] "r"(A.begin())
                                : [CD] "r"(CD.begin()), [B] "r"(B.begin()), [A] "r"(A.begin())
                                : "cc", "memory", "x25", "x26", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
                                  "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
                                  "x21", "x22", "x23", "x24");

                            A[0] ^= c;
                            //                            A[0] = A0 ^ c;
                            //                            A[1] = A1;
                            //                            A[2] = A2;
                            //                            A[3] = A3;
                            //                            A[4] = A4;
                            //                            A[5] = A5;
                            //                            A[6] = A6;
                            //                            A[7] = A7;
                            //                            A[8] = A8;
                            //                            A[9] = A9;
                            //                            A[10] = A10;
                            //                            A[11] = A11;
                            //                            A[12] = A12;
                            //                            A[13] = A13;
                            //                            A[14] = A14;
                            //                            A[15] = A15;
                            //                            A[16] = A16;
                            //                            A[17] = A17;
                            //                            A[18] = A18;
                            //                            A[19] = A19;
                            //                            A[20] = A20;
                            //                            A[21] = A21;
                            //                            A[22] = A22;
                            //                            A[23] = A23;
                            //                            A[24] = A24;
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
                        //                            : [A] "r"(A.begin()), [rounds] "r"(round_constants_size), [c]
                        //                            "r"(round_constants.begin()) : "cc", "memory", "%x26", "%x27",
                        //                            "%x28", "%x29", "%x30"    // C0, C1, C2, C3
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
