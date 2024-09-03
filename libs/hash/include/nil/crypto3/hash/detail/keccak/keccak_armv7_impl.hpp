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

#ifndef CRYPTO3_KECCAK_ARMV8_IMPL_HPP
#define CRYPTO3_KECCAK_ARMV8_IMPL_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>
#include <nil/crypto3/hash/detail/keccak/keccak_impl.hpp>

#define MOVQ(Xn, imm)                           \
    "movw   " #Xn ",  " #imm  " & 0xFFFF \n"    \
    "movt   " #Xn ", (" #imm  " >> 16) & 0xFFFF\n"

#define keccak_1600_armv7_step(c)   \
    "sub   sp, sp, #64 \n"          \
    "stmia sp, {r4-r11} \n"         \
                                     \
    "eor   r12, r0, r5 \n"          \
                                     \
    "str   r4, [sp, #32] \n"        \
                                     \
    "ldr   r0, [%[A], #4] \n"       \
    "eor   r11, r0, r6 \n"          \
    "eor   r10, r2, r7 \n"          \
    "eor   r9, r3, r8 \n"           \
                                     \
    "eor   r4, r4, r9 \n"           \
    "eor   r12, r12, r10 \n"        \
    "eor   r11, r11, r11 \n"        \
    "eor   r10, r10, r12 \n"        \
    "eor   r9, r9, r13 \n"          \
    "eor   r4, r4, r14 \n"          \
    "eor   r12, r12, r15 \n"        \
    "eor   r11, r11, r0 \n"         \
    "eor   r10, r10, r1 \n"         \
    "eor   r9, r9, r2 \n"           \
    "eor   r4, r4, r3 \n"           \
    "eor   r12, r12, r4 \n"         \
    "eor   r10, r10, r5 \n"         \
    "eor   r11, r11, r6 \n"         \
    "eor   r9, r9, r7 \n"           \
    "eor   r4, r4, r8 \n"           \
    "eor   r9, r12, r10, ror#31 \n" \
                                     \
    "eor   r0, r0, r9 \n"           \
    "str   r0, [%[A], #4] \n"       \
    "ldr   r0, [sp, #32] \n"        \
                                     \
    "eor   r6, r6, r9 \n"           \
    "eor   r11, r11, r9 \n"         \
    "eor   r1, r1, r9 \n"           \
    "eor   r5, r5, r9 \n"           \
    "eor   r9, r11, r10, ror#31 \n" \
    "eor   r10, r10, r4, ror#31 \n" \
    "eor   r11, r11, r12, ror#31 \n"\
    "eor   r4, r4, r11, ror#31 \n"  \
    "eor   r12, r2, r9 \n"          \
    "eor   r7, r7, r9 \n"           \
    "eor   r12, r12, r9 \n"         \
    "eor   r1, r1, r9 \n"           \
    "eor   r8, r8, r9 \n"           \
                                     \
    "eor   r0, r0, r4 \n"           \
    "eor   r5, r5, r4 \n"           \
    "eor   r10, r10, r4 \n"         \
    "eor   r3, r3, r4 \n"           \
    "eor   r4, r4, r8 \n"           \
                                     \
    "str   r4, [sp, #32] \n"        \
                                     \
    "eor   r12, r3, r10 \n"         \
    "eor   r8, r8, r10 \n"          \
    "eor   r13, r13, r10 \n"        \
    "eor   r4, r4, r10 \n"          \
    "eor   r14, r14, r10 \n"        \
    "eor   r10, r4, r11 \n"         \
    "eor   r9, r9, r11 \n"          \
    "eor   r4, r4, r11 \n"          \
    "eor   r5, r5, r11 \n"          \
    "eor   r0, r0, r11 \n"          \
                                     \
    "str   r0, [sp, #32] \n"        \
    "ldr   r0, [%[A], #4] \n"       \
    "mov   r11, r0\n"               \
    "ror   r0, r6, #20\n"           \
    "ror   r2, r12, #21\n"          \
    "ror   r3, r13, #43\n"          \
    "ror   r4, r14, #50\n"          \
                                     \
    "ror   r6, r9, #44\n"           \
    "ror   r12, r13, #39\n"         \
    "ror   r13, r4, #49\n"          \
    "ror   r14, r5, #62\n"          \
                                     \
    "ror   r9, r8, #3\n"            \
    "ror   r13, r5, #56\n"          \
    "ror   r4, r11, #54\n"          \
    "ror   r1, r8, #9\n"            \
                                     \
    "ror   r8, r14, #25\n"          \
    "ror   r13, r13, #8\n"          \
    "ror   r11, r7, #58\n"          \
    "ror   r4, r4, #19\n"           \
                                     \
    "ror   r14, r10, #46\n"         \
    "ror   r13, r1, #23\n"          \
    "ror   r7, r4, #61\n"           \
    "ror   r10, r5, #28\n"          \
                                     \
    "ror   r5, r12, #36\n"          \
    "ror   r10, r11, #63\n"         \
    "ror   r1, r10, #37\n"          \
    "ror   r0, r9, #2\n"            \
                                     \
    "bic   r12, r2, r0 \n"          \
    "str   r0, [%[A], #4] \n"       \
    "ldr   r0, [sp, #32] \n"        \
                                     \
    "bic   r13, r3, r2 \n"          \
                                     \
    "str   r2, [sp, #32] \n"        \
    "ldr   r2, [%[A], #4] \n"       \
    "bic   r14, r0, r4 \n"          \
    "bic   r11, r2, r0 \n"          \
    "eor   r0, r0, r12 \n"          \
                                     \
    "bic   r12, r4, r3 \n"          \
    "eor   r2, r2, r13 \n"          \
    "str   r2, [%[A], #4] \n"       \
    "ldr   r2, [sp, #32] \n"        \
                                     \
    "eor   r3, r3, r14 \n"          \
    "eor   r4, r4, r11 \n"          \
    "eor   r2, r2, r12 \n"          \
                                     \
    "bic   r12, r7, r6 \n"          \
                                     \
    "bic   r13, r8, r7 \n"          \
    "bic   r14, r5, r9 \n"          \
                                     \
    "bic   r11, r6, r5 \n"          \
    "eor   r5, r5, r12 \n"          \
    "bic   r12, r9, r8 \n"          \
    "eor   r6, r6, r13 \n"          \
    "eor   r8, r8, r14 \n"          \
    "eor   r9, r9, r11 \n"          \
    "eor   r7, r7, r12 \n"          \
    "bic   r12, r12, r11 \n"        \
    "bic   r13, r13, r12 \n"        \
    "bic   r14, r10, r14 \n"        \
    "bic   r11, r11, r10 \n"        \
    "eor   r10, r10, r12 \n"        \
    "bic   r12, r14, r13 \n"        \
    "eor   r11, r11, r13 \n"        \
    "eor   r14, r14, r14 \n"        \
    "eor   r12, r12, r14 \n"        \
    "bic   r14, r7, r6 \n"          \
    "bic   r11, r11, r14 \n"        \
    "bic   r13, r13, r1 \n"         \
    "bic   r14, r6, r1 \n"          \
    "eor   r1, r1, r12 \n"          \
    "bic   r12, r1, r14 \n"         \
    "eor   r0, r0, r13 \n"          \
    "eor   r1, r1, r11 \n"          \
    "eor   r5, r5, r14 \n"          \
    "eor   r2, r2, r12 \n"          \
    "bic   r12, r10, r9 \n"         \
    "bic   r13, r8, r12 \n"         \
    "bic   r14, r0, r9 \n"          \
    "bic   r11, r1, r0 \n"          \
    "eor   r0, r0, r12 \n"          \
    "bic   r12, r14, r13 \n"        \
    "eor   r1, r1, r13 \n"          \
    "eor   r14, r14, r11 \n"        \
    "eor   r12, r12, r14 \n"        \
    MOVQ(r12, c)                    \
                                     \
    "eor r0, r0, r12 \n"             \
    "ldmia sp, {r4-r11} \n"         \
    "add  sp, sp, #64 \n"

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename PolicyType>
                struct keccak_1600_armv7_impl {
                    typedef PolicyType policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t round_constants_size = policy_type::rounds;
                    typedef typename std::array<word_type, round_constants_size> round_constants_type;
                    constexpr static const round_constants_type round_constants = {
                        0x00000001, 0x00008082, 0x8000808a,
                        0x80008000, 0x0000808b, 0x00000001,
                        0x80008081, 0x80008009, 0x0000008a,
                        0x00000088, 0x00008009, 0x0000000a,
                        0x0000808b, 0x8000008b, 0x80008089,
                        0x80008003, 0x80008002, 0x80000080,
                        0x0000800a, 0x8000000a, 0x80008081,
                        0x80008080, 0x00000001, 0x80008008};

                    static inline void permute(state_type &A) {
                        __asm__ volatile(
                            "ldr r0, [%[A], #0]\n"
                            "ldr r2, [%[A], #8]\n"
                            "ldr r3, [%[A], #12]\n"
                            "ldr r4, [%[A], #16]\n"
                            "ldr r5, [%[A], #20]\n"
                            "ldr r6, [%[A], #24]\n"
                            "ldr r7, [%[A], #28]\n"
                            "ldr r8, [%[A], #32]\n"
                            "ldr r9, [%[A], #36]\n"
                            "ldr r10, [%[A], #40]\n"
                            "ldr r11, [%[A], #44]\n"
                            "ldr r12, [%[A], #48]\n"
                            "ldr r13, [%[A], #52]\n"
                            "ldr r14, [%[A], #56]\n"
                            "ldr r15, [%[A], #60]\n"

                            keccak_1600_armv7_step(0x00000001)
                            keccak_1600_armv7_step(0x00008082)
                            keccak_1600_armv7_step(0x8000808a)
                            keccak_1600_armv7_step(0x80008000)
                            keccak_1600_armv7_step(0x0000808b)
                            keccak_1600_armv7_step(0x00000001)
                            keccak_1600_armv7_step(0x80008081)
                            keccak_1600_armv7_step(0x80008009)
                            keccak_1600_armv7_step(0x0000008a)
                            keccak_1600_armv7_step(0x00000088)
                            keccak_1600_armv7_step(0x00008009)
                            keccak_1600_armv7_step(0x0000000a)
                            keccak_1600_armv7_step(0x0000808b)
                            keccak_1600_armv7_step(0x8000008b)
                            keccak_1600_armv7_step(0x80008089)
                            keccak_1600_armv7_step(0x80008003)
                            keccak_1600_armv7_step(0x80008002)
                            keccak_1600_armv7_step(0x80000080)
                            keccak_1600_armv7_step(0x0000800a)
                            keccak_1600_armv7_step(0x8000000a)
                            keccak_1600_armv7_step(0x80008081)
                            keccak_1600_armv7_step(0x80008080)
                            keccak_1600_armv7_step(0x00000001)
                            keccak_1600_armv7_step(0x80008008)

                            "str r0, [%[A], #0]\n"
                            "str r2, [%[A], #8]\n"
                            "str r3, [%[A], #12]\n"
                            "str r4, [%[A], #16]\n"
                            "str r5, [%[A], #20]\n"
                            "str r6, [%[A], #24]\n"
                            "str r7, [%[A], #28]\n"
                            "str r8, [%[A], #32]\n"
                            "str r9, [%[A], #36]\n"
                            "str r10, [%[A], #40]\n"
                            "str r11, [%[A], #44]\n"
                            "str r12, [%[A], #48]\n"
                            "str r13, [%[A], #52]\n"
                            "str r14, [%[A], #56]\n"
                            "str r15, [%[A], #60]\n"
                            :
                            : [A] "r"(A.begin())
                            : "cc", "memory", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15");
                    }
                };

                template<typename PolicyType>
                constexpr typename keccak_1600_armv7_impl<PolicyType>::round_constants_type const
                    keccak_1600_armv7_impl<PolicyType>::round_constants;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_ARMV8_IMPL_HPP