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

#define MOVQ(Xn, imm)                                       \
    "movz    " #Xn ",  " #imm  " & 0xFFFF \n"               \
    "movk    " #Xn ", (" #imm  " >> 16) & 0xFFFF, lsl 16\n" \
    "movk    " #Xn ", (" #imm  " >> 32) & 0xFFFF, lsl 32\n" \
    "movk    " #Xn ", (" #imm " >> 48) & 0xFFFF, lsl 48\n"

#define keccak_1600_armv8_step(c)    \
    "sub  sp, sp, #32 \n"            \
                                     \
    "eor   x25,x0,x5 \n"             \
                                     \
    "stp  x4, x9, [sp] \n"           \
                                     \
    "str   x0, [sp, #16]\n"          \
    "ldr   x0, [%[A], #8]\n"         \
    "eor	x26,x0,x6 \n"            \
    "eor	x27,x2,x7 \n"            \
    "eor	x28,x3,x8 \n"            \
                                     \
    "eor	x4,x4,x9 \n"             \
    "eor	x25,x25,x10 \n"          \
    "eor	x26,x26,x11 \n"          \
    "eor	x27,x27,x12 \n"          \
    "eor	x28,x28,x13 \n"          \
    "eor	x4,x4,x14 \n"            \
    "eor	x25,x25,x15 \n"          \
    "eor	x26,x26,x16 \n"          \
    "eor	x27,x27,x17 \n"          \
    "eor	x28,x28,x30 \n"          \
    "eor	x4,x4,x19 \n"            \
    "eor	x25,x25,x20 \n"          \
    "eor	x27,x27,x22 \n"          \
    "eor	x26,x26,x21 \n"          \
    "eor	x28,x28,x23 \n"          \
    "eor	x4,x4,x24 \n"            \
    "eor	x9,x25,x27,ror#63 \n"    \
                                     \
    "eor   x0,x0,x9 \n"              \
    "str   x0, [%[A], #8]\n"         \
    "ldr   x0, [sp, #16]\n"          \
                                     \
    "eor	x6,x6,x9 \n"             \
    "eor	x11,x11,x9 \n"           \
    "eor	x16,x16,x9 \n"           \
    "eor	x21,x21,x9 \n"           \
    "eor	x9,x26,x28,ror#63 \n"    \
    "eor	x27,x27,x4,ror#63 \n"    \
    "eor	x28,x28,x25,ror#63 \n"   \
    "eor	x4,x4,x26,ror#63 \n"     \
    "eor	x26,x2,x9 \n"            \
    "eor	x7,x7,x9 \n"             \
    "eor	x12,x12,x9 \n"           \
    "eor	x17,x17,x9 \n"           \
    "eor	x22,x22,x9 \n"           \
                                     \
    "eor	x0,x0,x4 \n"             \
    "eor	x5,x5,x4 \n"             \
    "eor	x10,x10,x4 \n"           \
    "eor	x15,x15,x4 \n"           \
    "eor	x20,x20,x4 \n"           \
                                     \
    "ldp  x4, x9, [sp]\n"            \
                                     \
    "eor	x25,x3,x27 \n"           \
    "eor	x8,x8,x27 \n"            \
    "eor	x13,x13,x27 \n"          \
    "eor	x30,x30,x27 \n"          \
    "eor	x23,x23,x27 \n"          \
    "eor	x27,x4,x28 \n"           \
    "eor	x9,x9,x28 \n"            \
    "eor	x14,x14,x28 \n"          \
    "eor	x19,x19,x28 \n"          \
    "eor	x24,x24,x28 \n"          \
                                     \
    "str   x0, [sp, #16]\n"          \
    "ldr   x0, [%[A], #8]\n"         \
    "mov	x28,x0\n"                \
    "ror	x0,x6,#20\n"             \
    "ror	x2,x12,#21\n"            \
    "ror	x3,x30,#43\n"            \
    "ror	x4,x24,#50\n"            \
                                     \
    "ror	x6,x9,#44\n"             \
    "ror	x12,x13,#39\n"           \
    "ror	x30,x17,#49\n"           \
    "ror	x24,x21,#62\n"           \
                                     \
    "ror	x9,x22,#3\n"             \
    "ror	x13,x19,#56\n"           \
    "ror	x17,x11,#54\n"           \
    "ror	x21,x8,#9\n"             \
                                     \
    "ror	x22,x14,#25\n"           \
    "ror	x19,x23,#8\n"            \
    "ror	x11,x7,#58\n"            \
    "ror	x8,x16,#19\n"            \
                                     \
    "ror	x14,x20,#46\n"           \
    "ror	x23,x15,#23\n"           \
    "ror	x7,x10,#61\n"            \
    "ror	x16,x5,#28\n"            \
                                     \
    "ror	x5,x25,#36\n"            \
    "ror	x10,x28,#63\n"           \
    "ror	x15,x27,#37\n"           \
    "ror	x20,x26,#2\n"            \
                                     \
    "bic	x25,x2,x0 \n"            \
    "str   x0, [%[A], #8]\n"         \
    "ldr   x0, [sp, #16]\n"          \
                                     \
    "bic	x26,x3,x2 \n"            \
                                     \
    "str   x2, [sp, #16]\n"          \
    "ldr   x2, [%[A], #8]\n"         \
    "bic	x27,x0,x4 \n"            \
    "bic	x28,x2,x0 \n"            \
    "eor	x0,x0,x25 \n"            \
                                     \
    "bic	x25,x4,x3 \n"            \
    "eor	x2,x2,x26 \n"            \
    "str   x2, [%[A], #8]\n"         \
    "ldr   x2, [sp, #16]\n"          \
                                     \
    "eor	x3,x3,x27 \n"            \
    "eor	x4,x4,x28 \n"            \
    "eor	x2,x2,x25 \n"            \
                                     \
    "bic	x25,x7,x6 \n"            \
                                     \
    "bic	x26,x8,x7 \n"            \
    "bic	x27,x5,x9 \n"            \
                                     \
    "bic	x28,x6,x5 \n"            \
    "eor	x5,x5,x25 \n"            \
    "bic	x25,x9,x8 \n"            \
    "eor	x6,x6,x26 \n"            \
    "eor	x8,x8,x27 \n"            \
    "eor	x9,x9,x28 \n"            \
    "eor	x7,x7,x25 \n"            \
    "bic	x25,x12,x11 \n"          \
    "bic	x26,x13,x12 \n"          \
    "bic	x27,x10,x14 \n"          \
    "bic	x28,x11,x10 \n"          \
    "eor	x10,x10,x25 \n"          \
    "bic	x25,x14,x13 \n"          \
    "eor	x11,x11,x26 \n"          \
    "eor	x13,x13,x27 \n"          \
    "eor	x14,x14,x28 \n"          \
    "eor	x12,x12,x25 \n"          \
    "bic	x25,x17,x16 \n"          \
    "bic	x26,x30,x17 \n"          \
    "bic	x27,x15,x19 \n"          \
    "bic	x28,x16,x15 \n"          \
    "eor	x15,x15,x25 \n"          \
    "bic	x25,x19,x30 \n"          \
    "eor	x16,x16,x26 \n"          \
    "eor	x30,x30,x27 \n"          \
    "eor	x19,x19,x28 \n"          \
    "eor	x17,x17,x25 \n"          \
    "bic	x25,x22,x21 \n"          \
    "bic	x26,x23,x22 \n"          \
    "bic	x27,x20,x24 \n"          \
    "bic	x28,x21,x20 \n"          \
    "eor	x20,x20,x25 \n"          \
    "bic	x25,x24,x23 \n"          \
    "eor	x21,x21,x26 \n"          \
    "eor	x23,x23,x27 \n"          \
    "eor	x24,x24,x28 \n"          \
    "eor	x22,x22,x25 \n"          \
    MOVQ(x25, c)                     \
                                     \
    "eor x0, x0, x25 \n"             \
    "add  sp, sp, #32 \n"

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
                        __asm__ volatile(
                            "ldr x0, [%[A], #0]\n"
//                            "ldr x1, [%[A], #8]\n"
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
                            "ldr x30, [%[A], #144]\n"
                            "ldr x19, [%[A], #152]\n"
                            "ldr x20, [%[A], #160]\n"
                            "ldr x21, [%[A], #168]\n"
                            "ldr x22, [%[A], #176]\n"
                            "ldr x23, [%[A], #184]\n"
                            "ldr x24, [%[A], #192]\n"

                            keccak_1600_armv8_step(0x0000000000000001)
                            keccak_1600_armv8_step(0x0000000000008082)
                            keccak_1600_armv8_step(0x800000000000808a)
                            keccak_1600_armv8_step(0x8000000080008000)
                            keccak_1600_armv8_step(0x000000000000808b)
                            keccak_1600_armv8_step(0x0000000080000001)
                            keccak_1600_armv8_step(0x8000000080008081)
                            keccak_1600_armv8_step(0x8000000000008009)
                            keccak_1600_armv8_step(0x000000000000008a)
                            keccak_1600_armv8_step(0x0000000000000088)
                            keccak_1600_armv8_step(0x0000000080008009)
                            keccak_1600_armv8_step(0x000000008000000a)
                            keccak_1600_armv8_step(0x000000008000808b)
                            keccak_1600_armv8_step(0x800000000000008b)
                            keccak_1600_armv8_step(0x8000000000008089)
                            keccak_1600_armv8_step(0x8000000000008003)
                            keccak_1600_armv8_step(0x8000000000008002)
                            keccak_1600_armv8_step(0x8000000000000080)
                            keccak_1600_armv8_step(0x000000000000800a)
                            keccak_1600_armv8_step(0x800000008000000a)
                            keccak_1600_armv8_step(0x8000000080008081)
                            keccak_1600_armv8_step(0x8000000000008080)
                            keccak_1600_armv8_step(0x0000000080000001)
                            keccak_1600_armv8_step(0x8000000080008008)

                            "str x0, [%[A], #0]\n"
//                            "str x1, [%[A], #8]\n"
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
                            "str x30, [%[A], #144]\n"
                            "str x19, [%[A], #152]\n"
                            "str x20, [%[A], #160]\n"
                            "str x21, [%[A], #168]\n"
                            "str x22, [%[A], #176]\n"
                            "str x23, [%[A], #184]\n"
                            "str x24, [%[A], #192]\n"
                            :
                            : [A] "r"(A.begin())
                            : "cc", "memory", "x25", "x26", "x27", "x28",    // C0, C1, C2, C3
                                                                             //"x1",
                              "x0", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
                              "x15", "x16", "x17", "x30", "x19", "x20", "x21", "x22", "x23", "x24");
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
