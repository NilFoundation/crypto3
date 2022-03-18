//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_ASM_FUNCTIONS_HPP
#define BOOST_MULTIPRECISION_ASM_FUNCTIONS_HPP

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
#if BOOST_ARCH_X86_64
                template<typename Limb1, typename Limb2>
                void sub_asm(size_t n, Limb1 *x, const Limb2 *y) {
                    __asm__ volatile(
                        "movq    (%[y]), %%rax           \n\t"
                        "subq    %%rax, (%[x])           \n\t"
                        "pushf                           \n\t"
                        "movq $1, %%rbx                  \n\t"
                        // Loop for sub
                        "4:                              \n\t"
                        "popf                            \n\t"
                        "movq (%[y], %%rbx, 8), %%rax    \n\t"
                        "sbbq %%rax, (%[x], %%rbx, 8)    \n\t"
                        "pushf                           \n\t"
                        "inc %%rbx                       \n\t"
                        "cmp %%rbx, %[limbs]             \n\t"
                        "jne 4b                          \n\t"
                        "popf                            \n\t"
                        :
                        : [limbs] "r"(n), [x] "r"(x), [y] "r"(y)
                        : "cc", "memory", "%rax", "%rcx", "%rbx");
                }

                template<typename Limb1, typename Limb2, typename Limb3>
                bool reduce_limb_asm(size_t n, const size_t &shift, Limb1 *res, const Limb2 *x, const Limb3 &inv) {
                    bool carry = false;
                    __asm__ volatile(
                        // Else check result with mod
                        "movq $0, %%r12                        \n\t"
                    "0:                                        \n\t"
                        "movq %%r12, %%r11                     \n\t"

                        "movq   (%[res], %%r11, 8), %%rax      \n\t"
                        "mulq   %[inv]                         \n\t"
                        "movq   %%rax, %%r10                   \n\t"

                        "movq   (%[x]), %%rax                  \n\t"
                        "mulq   %%r10                          \n\t"
                        "movq   %%rax, %%r8                    \n\t"
                        "movq   %%rdx, %%r9                    \n\t"

                        "mov $1, %%rbx                         \n\t"
                    "1:                                        \n\t"
                        "movq   (%[x], %%rbx, 8), %%rax        \n\t"
                        "mulq   %%r10                          \n\t"
                        "addq   %%r8, (%[res], %%r11, 8)       \n\t"
                        "movq   $0, %%r8                       \n\t"
                        "adcq   %%rax, %%r9                    \n\t"
                        "adcq   %%rdx, %%r8                    \n\t"
                        // swap tmp2, tmp1
                        "movq %%r9, %%rax                      \n\t"
                        "movq %%r8, %%r9                       \n\t"
                        "movq %%rax, %%r8                      \n\t"
                        // swap end
                        "movq $1, %%rdx                        \n\t"
                        "addq %%rdx, %%r11                     \n\t"
                        "inc %%rbx                             \n\t"
                        "cmp %%rbx, %[limbs]                   \n\t"
                        "jne 1b                                \n\t"
                        "mov  %%r11, %%rbx                     \n\t"
                        "addq   %%r8, (%[res], %%rbx, 8)       \n\t"
                        "adcq   %%r9, 8(%[res], %%rbx, 8)      \n\t"
                        "movb $0, %[carry]                     \n\t"
                        "jnc 2f                                \n\t"
                        "adcq   $0, 16(%[res], %%rbx, 8)       \n\t"
                        "movb $1, %[carry]                     \n\t"
                    "2:                                        \n\t"
                        "inc %%r12                             \n\t"
                        "cmpq %[limbs], %%r12                  \n\t"
                        "jne 0b                                \n\t"
                        : [carry] "+r"(carry)
                        : [limbs] "r"(n), [shift] "r"(shift), [res] "r"(res), [x] "r"(x), [inv] "r"(inv)
                        : "cc", "memory", "%rax", "%rbx", "%rdx", "%r8", "%r9", "%r10", "%r11", "%r12");
                    // r8, r9 - tmp1, tmp2
                    // r10 - k
                    return carry;
                }

                template<typename Limb1, typename Limb2>
                int cmp_asm(size_t n, const Limb1 *x, const Limb2 *y) {
                    int result = 0;
                    __asm__ volatile(
                        // Else check result with mod
                        "mov $0, %[res]                  \n\t"
                        "movq %[limbs], %%rbx            \n\t"
                    "1:                                  \n\t"
                        "movq  -8(%[y], %%rbx, 8), %%rax \n\t"
                        "cmpq  %%rax, -8(%[x], %%rbx, 8) \n\t"
                        "jb  2f                          \n\t"
                        "ja  3f                          \n\t"
                        "dec %%rbx                       \n\t"
                        "jnz 1b                          \n\t"
                        "jmp 4f                          \n\t"
                        // Start sub
                    "2:                                  \n\t"
                        "dec %[res]                      \n\t"
                        "jmp 4f                          \n\t"
                    "3:                                  \n\t"
                        "inc %[res]                      \n\t"
                    "4:                                  \n\t"
                        : [res] "=&r"(result)
                        : [limbs] "r"(n), [x] "r"(x), [y] "r"(y)
                        : "cc", "memory", "%rax", "%rcx", "%rbx");
                    return result;
                }

                template<typename Limb1, typename Limb2, typename Limb3>
                void sub_mod_asm(size_t n, Limb1 *x, const Limb2 *y, const Limb3 *mod) {
                    __asm__ volatile(
                        "movq    $1, %%rbx              \n\t"
                        "movq    (%[y]), %%rax          \n\t"
                        "subq    %%rax, (%[x])          \n\t"
                        "pushf                          \n\t"
                        // Start circle sub from 1st limb
                    "1:                                 \n\t"
                        "popf                           \n\t"
                        "movq (%[y], %%rbx, 8), %%rax   \n\t"
                        "sbbq %%rax, (%[x], %%rbx, 8)   \n\t"
                        "pushf                          \n\t"
                        "inc %%rbx                      \n\t"
                        "cmp %%rbx, %[limbs]            \n\t"
                        "jne 1b                         \n\t"
                        "popf                           \n\t"
                        // If it's more than zero (no carry bit) just go to end
                        "jnc 4f                         \n\t"
                        // Else add mod to result
                        "movq    (%[mod]), %%rax        \n\t"
                        "addq    %%rax, (%[x])          \n\t"
                        "pushf                          \n\t"
                        "movq    $1, %%rbx              \n\t"
                    "2:                                 \n\t"
                        "popf                           \n\t"
                        "movq (%[mod], %%rbx, 8), %%rax \n\t"
                        "adcq %%rax, (%[x], %%rbx, 8)   \n\t"
                        "pushf                          \n\t"
                        "inc %%rbx                      \n\t"
                        "cmp %%rbx, %[limbs]            \n\t"
                        "jne 2b                         \n\t"
                        "popf                           \n\t"
                    "4:                                 \n\t"
                        :
                        : [limbs] "r"(n), [x] "r"(x), [y] "r"(y), [mod] "r"(mod)
                        : "cc", "memory", "%rax", "%rcx", "%rbx");
                }

                template<typename Limb1, typename Limb2, typename Limb3>
                void add_mod_asm(size_t n, Limb1 *x, const Limb2 *y, const Limb3 *mod) {
                    __asm__ volatile(
                        "movq    (%[y]), %%rax              \n\t"
                        "addq    %%rax, (%[x])              \n\t"
                        "movq    $1, %%rbx                  \n\t"
                        "pushf                              \n\t"
                        // Start circle add from 1st limb
                    "1:                                     \n\t"
                        "popf                               \n\t"
                        "movq    (%[y], %%rbx, 8), %%rax    \n\t"
                        "adcq    %%rax, (%[x], %%rbx, 8)    \n\t"
                        "pushf                              \n\t"
                        "inc %%rbx                          \n\t"
                        "cmp %%rbx, %[limbs]                \n\t"
                        "jne 1b                             \n\t"
                        "popf                               \n\t"
                        // If was carry, we always need sub mod
                        "jc 3f                              \n\t"

                        // Else check result with mod
                        "movq %[limbs], %%rbx               \n\t"
                    "2:                                     \n\t"
                        "movq    -8(%[mod], %%rbx, 8), %%rax  \n\t"
                        "cmpq    %%rax, -8(%[x], %%rbx, 8)  \n\t"
                        "jb  5f                             \n\t"
                        "ja  3f                             \n\t"
                        "dec %%rbx                          \n\t"
                        "jnz 2b                              \n\t"
                        // Start sub
                    "3:                                     \n\t"
                        "movq    (%[mod]), %%rax            \n\t"
                        "subq    %%rax, (%[x])              \n\t"
                        "pushf                              \n\t"
                        "movq $1, %%rbx                     \n\t"
                        // Loop for sub
                    "4:                                     \n\t"
                        "popf                               \n\t"
                        "movq    (%[mod], %%rbx, 8), %%rax  \n\t"
                        "sbbq    %%rax, (%[x], %%rbx, 8)    \n\t"
                        "pushf                              \n\t"
                        "inc %%rbx                          \n\t"
                        "cmp %%rbx, %[limbs]                \n\t"
                        "jne 4b                             \n\t"
                        "popf                               \n\t"
                    "5:                                     \n\t"
                        :
                        : [limbs] "r"(n), [x] "r"(x), [y] "r"(y), [mod] "r"(mod)
                        : "cc", "memory", "%rax", "%rcx", "%rbx");
                }
#endif
            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif    //_MULTIPRECISION_BARRETT_PARAMS_HPP
