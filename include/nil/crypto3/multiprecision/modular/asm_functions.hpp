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
                template<typename Limb1, typename Limb2>
                void sub_only(size_t n, Limb1 *x, const Limb2 *y) {
                    __asm__(
                        "movq    (%[y]), %%rax \n\t"
                        "subq    %%rax, (%[x]) \n\t"
                        "pushf                 \n\t"
                        "movq $1, %%rbx        \n\t"
                    // Loop for sub
                    "4:\n\t"
                        "popf\n\t"
                        "movq    (%[y], %%rbx, 8), %%rax \n\t"
                        "sbbq    %%rax, (%[x], %%rbx, 8) \n\t"
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
                bool reduce_help(size_t n, size_t shift, Limb1 *res, const Limb2 *x, Limb3 inv) {
                    Limb1 k, tmp1, tmp2, tmp3;
                    bool carry = false;
                    __asm__(
                        // Else check result with mod
                        "movq   (%[res], %[shift], 8), %%rax   \n\t"
                        "mulq   %[inv]                         \n\t"
                        "movq   %%rax, %[k]                    \n\t"

                        "movq   (%[x]), %%rax                  \n\t"
                        "mulq   %[k]                           \n\t"
                        "movq   %%rax, %[tmp1]                 \n\t"
                        "movq   %%rdx, %[tmp2]                 \n\t"

                        "mov $1, %%rbx                         \n\t"
                        "1:"
                        "movq   (%[x], %%rbx, 8), %%rax        \n\t"
                        "mulq   %[k]                           \n\t"
                        "addq   %[tmp1], (%[res], %[shift], 8) \n\t"
                        "movq   $0, %[tmp1]                    \n\t"
                        "adcq   %%rax, %[tmp2]                 \n\t"
                        "adcq   %%rdx, %[tmp1]                 \n\t"
                        // swap tmp2, tmp1
                        "movq %[tmp2], %%rax                   \n\t"
                        "movq %[tmp1], %[tmp2]                 \n\t"
                        "movq %%rax, %[tmp1]                   \n\t"
                        // swap end
                        "movq $1, %%rdx                        \n\t"
                        "addq %%rdx, %[shift]                  \n\t"
                        "inc %%rbx                             \n\t"
                        "cmp %%rbx, %[limbs]                   \n\t"
                        "jne 1b                                \n\t"
                        "mov %[shift], %%rbx                   \n\t"
                        "addq   %[tmp1], (%[res], %%rbx, 8)    \n\t"
                        "adcq   %[tmp2], 8(%[res], %%rbx, 8)   \n\t"
                        "jnc 2f                                \n\t"
                        "adcq   $0, 16(%[res], %%rbx, 8)       \n\t"
                        "movb $1, %[carry]                     \n\t"
                        "2:                                    \n\t"
                        : [k] "=&r"(k), [tmp1] "=&r"(tmp1), [tmp2] "=&r"(tmp2), [carry] "=r" (carry)
                        : [limbs] "r"(n), [shift] "r"(shift), [res] "r"(res), [x] "r"(x), [inv] "r"(inv)
                        : "cc", "memory", "%rax", "%rbx", "%rdx");
                    return carry;
                }

                template<typename Limb1, typename Limb2>
                int cmp_asm(size_t n, const Limb1 *x, const Limb2 *y) {
                    int result = 0;
                    __asm__(
                        // Else check result with mod
                        "mov $0, %[res]                  \n\t"
                        "movq %[limbs], %%rbx            \n\t"
                    "1:                                  \n\t"
                        "movq  -8(%[y], %%rbx, 8), %%rax \n\t"
                        "cmpq  %%rax, -8(%[x], %%rbx, 8) \n\t"
                        "ja  3f                          \n\t"
                        "jb  2f                          \n\t"
                        "dec %%rbx                       \n\t"
                        "cmp $0, %%rbx                   \n\t"
                        "jne 1b                          \n\t"
                        "jmp 4f                          \n\t"
                        // Start sub
                        "2:                              \n\t"
                        "dec %[res]                      \n\t"
                        "jmp 4f                          \n\t"
                    "3:                                  \n\t"
                        "inc %[res]                      \n\t"
                    "4:                                  \n\t"
                        : [res] "=r"(result)
                        : [limbs] "r"(n), [x] "r"(x), [y] "r"(y)
                        : "cc", "memory", "%rax", "%rcx", "%rbx");
                    return result;
                }

                template<typename Limb1, typename Limb2, typename Limb3>
                void sub_mod(size_t n, Limb1 *x, const Limb2 *y, const Limb3 *mod) {
                    __asm__(
                        "movq    %[limbs], %%rcx \n\t"
                        "movq    $1, %%rbx       \n\t"

                        "movq    (%[y]), %%rax              \n\t"
                        "subq    %%rax, (%[x])\n\t"
                        "pushf\n\t"
                        // Start circle sub from 1st limb
                    "1:                                 \n\t"
                        "popf                           \n\t"
                        "movq    (%[y], %%rbx, 8), %%rax\n\t"
                        "sbbq    %%rax, (%[x], %%rbx, 8)\n\t"
                        "pushf\n\t"
                        "inc %%rbx\n\t"
                        "cmp %%rbx, %%rcx\n\t"
                        "jne 1b\n\t"
                        "popf\n\t"
                        // If it's more than zero (no carry bit) just go to end
                        "jnc     4f\n\t"
                        // Else add mod to result
                        "movq    (%[mod]), %%rax\n\t"
                        "addq    %%rax, (%[x])\n\t"
                        "pushf\n\t"
                        "movq    $1, %%rbx\n\t"
                        "2:\n\t"
                        "popf\n\t"
                        "movq    (%[mod], %%rbx, 8), %%rax\n\t"
                        "adcq    %%rax, (%[x], %%rbx, 8)\n\t"
                        "pushf\n\t"
                        "inc %%rbx\n\t"
                        "cmp %%rbx, %%rcx\n\t"
                        "jne 2b\n\t"
                        "popf\n\t"
                        "4:\n\t"
                        :
                        : [limbs] "r"(n), [x] "r"(x), [y] "r"(y), [mod] "r"(mod)
                        : "cc", "memory", "%rax", "%rcx", "%rbx");
                }

                template<typename Backend1, typename Backend2, typename Number>
                void add_mod(size_t n, Backend1 &x, Backend2 y, Number mod) {
                    __asm__(
                        "movq    (%[y]), %%rax\n\t"
                        "addq    %%rax, (%[x])\n\t"
                        "movq    %[limbs], %%rcx\n\t"
                        "movq    $1, %%rbx\n\t"
                        "pushf\n\t"
                        // Start circle add from 1st limb
                        "1:\n\t"
                        "popf\n\t"
                        "movq    (%[y], %%rbx, 8), %%rax\n\t"
                        "adcq    %%rax, (%[x], %%rbx, 8)\n\t"
                        "pushf\n\t"
                        "inc %%rbx\n\t"
                        "cmp %%rbx, %%rcx\n\t"
                        "jne 1b\n\t"
                        "popf\n\t"
                        // If was carry, we always need sub mod
                        "jc 3f\n\t"

                        // Else check result with mod
                        "movq %[limbs], %%rbx\n\t"
                        "dec %%rbx\n\t"
                        "2:\n\t"
                        "movq    (%[mod], %%rbx, 8), %%rax\n\t"
                        "cmpq    %%rax, (%[x], %%rbx, 8)\n\t"
                        "jb  5f\n\t"
                        "ja  3f\n\t"
                        "dec %%rbx\n\t"
                        "cmp $0, %%rbx\n\t"
                        "jl 2b\n\t"
                        // Start sub
                        "3:\n\t"
                        "movq    (%[mod]), %%rax\n\t"
                        "subq    %%rax, (%[x])\n\t"
                        "pushf\n\t"
                        "movq $1, %%rbx\n\t"
                        // Loop for sub
                        "4:\n\t"
                        "popf\n\t"
                        "movq    (%[mod], %%rbx, 8), %%rax\n\t"
                        "sbbq    %%rax, (%[x], %%rbx, 8)\n\t"
                        "pushf\n\t"
                        "inc %%rbx\n\t"
                        "cmp %%rbx, %%rcx\n\t"
                        "jne 4b\n\t"
                        "popf\n\t"
                        "5:\n\t"
                        :
                        : [limbs] "r"(n), [x] "r"(x.limbs()), [y] "r"(y.limbs()), [mod] "r"(mod.backend().limbs())
                        : "cc", "memory", "%rax", "%rcx", "%rbx");
                }
            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif    //_MULTIPRECISION_BARRETT_PARAMS_HPP
