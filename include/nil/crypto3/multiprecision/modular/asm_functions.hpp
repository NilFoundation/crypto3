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
                template <typename Backend1, typename Backend2, typename Number>
                void sub_mod(size_t n, Backend1 &x, Backend2 y, Number mod) {
                    __asm__(
                        "movq    %[limbs], %%rcx\n\t"
                        "movq    $1, %%rbx\n\t"

                        "movq    (%[y]), %%rax\n\t"
                        "subq    %%rax, (%[x])\n\t"
                        "pushf\n\t"
                    "1:\n\t"
                        "popf\n\t"
                        "movq    (%[y], %%rbx, 8), %%rax\n\t"
                        "sbbq    %%rax, (%[x], %%rbx, 8)\n\t"
                        "pushf\n\t"
                        "inc %%rbx\n\t"
                        "cmp %%rbx, %%rcx\n\t"
                        "jne 1b\n\t"
                        "popf\n\t"
                        "jnc     4f\n\t"
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
                        : [limbs] "r"(n), [x] "r"(x.limbs()), [y] "r"(y.limbs()), [mod] "r"(mod.backend().limbs())
                        : "cc", "memory", "%rax", "%rcx", "%rbx");
                }

                template <typename Backend1, typename Backend2, typename Number>
                void add_mod(size_t n, Backend1 &x, Backend2 y, Number mod) {
                    __asm__(
                        "movq    (%[y]), %%rax\n\t"
                        "addq    %%rax, (%[x])\n\t"
                        "movq    %[limbs], %%rcx\n\t"
                        "movq    $1, %%rbx\n\t"
                        "pushf\n\t"
                    "1:\n\t"
                        "popf\n\t"
                        "movq    (%[y], %%rbx, 8), %%rax\n\t"
                        "adcq    %%rax, (%[x], %%rbx, 8)\n\t"
                        "pushf\n\t"
                        "inc %%rbx\n\t"
                        "cmp %%rbx, %%rcx\n\t"
                    "jne 1b\n\t"
                        "popf\n\t"
                        "jc 3f\n\t"
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

                    "3:\n\t"
                        "movq    (%[mod]), %%rax\n\t"
                        "subq    %%rax, (%[x])\n\t"
                        "pushf\n\t"

                        "movq $1, %%rbx\n\t"
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
