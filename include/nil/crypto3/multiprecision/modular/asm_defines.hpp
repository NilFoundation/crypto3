////---------------------------------------------------------------------------//
//// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
////
//// Distributed under the Boost Software License, Version 1.0
//// See accompanying file LICENSE_1_0.txt or copy at
//// http://www.boost.org/LICENSE_1_0.txt
////---------------------------------------------------------------------------//
//
//#ifndef BOOST_MULTIPRECISION_ASM_DEFINES_HPP
//#define BOOST_MULTIPRECISION_ASM_DEFINES_HPP
//
//#define STR_HELPER(x) #x
//#define STR(x) STR_HELPER(x)
//
///* addq is faster than adcq, even if preceded by clc */
//#define SUB_FIRSTSUB            \
//    "movq    (%[B]), %%rax\n\t" \
//    "subq    %%rax, (%[A])\n\t"
//
//#define SUB_NEXTSUB(ofs) \
//    "movq    " STR(ofs) "(%[B]), %%rax\n\t"     \
//    "sbbq    %%rax, " STR(ofs) "(%[A])\n\t"
//
//#define SUB_FIRSTADD              \
//    "movq    (%[mod]), %%rax\n\t" \
//    "addq    %%rax, (%[A])\n\t"
//
//#define SUB_NEXTADD(ofs) \
//    "movq    " STR(ofs) "(%[mod]), %%rax\n\t"   \
//    "adcq    %%rax, " STR(ofs) "(%[A])\n\t"
//
//#define ADD_CMP(ofs) \
//    "movq    " STR(ofs) "(%[mod]), %%rax   \n\t"      \
//    "cmpq    %%rax, " STR(ofs) "(%[A])     \n\t"      \
//    "jb      done%=              \n\t"                \
//    "ja      subtract%=          \n\t"
//
//#define ADD_FIRSTADD                       \
//    "movq    (%[B]), %%rax           \n\t" \
//    "addq    %%rax, (%[A])           \n\t"
//
//#define ADD_NEXTADD(ofs) \
//    "movq    " STR(ofs) "(%[B]), %%rax          \n\t"   \
//    "adcq    %%rax, " STR(ofs) "(%[A])          \n\t"
//
//#define ADD_FIRSTSUB                   \
//    "movq    (%[mod]), %%rax     \n\t" \
//    "subq    %%rax, (%[A])       \n\t"
//
//#define ADD_NEXTSUB(ofs) \
//    "movq    " STR(ofs) "(%[mod]), %%rax    \n\t"       \
//    "sbbq    %%rax, " STR(ofs) "(%[A])      \n\t"
//
//namespace nil {
//    namespace crypto3 {
//        namespace multiprecision {
//            namespace backends {
//                template <typename Backend1, typename Backend2, typename Number>
//                void sub_mod(size_t n, Backend1 &x, Backend2 y, Number mod) {
//                    if (n == 3)
//                    {
//                        __asm__
//                            (SUB_FIRSTSUB
//                             SUB_NEXTSUB(8)
//                             SUB_NEXTSUB(16)
//
//                             "jnc     done%=\n\t"
//
//                             SUB_FIRSTADD
//                             SUB_NEXTADD(8)
//                             SUB_NEXTADD(16)
//
//                             "done%=:\n\t"
//                             :
//                             : [A] "r" (x.limbs()), [B] "r" (y.limbs()), [mod] "r" (mod.backend().limbs())
//                             : "cc", "memory", "%rax");
//                    }
//                    else if (n == 4)
//                    {
//                        __asm__
//                            (SUB_FIRSTSUB
//                             SUB_NEXTSUB(8)
//                             SUB_NEXTSUB(16)
//                             SUB_NEXTSUB(24)
//
//                             "jnc     done%=\n\t"
//
//                             SUB_FIRSTADD
//                             SUB_NEXTADD(8)
//                             SUB_NEXTADD(16)
//                             SUB_NEXTADD(24)
//
//                             "done%=:\n\t"
//                             :
//                             : [A] "r" (x.limbs()), [B] "r" (y.limbs()), [mod] "r" (mod.backend().limbs())
//                             : "cc", "memory", "%rax");
//                    }
//                    else if (n == 5)
//                    {
//                        __asm__
//                            (SUB_FIRSTSUB
//                             SUB_NEXTSUB(8)
//                             SUB_NEXTSUB(16)
//                             SUB_NEXTSUB(24)
//                             SUB_NEXTSUB(32)
//
//                             "jnc     done%=\n\t"
//
//                             SUB_FIRSTADD
//                             SUB_NEXTADD(8)
//                             SUB_NEXTADD(16)
//                             SUB_NEXTADD(24)
//                             SUB_NEXTADD(32)
//
//                             "done%=:\n\t"
//                             :
//                             : [A] "r" (x.limbs()), [B] "r" (y.limbs()), [mod] "r" (mod.backend().limbs())
//                             : "cc", "memory", "%rax");
//                    }
//                }
//
//                template <typename Backend1, typename Backend2, typename Number>
//                void add_mod(size_t n, Backend1 &x, Backend2 y, Number mod) {
//                    if (n == 3) {
//                        __asm__
//                            ("/* perform bignum addition */   \n\t"
//                             ADD_FIRSTADD
//                             ADD_NEXTADD(8)
//                             ADD_NEXTADD(16)
//                             "/* if overflow: subtract     */ \n\t"
//                             "/* (tricky point: if A and B are in the range we do not need to do anything special for the possible carry flag) */ \n\t"
//                             "jc      subtract%=              \n\t"
//
//                             "/* check for overflow */        \n\t"
//                             ADD_CMP(16)
//                             ADD_CMP(8)
//                             ADD_CMP(0)
//                             "/* subtract mod if overflow */  \n\t"
//                             "subtract%=:                     \n\t"
//                             ADD_FIRSTSUB
//                             ADD_NEXTSUB(8)
//                             ADD_NEXTSUB(16)
//                             "done%=:                         \n\t"
//                             :
//                             : [A] "r" (x.limbs()), [B] "r" (y.limbs()), [mod] "r" (mod.backend().limbs())
//                             : "cc", "memory", "%rax");
//                    }
//                    if (n == 4) {
//                        __asm__
//                        ("/* perform bignum addition */   \n\t"
//                         ADD_FIRSTADD
//                         ADD_NEXTADD(8)
//                         ADD_NEXTADD(16)
//                         ADD_NEXTADD(24)
//                         "/* if overflow: subtract     */ \n\t"
//                         "/* (tricky point: if A and B are in the range we do not need to do anything special for the possible carry flag) */ \n\t"
//                         "jc      subtract%=              \n\t"
//
//                         "/* check for overflow */        \n\t"
//                         ADD_CMP(24)
//                         ADD_CMP(16)
//                         ADD_CMP(8)
//                         ADD_CMP(0)
//
//                         "/* subtract mod if overflow */  \n\t"
//                         "subtract%=:                     \n\t"
//                         ADD_FIRSTSUB
//                         ADD_NEXTSUB(8)
//                         ADD_NEXTSUB(16)
//                         ADD_NEXTSUB(24)
//                         "done%=:                         \n\t"
//                         :
//                         : [A] "r" (x.limbs()), [B] "r" (y.limbs()), [mod] "r" (mod.backend().limbs())
//                         : "cc", "memory", "%rax");
//                    }
//                    if (n == 5)
//                    {
//                        __asm__
//                            ("/* perform bignum addition */   \n\t"
//                             ADD_FIRSTADD
//                             ADD_NEXTADD(8)
//                             ADD_NEXTADD(16)
//                             ADD_NEXTADD(24)
//                             ADD_NEXTADD(32)
//                             "/* if overflow: subtract     */ \n\t"
//                             "/* (tricky point: if A and B are in the range we do not need to do anything special for the possible carry flag) */ \n\t"
//                             "jc      subtract%=              \n\t"
//
//                             "/* check for overflow */        \n\t"
//                             ADD_CMP(32)
//                             ADD_CMP(24)
//                             ADD_CMP(16)
//                             ADD_CMP(8)
//                             ADD_CMP(0)
//
//                             "/* subtract mod if overflow */  \n\t"
//                             "subtract%=:                     \n\t"
//                             ADD_FIRSTSUB
//                             ADD_NEXTSUB(8)
//                             ADD_NEXTSUB(16)
//                             ADD_NEXTSUB(24)
//                             ADD_NEXTSUB(32)
//                             "done%=:                         \n\t"
//                             :
//                             : [A] "r" (x.limbs()), [B] "r" (y.limbs()), [mod] "r" (mod.backend().limbs())
//                             : "cc", "memory", "%rax");
//                    }
//                }
//            }    // namespace backends
//        }        // namespace multiprecision
//    }            // namespace crypto3
//}    // namespace nil
//
//#endif    //_MULTIPRECISION_BARRETT_PARAMS_HPP
