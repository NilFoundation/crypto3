//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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
// @file This particular header is responsible for defining current architecture's
// (the architecture the library being compiled for) properties such as amount of
// bits target machine CPU's machine word is being represented with.
// This particular header is a pretty temporary one, and is present in Crypto3 library
// until following PR's are not accepted: https://github.com/boostorg/predef/pull/108,
// https://github.com/boostorg/predef/pull/107.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_PREDEF_HPP
#define CRYPTO3_DETAIL_PREDEF_HPP

#include <boost/predef/architecture.h>

#if defined(BOOST_ARCH_ALPHA_AVAILABLE) && defined(BOOST_ARCH_ALPHA_NAME)
#define BOOST_ARCH_ALPHA_WORD_BITS 64
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_ALPHA_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_ALPHA_WORD_BITS
#elif defined(BOOST_ARCH_ARM_AVAILABLE) && defined(BOOST_ARCH_ARM_NAME)
#if defined(__ARM_ARCH) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(_M_ARM) ||          \
    defined(__arm__) || defined(__arm64) || defined(__thumb__) || defined(_M_ARM64) || defined(__aarch64__) ||       \
    defined(__AARCH64EL__) || defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) ||     \
    defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6KZ__) || \
    defined(__ARM_ARCH_6T2__) || defined(__ARM_ARCH_5TE__) || defined(__ARM_ARCH_5TEJ__) ||                          \
    defined(__ARM_ARCH_4T__) || defined(__ARM_ARCH_4__)
#if !defined(BOOST_ARCH_ARM) && \
    (defined(__arm64) || defined(_M_ARM64) || defined(__aarch64__) || defined(__AARCH64EL__))
#define BOOST_ARCH_ARM_WORD_BITS 64
#endif
#if !defined(BOOST_ARCH_ARM) && \
    (defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__))
#define BOOST_ARCH_ARM_WORD_BITS 32
#endif
#if !defined(BOOST_ARCH_ARM) && \
    (defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6KZ__) || defined(__ARM_ARCH_6T2__))
#define BOOST_ARCH_ARM_WORD_BITS 32
#endif
#if !defined(BOOST_ARCH_ARM) && (defined(__ARM_ARCH_5TE__) || defined(__ARM_ARCH_5TEJ__))
#define BOOST_ARCH_ARM_WORD_BITS 32
#endif
#if !defined(BOOST_ARCH_ARM) && (defined(__ARM_ARCH_4T__) || defined(__ARM_ARCH_4__))
#define BOOST_ARCH_ARM_WORD_BITS 32
#endif
#endif
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_ARM_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_ARM_WORD_BITS
#elif defined(BOOST_ARCH_BLACKFIN_AVAILABLE) && defined(BOOST_ARCH_BLACKFIN_NAME)
#define BOOST_ARCH_BLACKFIN_WORD_BITS 16
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_BLACKFIN_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_BLACKFIN_WORD_BITS
#elif defined(BOOST_ARCH_CONVEX_AVAILABLE) && defined(BOOST_ARCH_CONVEX_NAME)
#define BOOST_ARCH_CONVEX_WORD_BITS 32
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_CONVEX_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_CONVEX_WORD_BITS
#elif defined(BOOST_ARCH_IA64_AVAILABLE) && defined(BOOST_ARCH_IA64_NAME)
#define BOOST_ARCH_IA64_WORD_BITS 64
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_IA64_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_IA64_WORD_BITS
#elif defined(BOOST_ARCH_M68K_AVAILABLE) && defined(BOOST_ARCH_M68K_NAME)
#define BOOST_ARCH_M68K_WORD_BITS 32
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_M68K_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_M68K_WORD_BITS
#elif defined(BOOST_ARCH_MIPS_AVAILABLE) && defined(BOOST_ARCH_MIPS_NAME)
#if defined(__mips__) || defined(__mips) || defined(__MIPS__)
#if !defined(BOOST_ARCH_MIPS) && (defined(_MIPS_ISA_MIPS1) || defined(_R3000))
#define BOOST_ARCH_MIPS_WORD_BITS 32
#endif
#if !defined(BOOST_ARCH_MIPS) && (defined(_MIPS_ISA_MIPS2) || defined(__MIPS_ISA2__) || defined(_R4000))
#define BOOST_ARCH_MIPS_WORD_BITS 32
#endif
#if !defined(BOOST_ARCH_MIPS) && (defined(_MIPS_ISA_MIPS3) || defined(__MIPS_ISA3__))
#define BOOST_ARCH_MIPS_WORD_BITS 64
#endif
#if !defined(BOOST_ARCH_MIPS) && (defined(_MIPS_ISA_MIPS4) || defined(__MIPS_ISA4__))
#define BOOST_ARCH_MIPS_WORD_BITS 64
#endif
#endif
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_MIPS_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_MIPS_WORD_BITS
#elif defined(BOOST_ARCH_PARISC_AVAILABLE) && defined(BOOST_ARCH_PARISC_NAME)
#define BOOST_ARCH_PARISC_WORD_BITS 32
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_PARISC_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_PARISC_WORD_BITS
#elif defined(BOOST_ARCH_PPC_AVAILABLE) && defined(BOOST_ARCH_PPC_NAME)
#if defined(__powerpc) || defined(__powerpc__) || defined(__POWERPC__) || defined(__ppc__) || defined(_M_PPC) || \
    defined(_ARCH_PPC) || defined(__PPCGECKO__) || defined(__PPCBROADWAY__) || defined(_XENON)
#if !defined(BOOST_ARCH_PPC) && (defined(__ppc601__) || defined(_ARCH_601))
#define BOOST_ARCH_PPC_WORD_BITS 32
#endif
#if !defined(BOOST_ARCH_PPC) && (defined(__ppc603__) || defined(_ARCH_603))
#define BOOST_ARCH_PPC_WORD_BITS 32
#endif
#if !defined(BOOST_ARCH_PPC) && (defined(__ppc604__) || defined(__ppc604__))
#define BOOST_ARCH_PPC_WORD_BITS 32
#endif
#endif
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_PPC_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_PPC_WORD_BITS
#elif defined(BOOST_ARCH_PTX_AVAILABLE) && defined(BOOST_ARCH_PTX_NAME)
#define BOOST_ARCH_PTX_WORD_BITS 64
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_PTX_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_PTX_WORD_BITS
#elif defined(BOOST_ARCH_PYRAMID_AVAILABLE) && defined(BOOST_ARCH_PYRAMID_NAME)
#define BOOST_ARCH_PYRAMID_WORD_BITS 32
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_PYRAMID_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_PYRAMID_WORD_BITS
#elif defined(BOOST_ARCH_RISCV_AVAILABLE) && defined(BOOST_ARCH_RISCV_NAME)
#define BOOST_ARCH_RISCV_WORD_BITS 32
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_RISCV_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_RISCV_WORD_BITS
#elif defined(BOOST_ARCH_RS6K_AVAILABLE) && defined(BOOST_ARCH_RS6K_NAME)
#define BOOST_ARCH_PWR BOOST_ARCH_RS6000
#define BOOST_ARCH_PWR_NAME BOOST_ARCH_RS6000_NAME
#define BOOST_ARCH_PWR_WORD_BITS 32
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_RS6K_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_RS6K_WORD_BITS
#elif defined(BOOST_ARCH_SPARC_AVAILABLE) && defined(BOOST_ARCH_SPARC_NAME)
#if defined(__sparc__) || defined(__sparc)
#undef BOOST_ARCH_SPARC
#if !defined(BOOST_ARCH_SPARC) && defined(__sparcv9)
#define BOOST_ARCH_SPARC_WORD_BITS 64
#endif
#if !defined(BOOST_ARCH_SPARC) && defined(__sparcv8)
#define BOOST_ARCH_SPARC_WORD_BITS 32
#endif
#endif
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_SPARC_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_SPARC_WORD_BITS
#elif defined(BOOST_ARCH_SUPERH_AVAILABLE) && defined(BOOST_ARCH_SUPERH_NAME)
#if defined(__sh__)
#undef BOOST_ARCH_SH
#if !defined(BOOST_ARCH_SH) && (defined(__SH5__))
#define BOOST_ARCH_SH_WORD_BITS 64
#endif
#if !defined(BOOST_ARCH_SH) && (defined(__SH4__))
#define BOOST_ARCH_SH_WORD_BITS 32
#endif
#if !defined(BOOST_ARCH_SH) && (defined(__sh3__) || defined(__SH3__))
#define BOOST_ARCH_SH_WORD_BITS 32
#endif
#if !defined(BOOST_ARCH_SH) && (defined(__sh2__))
#define BOOST_ARCH_SH_WORD_BITS 16
#endif
#if !defined(BOOST_ARCH_SH) && (defined(__sh1__))
#define BOOST_ARCH_SH_WORD_BITS 16
#endif
#endif
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_SUPERH_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_SUPERH_WORD_BITS
#elif defined(BOOST_ARCH_SYS370_AVAILABLE) && defined(BOOST_ARCH_SYS370_NAME)
#define BOOST_ARCH_SYS370_WORD_BITS 32
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_SYS370_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_SYS370_WORD_BITS
#elif defined(BOOST_ARCH_SYS390_AVAILABLE) && defined(BOOST_ARCH_SYS390_NAME)
#define BOOST_ARCH_SYS390_WORD_BITS 32
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_SYS390_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_SYS390_WORD_BITS
#elif defined(BOOST_ARCH_X86_AVAILABLE) && defined(BOOST_ARCH_X86_NAME)
#define BOOST_ARCH_X86_32_WORD_BITS 32
#define BOOST_ARCH_X86_64_WORD_BITS 64
#if defined(BOOST_ARCH_x86_32)
#define BOOST_ARCH_X86_WORD_BITS BOOST_ARCH_X86_32_WORD_BITS
#define BOOST_ARCH_X86_NAME BOOST_ARCH_X86_32_NAME
#elif defined(BOOST_ARCH_X86_64)
#define BOOST_ARCH_X86_WORD_BITS BOOST_ARCH_X86_64_WORD_BITS
#endif
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_X86_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_X86_WORD_BITS
#elif defined(BOOST_ARCH_Z_AVAILABLE) && defined(BOOST_ARCH_Z_NAME)
#define BOOST_ARCH_Z_WORD_BITS 64
#define BOOST_ARCH_CURRENT_NAME BOOST_ARCH_Z_NAME
#define BOOST_ARCH_CURRENT_WORD_BITS BOOST_ARCH_Z_WORD_BITS
#endif

#endif    // CRYPTO3_PREDEF_HPP
