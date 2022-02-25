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
#include <immintrin.h>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename PolicyType>
                struct keccak_1600_avx2_impl {
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
                        __asm__(
                            "1:\n\t"
                            ////////////////////////////////////////// Theta
                            "eor	%%x26,[%[A], #0],[%[A], #40]\n\t"
                            "stp	[%[A], #32],[%[A], #72],[sp,#0]\n\t"
                            "eor	%%x27,[%[A], #8],[%[A], #48]"
                            "eor	%%x28,[%[A], #16]],[%[A], #56]\n\t"
                            "eor	%%x29,[%[A], #24]],[%[A], #64]\n\t"

                            "eor	%%x30,[%[A], #32],[%[A], #72]\n\t"
                            "eor	%%x26,%%x26,[%[A], #80]\n\t"
                            "eor	%%x27,%%x27,[%[A], #88]\n\t"
                            "eor	%%x28,%%x28,[%[A], #96]\n\t"
                            "eor	%%x29,%%x29,[%[A], #104]\n\t"
                            "eor	%%x30,%%x30,[%[A], #112]\n\t"
                            "eor	%%x26,%%x26,[%[A], #120]\n\t"
                            "eor	%%x27,%%x27,[%[A], #128]\n\t"
                            "eor	%%x28,%%x28,[%[A], #136]\n\t"
                            "eor	%%x29,%%x29,[%[A], #144]\n\t"
                            "eor	%%x30,%%x30,[%[A], #152]\n\t"
                            "eor	%%x26,%%x26,[%[A], #160]\n\t"
                            "eor	%%x28,%%x28,[%[A], #176]\n\t"
                            "eor	%%x27,%%x27,[%[A], #168]\n\t"
                            "eor	%%x29,%%x29,[%[A], #184]\n\t"
                            "eor	%%x30,%%x30,[%[A], #192]\n\t"
                            "eor	$C[5],%%x26,%%x28,ror#63\n\t"
                            "eor	[%[A], #8],[%[A], #8],$C[5]\n\t"
                            "eor	[%[A], #48],[%[A], #48],$C[5]\n\t"
                            "eor	[%[A], #88],[%[A], #88],$C[5]\n\t"
                            "eor	[%[A], #128],[%[A], #128],$C[5]\n\t"
                            "eor	[%[A], #168],[%[A], #168],$C[5]\n\t"
                            "eor	$C[5],%%x27,%%x29,ror#63\n\t"
                            "eor	%%x28,%%x28,%%x30,ror#63\n\t"
                            "eor	%%x29,%%x29,%%x26,ror#63\n\t"
                            "eor	%%x30,%%x30,%%x27,ror#63\n\t"
                            "eor	%%x27,   [%[A], #16]],$C[5]\n\t"
                            "eor	[%[A], #56],[%[A], #56],$C[5]\n\t"
                            "eor	[%[A], #96],[%[A], #96],$C[5]\n\t"
                            "eor	[%[A], #136],[%[A], #136],$C[5]\n\t"
                            "eor	[%[A], #176],[%[A], #176],$C[5]\n\t"
                            "eor	[%[A], #0],[%[A], #0],%%x30\n\t"
                            "eor	[%[A], #40],[%[A], #40],%%x30\n\t"
                            "eor	[%[A], #80],[%[A], #80],%%x30\n\t"
                            "eor	[%[A], #120],[%[A], #120],%%x30\n\t"
                            "eor	[%[A], #160],[%[A], #160],%%x30\n\t"

                            "ldp	[%[A], #32],[%[A], #72],[sp,#0]\n\t"
                            "eor	%%x26, [%[A], #24]],%%x28  \n\t"
                            "eor	[%[A], #64],[%[A], #64],%%x28\n\t"
                            "eor	[%[A], #104],[%[A], #104],%%x28\n\t"
                            "eor	[%[A], #144],[%[A], #144],%%x28\n\t"
                            "eor	[%[A], #184],[%[A], #184],%%x28\n\t"
                            "eor	%%x28, [%[A], #32],%%x29  \n\t"
                            "eor	[%[A], #72],[%[A], #72],%%x29\n\t"
                            "eor	[%[A], #112],[%[A], #112],%%x29\n\t"
                            "eor	[%[A], #152],[%[A], #152],%%x29\n\t"
                            "eor	[%[A], #192],[%[A], #192],%%x29\n\t"

                            "mov	%%x29,[%[A], #8]\n\t"
                            "ror	[%[A], #8],[%[A], #48],#20\n\t"
                            "ror	[%[A], #16]],[%[A], #96],#21\n\t"
                            "ror	[%[A], #24]],[%[A], #144],#43\n\t"
                            "ror	[%[A], #32],[%[A], #192],#50\n\t"
                            "ror	[%[A], #48],[%[A], #72],#44\n\t"
                            "ror	[%[A], #96],[%[A], #104],#39\n\t"
                            "ror	[%[A], #144],[%[A], #136],#49\n\t"
                            "ror	[%[A], #192],[%[A], #168],#62\n\t"
                            "ror	[%[A], #72],[%[A], #176],#3\n\t"
                            "ror	[%[A], #104],[%[A], #152],#56\n\t"
                            "ror	[%[A], #136],[%[A], #88],#54\n\t"
                            "ror	[%[A], #168],[%[A], #64],#9\n\t"
                            "ror	[%[A], #176],[%[A], #112],#25\n\t"
                            "ror	[%[A], #152],[%[A], #184],#8\n\t"
                            "ror	[%[A], #88],[%[A], #56],#58\n\t"
                            "ror	[%[A], #64],[%[A], #128],#19\n\t"
                            "ror	[%[A], #112],[%[A], #160],#46\n\t"
                            "ror	[%[A], #184],[%[A], #120],#23\n\t"
                            "ror	[%[A], #56],[%[A], #80],#61\n\t"
                            "ror	[%[A], #128],[%[A], #40],#28\n\t"
                            "ror	[%[A], #40],%%x26,#36\n\t"
                            "ror	[%[A], #80],%%x29,#63\n\t"
                            "ror	[%[A], #120],%%x28,#37\n\t"
                            "ror	[%[A], #160],%%x27,#2\n\t"

                            "bic	%%x26,[%[A], #16]],[%[A], #8]\n\t"
                            "bic	%%x27,[%[A], #24]],[%[A], #16]]\n\t"
                            "bic	%%x28,[%[A], #0],[%[A], #32]\n\t"
                            "bic	%%x29,[%[A], #8],[%[A], #0]\n\t"
                            "eor	[%[A], #0],[%[A], #0],%%x26\n\t"
                            "bic	%%x26,[%[A], #32],[%[A], #24]]\n\t"
                            "eor	[%[A], #8],[%[A], #8],%%x27\n\t"
                            "ldr	%%x27,[sp,#16]\n\t"
                            "eor	[%[A], #24]],[%[A], #24]],%%x28\n\t"
                            "eor	[%[A], #32],[%[A], #32],%%x29\n\t"
                            "eor	[%[A], #16]],[%[A], #16]],%%x26\n\t"
                            "ldr	%%x29,[%%x27],#8\n\t"
                            "bic	%%x26,[%[A], #56],[%[A], #48]\n\t"
//                            "tst	%%x27,#255\n\t"
//                            "str	%%x27,[sp,#16]\n\t"
                            "bic	%%x27,[%[A], #64],[%[A], #56]\n\t"
                            "bic	%%x28,[%[A], #40],[%[A], #72]\n\t"
                            "eor	[%[A], #0],[%[A], #0],%%x29\n\t"
                            "bic	%%x29,[%[A], #48],[%[A], #40]\n\t"
                            "eor	[%[A], #40],[%[A], #40],%%x26\n\t"
                            "bic	%%x26,[%[A], #72],[%[A], #64]\n\t"
                            "eor	[%[A], #48],[%[A], #48],%%x27\n\t"
                            "eor	[%[A], #64],[%[A], #64],%%x28\n\t"
                            "eor	[%[A], #72],[%[A], #72],%%x29\n\t"
                            "eor	[%[A], #56],[%[A], #56],%%x26\n\t"
                            "bic	%%x26,[%[A], #96],[%[A], #88]\n\t"
                            "bic	%%x27,[%[A], #104],[%[A], #96]\n\t"
                            "bic	%%x28,[%[A], #80],[%[A], #112]\n\t"
                            "bic	%%x29,[%[A], #88],[%[A], #80]\n\t"
                            "eor	[%[A], #80],[%[A], #80],%%x26\n\t"
                            "bic	%%x26,[%[A], #112],[%[A], #104]\n\t"
                            "eor	[%[A], #88],[%[A], #88],%%x27\n\t"
                            "eor	[%[A], #104],[%[A], #104],%%x28\n\t"
                            "eor	[%[A], #112],[%[A], #112],%%x29\n\t"
                            "eor	[%[A], #96],[%[A], #96],%%x26\n\t"
                            "bic	%%x26,[%[A], #136],[%[A], #128]\n\t"
                            "bic	%%x27,[%[A], #144],[%[A], #136]\n\t"
                            "bic	%%x28,[%[A], #120],[%[A], #152]\n\t"
                            "bic	%%x29,[%[A], #128],[%[A], #120]\n\t"
                            "eor	[%[A], #120],[%[A], #120],%%x26\n\t"
                            "bic	%%x26,[%[A], #152],[%[A], #144]\n\t"
                            "eor	[%[A], #128],[%[A], #128],%%x27\n\t"
                            "eor	[%[A], #144],[%[A], #144],%%x28\n\t"
                            "eor	[%[A], #152],[%[A], #152],%%x29\n\t"
                            "eor	[%[A], #136],[%[A], #136],%%x26\n\t"
                            "bic	%%x26,[%[A], #176],[%[A], #168]\n\t"
                            "bic	%%x27,[%[A], #184],[%[A], #176]\n\t"
                            "bic	%%x28,[%[A], #160],[%[A], #192]\n\t"
                            "bic	%%x29,[%[A], #168],[%[A], #160]\n\t"
                            "eor	[%[A], #160],[%[A], #160],%%x26\n\t"
                            "bic	%%x26,[%[A], #192],[%[A], #184]\n\t"
                            "eor	[%[A], #168],[%[A], #168],%%x27\n\t"
                            "eor	[%[A], #184],[%[A], #184],%%x28\n\t"
                            "eor	[%[A], #192],[%[A], #192],%%x29\n\t"
                            "eor	[%[A], #176],[%[A], #176],%%x26\n\t"
//                            "bne	1b\n\t"

                            : 
                            : [A] "r" (A.begin()), [rounds] "r"(round_constants_size), [c] "r"(round_constants.begin())
                            : "cc", "memory", "%x26", "%x27", "%x28", "%x29", "%x30" // C0, C1, C2, C3
                        );
                    }
                };

                template<typename PolicyType>
                constexpr typename keccak_1600_avx2_impl<PolicyType>::round_constants_type const
                    keccak_1600_avx2_impl<PolicyType>::round_constants;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_ARMV8_IMPL_HPP
