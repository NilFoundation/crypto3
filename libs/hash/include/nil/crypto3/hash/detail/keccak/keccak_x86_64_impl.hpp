//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software "and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, "and/or sell
// copies of the Software, "and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright "notice "and this permission "notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT "not LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE "and NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KECCAK_X86_64_IMPL_HPP
#define CRYPTO3_KECCAK_X86_64_IMPL_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename PolicyType>
                struct keccak_1600_x86_64_impl {
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
                        std::array<word_type, 10> C;
                        std::array<word_type, 25> B;
#if defined(_MSC_VER)
                        for (std::size_t i = 0; i < 24; ++i) {
                            // Calculate C
                            for (std::size_t x = 0; x < 5; ++x) {
                                C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
                            }

                            // Calculate D
                            for (std::size_t x = 0; x < 5; ++x) {
                                C[x + 5] = _rotl64(C[(x + 1) % 5], 1) ^ C[(x + 4) % 5];
                            }

                            // Apply D to A
                            for (std::size_t x = 0; x < 5; ++x) {
                                for (std::size_t y = 0; y < 5; ++y) {
                                    A[x + 5 * y] ^= C[x + 5];
                                }
                            }

                            // rho and pi steps
                            static constexpr std::array<int, 25> rho_offsets = {
                                0, 1, 62, 28, 27,
                                36, 44, 6, 55, 20,
                                3, 10, 43, 25, 39,
                                41, 45, 15, 21, 8,
                                18, 2, 61, 56, 14
                            };

                            for (std::size_t x = 0; x < 5; ++x) {
                                for (std::size_t y = 0; y < 5; ++y) {
                                    B[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(A[x + 5 * y], rho_offsets[x + 5 * y]);
                                }
                            }

                            // chi step
                            for (std::size_t y = 0; y < 5; ++y) {
                                for (std::size_t x = 0; x < 5; ++x) {
                                    A[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
                                }
                            }

                            // iota step
                            A[0] ^= round_constants[i];
                        }
#else
                        __asm__(
                            "mov $24, %%r13 \n\t"
                            "1:\n\t"

                            "mov (%[A]), %%r15\n\t"
                            "xor 40(%[A]), %%r15\n\t"
                            "xor 80(%[A]), %%r15\n\t"
                            "xor 120(%[A]), %%r15\n\t"
                            "xor 160(%[A]), %%r15\n\t"
                            "mov %%r15, (%[C]) \n\t"
                            "mov %%r15, %%r8 \n\t"

                            "mov 8(%[A]), %%r15\n\t"
                            "xor 48(%[A]), %%r15\n\t"
                            "xor 88(%[A]), %%r15\n\t"
                            "xor 128(%[A]), %%r15\n\t"
                            "xor 168(%[A]), %%r15\n\t"
                            "mov %%r15, 8(%[C]) \n\t"
                            "mov %%r15, %%r9 \n\t"

                            "mov 16(%[A]), %%r15\n\t"
                            "xor 56(%[A]), %%r15\n\t"
                            "xor 96(%[A]), %%r15\n\t"
                            "xor 136(%[A]), %%r15\n\t"
                            "xor 176(%[A]), %%r15\n\t"
                            "mov %%r15, 16(%[C]) \n\t"
                            "mov %%r15, %%r10 \n\t"

                            "mov 24(%[A]), %%r15\n\t"
                            "xor 64(%[A]), %%r15\n\t"
                            "xor 104(%[A]), %%r15\n\t"
                            "xor 144(%[A]), %%r15\n\t"
                            "xor 184(%[A]), %%r15\n\t"
                            "mov %%r15, 24(%[C]) \n\t"
                            "mov %%r15, %%r11 \n\t"

                            "mov 32(%[A]), %%r15\n\t"
                            "xor 72(%[A]), %%r15\n\t"
                            "xor 112(%[A]), %%r15\n\t"
                            "xor 152(%[A]), %%r15\n\t"
                            "xor 192(%[A]), %%r15\n\t"
                            "mov %%r15, 32(%[C]) \n\t"
                            "mov %%r15, %%r12 \n\t"
                            // Calculate D
                            "rol $1, %%r8\n\t"
                            "xor 24(%[C]), %%r8\n\t"
                            "rol $1, %%r9\n\t"
                            "xor 32(%[C]), %%r9\n\t"
                            "rol $1, %%r10\n\t"
                            "xor (%[C]), %%r10\n\t"
                            "rol $1, %%r11\n\t"
                            "xor 8(%[C]), %%r11\n\t"
                            "rol $1, %%r12\n\t"
                            "xor 16(%[C]), %%r12\n\t"
                            // Calculate B
                            "mov (%[A]), %%r15 \n\t"
                            "xor %%r9, %%r15 \n\t"
                            "rol $0, %%r15 \n\t"
                            "mov %%r15, (%[B]) \n\t"

                            "mov 8(%[A]), %%r15 \n\t"
                            "xor %%r10, %%r15 \n\t"
                            "rol $1, %%r15 \n\t"
                            "mov %%r15, 80(%[B]) \n\t"

                            "mov 16(%[A]), %%r15 \n\t"
                            "xor %%r11, %%r15 \n\t"
                            "rol $62, %%r15 \n\t"
                            "mov %%r15, 160(%[B]) \n\t"

                            "mov 24(%[A]), %%r15 \n\t"
                            "xor %%r12, %%r15 \n\t"
                            "rol $28, %%r15 \n\t"
                            "mov %%r15, 40(%[B]) \n\t"

                            "mov 32(%[A]), %%r15 \n\t"
                            "xor %%r8, %%r15 \n\t"
                            "rol $27, %%r15 \n\t"
                            "mov %%r15, 120(%[B]) \n\t"
                            // end a4

                            "mov 40(%[A]), %%r15 \n\t"
                            "xor %%r9, %%r15 \n\t"
                            "rol $36, %%r15 \n\t"
                            "mov %%r15, 128(%[B]) \n\t"

                            "mov 48(%[A]), %%r15 \n\t"
                            "xor %%r10, %%r15 \n\t"
                            "rol $44, %%r15 \n\t"
                            "mov %%r15, 8(%[B]) \n\t"

                            "mov 56(%[A]), %%r15 \n\t"
                            "xor %%r11, %%r15 \n\t"
                            "rol $6, %%r15 \n\t"
                            "mov %%r15, 88(%[B]) \n\t"

                            "mov 64(%[A]), %%r15 \n\t"
                            "xor %%r12, %%r15 \n\t"
                            "rol $55, %%r15 \n\t"
                            "mov %%r15, 168(%[B]) \n\t"

                            "mov 72(%[A]), %%r15 \n\t"
                            "xor %%r8, %%r15 \n\t"
                            "rol $20, %%r15 \n\t"
                            "mov %%r15, 48(%[B]) \n\t"
                            // end a9

                            "mov 80(%[A]), %%r15 \n\t"
                            "xor %%r9, %%r15 \n\t"
                            "rol $3, %%r15 \n\t"
                            "mov %%r15, 56(%[B]) \n\t"

                            "mov 88(%[A]), %%r15 \n\t"
                            "xor %%r10, %%r15 \n\t"
                            "rol $10, %%r15 \n\t"
                            "mov %%r15, 136(%[B]) \n\t"

                            "mov 96(%[A]), %%r15 \n\t"
                            "xor %%r11, %%r15 \n\t"
                            "rol $43, %%r15 \n\t"
                            "mov %%r15, 16(%[B]) \n\t"

                            "mov 104(%[A]), %%r15 \n\t"
                            "xor %%r12, %%r15 \n\t"
                            "rol $25, %%r15 \n\t"
                            "mov %%r15, 96(%[B]) \n\t"

                            "mov 112(%[A]), %%r15 \n\t"
                            "xor %%r8, %%r15 \n\t"
                            "rol $39, %%r15 \n\t"
                            "mov %%r15, 176(%[B]) \n\t"
                            // end a14

                            "mov 120(%[A]), %%r15 \n\t"
                            "xor %%r9, %%r15 \n\t"
                            "rol $41, %%r15 \n\t"
                            "mov %%r15, 184(%[B]) \n\t"

                            "mov 128(%[A]), %%r15 \n\t"
                            "xor %%r10, %%r15 \n\t"
                            "rol $45, %%r15 \n\t"
                            "mov %%r15, 64(%[B]) \n\t"

                            "mov 136(%[A]), %%r15 \n\t"
                            "xor %%r11, %%r15 \n\t"
                            "rol $15, %%r15 \n\t"
                            "mov %%r15, 144(%[B]) \n\t"

                            "mov 144(%[A]), %%r15 \n\t"
                            "xor %%r12, %%r15 \n\t"
                            "rol $21, %%r15 \n\t"
                            "mov %%r15, 24(%[B]) \n\t"

                            "mov 152(%[A]), %%r15 \n\t"
                            "xor %%r8, %%r15 \n\t"
                            "rol $8, %%r15 \n\t"
                            "mov %%r15, 104(%[B]) \n\t"
                            // end a19

                            "mov 160(%[A]), %%r15 \n\t"
                            "xor %%r9, %%r15 \n\t"
                            "rol $18, %%r15 \n\t"
                            "mov %%r15, 112(%[B]) \n\t"

                            "mov 168(%[A]), %%r15 \n\t"
                            "xor %%r10, %%r15 \n\t"
                            "rol $2, %%r15 \n\t"
                            "mov %%r15, 192(%[B]) \n\t"

                            "mov 176(%[A]), %%r15 \n\t"
                            "xor %%r11, %%r15 \n\t"
                            "rol $61, %%r15 \n\t"
                            "mov %%r15, 72(%[B]) \n\t"

                            "mov 184(%[A]), %%r15 \n\t"
                            "xor %%r12, %%r15 \n\t"
                            "rol $56, %%r15 \n\t"
                            "mov %%r15, 152(%[B]) \n\t"

                            "mov 192(%[A]), %%r15 \n\t"
                            "xor %%r8, %%r15 \n\t"
                            "rol $14, %%r15 \n\t"
                            "mov %%r15, 32(%[B]) \n\t"
                            // end a24
                            // Start calculate ending A
                            "mov 8(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 16(%[B]), %%r15 \n\t"
                            "xor (%[B]), %%r15 \n\t"
                            "xor (%[c]), %%r15\n\t"
                            "mov %%r15, (%[A]) \n\t"

                            "mov 16(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 24(%[B]), %%r15 \n\t"
                            "xor 8(%[B]), %%r15 \n\t"
                            "mov %%r15, 8(%[A]) \n\t"

                            "mov 24(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 32(%[B]), %%r15 \n\t"
                            "xor 16(%[B]), %%r15 \n\t"
                            "mov %%r15, 16(%[A]) \n\t"

                            "mov 32(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and (%[B]), %%r15 \n\t"
                            "xor 24(%[B]), %%r15 \n\t"
                            "mov %%r15, 24(%[A]) \n\t"
                            // a4
                            "mov (%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 8(%[B]), %%r15 \n\t"
                            "xor 32(%[B]), %%r15 \n\t"
                            "mov %%r15, 32(%[A]) \n\t"

                            "mov 48(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 56(%[B]), %%r15 \n\t"
                            "xor 40(%[B]), %%r15 \n\t"
                            "mov %%r15, 40(%[A]) \n\t"

                            "mov 56(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 64(%[B]), %%r15 \n\t"
                            "xor 48(%[B]), %%r15 \n\t"
                            "mov %%r15, 48(%[A]) \n\t"

                            "mov 64(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 72(%[B]), %%r15 \n\t"
                            "xor 56(%[B]), %%r15 \n\t"
                            "mov %%r15, 56(%[A]) \n\t"
                            // a8
                            "mov 72(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 40(%[B]), %%r15 \n\t"
                            "xor 64(%[B]), %%r15 \n\t"
                            "mov %%r15, 64(%[A]) \n\t"

                            "mov 40(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 48(%[B]), %%r15 \n\t"
                            "xor 72(%[B]), %%r15 \n\t"
                            "mov %%r15, 72(%[A]) \n\t"

                            "mov 88(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 96(%[B]), %%r15 \n\t"
                            "xor 80(%[B]), %%r15 \n\t"
                            "mov %%r15, 80(%[A]) \n\t"

                            "mov 96(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 104(%[B]), %%r15 \n\t"
                            "xor 88(%[B]), %%r15 \n\t"
                            "mov %%r15, 88(%[A]) \n\t"
                            // a12
                            "mov 104(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 112(%[B]), %%r15 \n\t"
                            "xor 96(%[B]), %%r15 \n\t"
                            "mov %%r15, 96(%[A]) \n\t"

                            "mov 112(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 80(%[B]), %%r15 \n\t"
                            "xor 104(%[B]), %%r15 \n\t"
                            "mov %%r15, 104(%[A]) \n\t"

                            "mov 80(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 88(%[B]), %%r15 \n\t"
                            "xor 112(%[B]), %%r15 \n\t"
                            "mov %%r15, 112(%[A]) \n\t"

                            "mov 128(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 136(%[B]), %%r15 \n\t"
                            "xor 120(%[B]), %%r15 \n\t"
                            "mov %%r15, 120(%[A]) \n\t"
                            // a16
                            "mov 136(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 144(%[B]), %%r15 \n\t"
                            "xor 128(%[B]), %%r15 \n\t"
                            "mov %%r15, 128(%[A]) \n\t"

                            "mov 144(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 152(%[B]), %%r15 \n\t"
                            "xor 136(%[B]), %%r15 \n\t"
                            "mov %%r15, 136(%[A]) \n\t"

                            "mov 152(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 120(%[B]), %%r15 \n\t"
                            "xor 144(%[B]), %%r15 \n\t"
                            "mov %%r15, 144(%[A]) \n\t"

                            "mov 120(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 128(%[B]), %%r15 \n\t"
                            "xor 152(%[B]), %%r15 \n\t"
                            "mov %%r15, 152(%[A]) \n\t"
                            // a20
                            "mov 168(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 176(%[B]), %%r15 \n\t"
                            "xor 160(%[B]), %%r15 \n\t"
                            "mov %%r15, 160(%[A]) \n\t"

                            "mov 176(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 184(%[B]), %%r15 \n\t"
                            "xor 168(%[B]), %%r15 \n\t"
                            "mov %%r15, 168(%[A]) \n\t"

                            "mov 184(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 192(%[B]), %%r15 \n\t"
                            "xor 176(%[B]), %%r15 \n\t"
                            "mov %%r15, 176(%[A]) \n\t"

                            "mov 192(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 160(%[B]), %%r15 \n\t"
                            "xor 184(%[B]), %%r15 \n\t"
                            "mov %%r15, 184(%[A]) \n\t"

                            "mov 160(%[B]), %%r15 \n\t"
                            "not %%r15 \n\t"
                            "and 168(%[B]), %%r15 \n\t"
                            "xor 192(%[B]), %%r15 \n\t"
                            "mov %%r15, 192(%[A]) \n\t"
                            // a24

                            "lea 8(%[c]), %[c]\n\t"
                            "dec %%r13 \n\t"
                            "jnz 1b \n\t"
                            :
                            :
                            [A] "r"(A.begin()), [C] "r"(C.begin()), [B] "r"(B.begin()), [c] "r"(round_constants.begin())
                            : "cc", "memory", "%r8", "%r9", "%r10", "%r11", "%r12",    // D0, D1, D2, D3, D4
                              "%r13",                                                  // Circle
                              "%r15"                                                   // tmp
                        );
#endif
                    }
                };

                template<typename PolicyType>
                constexpr typename keccak_1600_x86_64_impl<PolicyType>::round_constants_type const
                    keccak_1600_x86_64_impl<PolicyType>::round_constants;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_X86_64_IMPL_HPP
