//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_KECCAK_FUNCTIONS_AVX2_IMPL_HPP
#define CRYPTO3_KECCAK_FUNCTIONS_AVX2_IMPL_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>
#include <nil/crypto3/hash/detail/keccak/keccak_impl.hpp>

#if BOOST_ARCH_X86_64
    #if defined(CRYPTO3_HAS_AVX512)
        #include <nil/crypto3/hash/detail/keccak/keccak_avx512_impl.hpp>
    #else
        #if defined(CRYPTO3_HAS_AVX2)
            #include <nil/crypto3/hash/detail/keccak/keccak_avx2_impl.hpp>
        #else
            #include <nil/crypto3/hash/detail/keccak/keccak_x86_64_impl.hpp>
        #endif
    #endif
#elif BOOST_ARCH_ARM
    #if defined(__ARM_ARCH_8A__) || defined(__aarch64__)
        #include <nil/crypto3/hash/detail/keccak/keccak_armv8_impl.hpp>
    #else
        #if defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
            #include <nil/crypto3/hash/detail/keccak/keccak_armv7_impl.hpp>
            //#error "Unsupported ARM7 LOL"
        #else
            #error "Unsupported ARM architecture"
        #endif
    #endif
#endif

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<std::size_t DigestBits>
                struct keccak_1600_functions : public keccak_1600_policy<DigestBits> {
                    typedef keccak_1600_policy<DigestBits> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    typedef typename policy_type::block_type block_type;

                    typedef typename policy_type::state_type state_type;

                    typedef typename std::conditional<word_bits == 64,
#if BOOST_ARCH_X86_64
#if defined(CRYPTO3_HAS_AVX512)
                                                      keccak_1600_avx512_impl<policy_type>,
#else
#if defined(CRYPTO3_HAS_AVX2)
                                                      keccak_1600_avx2_impl<policy_type>,
#else
                                                      keccak_1600_x86_64_impl<policy_type>,
#endif
#endif
#elif BOOST_ARCH_ARM && BOOST_ARCH_ARM >= BOOST_VERSION_NUMBER(8, 0, 0)
                                                      keccak_1600_armv8_impl<policy_type>,
#else
                                                      keccak_1600_impl<policy_type>,
#endif
                    
                    
                    keccak_1600_impl<policy_type>>::type impl_type;

                    typedef keccak_1600_impl<policy_type> const_impl_type;

                    typedef typename impl_type::round_constants_type round_constants_type;
                    constexpr static const round_constants_type round_constants = impl_type::round_constants;

                    static void absorb(const block_type& block, state_type& state) {
                        for (std::size_t i = 0; i < block.size(); ++i) {
                            // XOR
                            state[i] ^= block[i];
                        }
                    }
                };

                template<std::size_t DigestBits>
                constexpr typename keccak_1600_functions<DigestBits>::round_constants_type const
                    keccak_1600_functions<DigestBits>::round_constants;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_FUNCTIONS_AVX2_IMPL_HPP
