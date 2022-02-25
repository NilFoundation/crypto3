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

#if defined(BOOST_ARCH_X86_64)
#if defined(CRYPTO3_HAS_AVX2)
#include <nil/crypto3/hash/detail/keccak/keccak_avx2_impl.hpp>
#else
#include <nil/crypto3/hash/detail/keccak/keccak_x86_64_impl.hpp>
#endif
#else
#if defined(CRYPTO3_HAS_ARMV8)
#include <nil/crypto3/hash/detail/keccak/keccak_armv8_impl.hpp>
#endif
#endif

#include <nil/crypto3/hash/detail/keccak/keccak_x86_64_impl.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<std::size_t DigestBits>
                struct keccak_1600_functions : public keccak_1600_policy<DigestBits> {
                    typedef keccak_1600_policy<DigestBits> policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    typedef typename policy_type::state_type state_type;

//                    typedef typename std::conditional<word_bits == 64,
//#if defined(BOOST_ARCH_X86_64)
//#if defined(CRYPTO3_HAS_AVX2)
//                                                      keccak_1600_avx2_impl<policy_type>,
//#else
//                                                      keccak_1600_x86_64_impl<policy_type>,
//#endif
//#else
//                                                      keccak_1600_impl<policy_type>,
//#endif
//                                                      keccak_1600_impl<policy_type>>::type impl_type;
                    typedef typename std::conditional<word_bits == 64, keccak_1600_avx2_impl<policy_type>, keccak_1600_avx2_impl<policy_type>>::type impl_type;

                    typedef keccak_1600_impl<policy_type> const_impl_type;

                    typedef typename impl_type::round_constants_type round_constants_type;
                    constexpr static const round_constants_type round_constants = impl_type::round_constants;
                };

                template<std::size_t DigestBits>
                constexpr typename keccak_1600_functions<DigestBits>::round_constants_type const
                    keccak_1600_functions<DigestBits>::round_constants;
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_FUNCTIONS_AVX2_IMPL_HPP
