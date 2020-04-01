//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SHA3_POLICY_HPP
#define CRYPTO3_SHA3_POLICY_HPP

#include <nil/crypto3/detail/basic_functions.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

#include <array>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct sha3_policy : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef ::nil::crypto3::detail::basic_functions<64> policy_type;

                    constexpr static const std::size_t digest_bits = DigestBits; 
                    typedef static_digest<digest_bits> digest_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t state_bits = 1600;
                    constexpr static const std::size_t state_words = state_bits / word_bits;
                    typedef typename std::array<word_type, state_words> state_type;

                    constexpr static const std::size_t block_bits = state_bits - 2 * digest_bits;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef typename std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t rounds = 24;

                    struct iv_generator {
                        state_type const &operator()() const {
                            static state_type const H0 = {
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                            UINT64_C(0x0000000000000000)};
                            return H0;
                        }
                    };

                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SHA3_POLICY_HPP
