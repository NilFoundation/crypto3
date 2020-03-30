//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_GOST_3411_POLICY_HPP
#define CRYPTO3_GOST_3411_POLICY_HPP

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                struct gost_3411_policy : public ::nil::crypto3::detail::basic_functions<32> {
                    constexpr static const std::size_t rounds = 32;

                    constexpr static const std::size_t word_bits = ::nil::crypto3::detail::basic_functions<32>::word_bits;
                    typedef typename ::nil::crypto3::detail::basic_functions<32>::word_type word_type;

                    constexpr static const std::size_t digest_bits = 256;
                    typedef static_digest<digest_bits> digest_type;

                    constexpr static const std::size_t block_bits = 64;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t state_bits = 256;
                    constexpr static const std::size_t state_words = state_bits / word_bits;
                    typedef std::array<word_type, state_words> state_type;
                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_GOST_3411_POLICY_HPP
