//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_DETAIL_SERPENT_POLICY_HPP
#define CRYPTO3_BLOCK_DETAIL_SERPENT_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/serpent/serpent_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {

                template<std::size_t Version>
                struct basic_serpent_policy : serpent_functions<32> {
                    constexpr static const std::size_t rounds = 32;

                    constexpr static const std::size_t block_bits = 128;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t key_bits = Version;
                    constexpr static const std::size_t key_words = key_bits / word_bits;
                    typedef std::array<word_type, key_words> key_type;
                    typedef std::array<word_type, key_words + 1> key_schedule_type;

                    constexpr static const std::size_t tweak_bits = 128;
                    constexpr static const std::size_t tweak_words = tweak_bits / word_bits;
                    typedef std::array<word_type, tweak_words> tweak_type;
                    typedef std::array<word_type, tweak_words + 1> tweak_schedule_type;

                    typedef std::array<std::size_t, block_words> permutations_type;
                    typedef std::array<std::array<std::size_t, block_words / 2>, 8> rotations_type;

                    constexpr static const word_type phi = 0x9E3779B9;
                };

                template<std::size_t Version>
                struct serpent_policy;

                template<>
                struct serpent_policy<128> : basic_serpent_policy<128> {
                    typedef std::array<word_type, rounds> constants_type;
                };

                template<>
                struct serpent_policy<192> : basic_serpent_policy<192> {
                    typedef std::array<word_type, rounds> constants_type;
                };

                template<>
                struct serpent_policy<256> : basic_serpent_policy<256> {
                    typedef std::array<word_type, rounds> constants_type;
                };

            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_DETAIL_SERPENT_POLICY_HPP
