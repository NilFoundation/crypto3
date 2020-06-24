//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_NOEKEON_POLICY_HPP
#define CRYPTO3_NOEKEON_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/noekeon/noekeon_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct noekeon_policy : noekeon_functions<32> {
                    constexpr static const std::size_t rounds = 16;

                    constexpr static const std::size_t block_bits = 128;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t key_bits = 128;
                    constexpr static const std::size_t key_words = block_bits / word_bits;
                    typedef std::array<word_type, key_words> key_type;

                    constexpr static const std::size_t key_schedule_size = 4;
                    typedef std::array<word_type, key_schedule_size> key_schedule_type;

                    typedef std::array<byte_type, rounds + 1> constants_type;
                    constexpr static const constants_type round_constants = {0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB,
                                                                             0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63,
                                                                             0xC6, 0x97, 0x35, 0x6A, 0xD4};
                };

                constexpr typename noekeon_policy::constants_type const noekeon_policy::round_constants;
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_NOEKEON_POLICY_HPP
