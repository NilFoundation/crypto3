//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_XTEA_POLICY_HPP
#define CRYPTO3_XTEA_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/xtea/xtea_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct xtea_policy : xtea_functions<32> {
                    constexpr static const std::size_t rounds = 32;

                    constexpr static const std::size_t block_bits = 64;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t key_bits = 128;
                    constexpr static const std::size_t key_words = key_bits / word_bits;
                    typedef std::array<word_type, key_words> key_type;

                    constexpr static const std::size_t key_schedule_size = 64;
                    typedef std::array<word_type, key_schedule_size> key_schedule_type;
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MISTY1_POLICY_HPP
