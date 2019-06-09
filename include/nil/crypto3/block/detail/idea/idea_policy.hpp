//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_IDEA_POLICY_HPP
#define CRYPTO3_IDEA_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/idea/idea_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct idea_policy : idea_functions<16> {
                    constexpr static const std::size_t rounds = 8;

                    constexpr static const std::size_t block_bits = 64;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t key_bits = 128;
                    constexpr static const std::size_t key_words = key_bits / word_bits;
                    typedef std::array<word_type, key_words> key_type;

                    constexpr static const std::size_t key_schedule_size = 52;
                    typedef std::array<word_type, key_schedule_size> key_schedule_type;
                };
            }
        }
    }
}

#endif //CRYPTO3_IDEA_POLICY_HPP
