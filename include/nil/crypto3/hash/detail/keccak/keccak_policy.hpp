//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KECCAK_POLICY_HPP
#define CRYPTO3_KECCAK_POLICY_HPP

#include <nil/crypto3/hash/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                class keccak_1600_policy : public basic_functions<64> {
                    constexpr static const std::size_t word_bits = basic_functions<64>::word_bits;
                    typedef typename basic_functions<64>::word_type word_type;

                    constexpr static const std::size_t block_bits = DigestBits;
                    constexpr static const std::size_t block_words = DigestBits / word_bits;
                    typedef typename std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t rounds = 24;

                    constexpr static const std::size_t round_constants_size = rounds;
                    typedef typename std::array<word_type, round_constants_size> round_constants_type;
                    constexpr static const round_constants_type round_constants = {
                            0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
                            0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
                            0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
                            0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
                            0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
                            0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
                    };
                };
            }
        }
    }
}

#endif //CRYPTO3_KECCAK_POLICY_HPP
