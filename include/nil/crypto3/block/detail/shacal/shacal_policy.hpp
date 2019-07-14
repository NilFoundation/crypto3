//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_CIPHERS_DETAIL_SHACAL_POLICY_HPP
#define CRYPTO3_BLOCK_CIPHERS_DETAIL_SHACAL_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/shacal/shacal_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {

                struct shacal_policy : public shacal_functions {

                    constexpr static const std::size_t block_words = 5;
                    constexpr static const std::size_t block_bits = block_words * word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t key_words = 16;
                    constexpr static const std::size_t key_bits = key_words * word_bits;
                    typedef std::array<word_type, key_words> key_type;

                    static const std::size_t rounds = 80;
                    typedef std::array<word_type, rounds> schedule_type;
                    typedef std::array<word_type, rounds> constants_type;

                    constexpr static constants_type const constants = {{
                        0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
                        0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
                        0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,

                        0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
                        0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
                        0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,

                        0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
                        0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
                        0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,

                        0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
                        0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
                        0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
                    }};
                };

                constexpr shacal_policy::constants_type const shacal_policy::constants;

                typedef shacal_policy shacal0_policy;

            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_CIPHERS_DETAIL_SHACAL_POLICY_HPP
