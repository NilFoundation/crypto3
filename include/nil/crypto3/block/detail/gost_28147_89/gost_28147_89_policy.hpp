//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_GOST_28147_89_POLICY_HPP
#define CRYPTO3_GOST_28147_89_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/gost_28147_89/gost_28147_89_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                /*
                 * Two rounds of GOST
                 */
#define GOST_2ROUND(N1, N2, R1, R2)   \
   do {                               \
   uint32_t T0 = N1 + key_schedule[R1];           \
   N2 ^= expanded_substitution[extract_uint_t<CHAR_BIT>(T0, 3)] |      \
         expanded_substitution[extract_uint_t<CHAR_BIT>(T0, 2)+256] |  \
         expanded_substitution[extract_uint_t<CHAR_BIT>(T0, 1)+512] |  \
         expanded_substitution[extract_uint_t<CHAR_BIT>(T0, 0)+768];   \
                                      \
   uint32_t T1 = N2 + key_schedule[R2];           \
   N1 ^= expanded_substitution[extract_uint_t<CHAR_BIT>(T1, 3)] |      \
         expanded_substitution[extract_uint_t<CHAR_BIT>(T1, 2)+256] |  \
         expanded_substitution[extract_uint_t<CHAR_BIT>(T1, 1)+512] |  \
         expanded_substitution[extract_uint_t<CHAR_BIT>(T1, 0)+768];   \
   } while(0)

                template<typename ParamsType>
                struct gost_28147_89_policy : gost_28147_89_functions<32> {
                    constexpr static const std::size_t rounds = 32;

                    constexpr static const std::size_t block_bits = 64;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t key_bits = 256;
                    constexpr static const std::size_t key_words = key_bits / word_bits;
                    typedef std::array<word_type, key_words> key_type;

                    constexpr static const std::size_t key_schedule_size = 8;
                    typedef std::array<word_type, key_schedule_size> key_schedule_type;

                    constexpr static const std::size_t expanded_substitution_size = 1024;
                    typedef std::array<byte_type, expanded_substitution_size> expanded_substitution_type;
                };
            }
        }
    }
}

#endif //CRYPTO3_GOST_28147_89_POLICY_HPP
