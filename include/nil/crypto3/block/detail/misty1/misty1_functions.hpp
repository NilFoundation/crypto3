//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MISTY1_FUNCTIONS_CPP_HPP
#define CRYPTO3_MISTY1_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/misty1/misty1_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct misty1_functions : public misty1_policy {
                    typedef typename misty1_policy::word_type word_type;

                    static inline word_type fi(word_type input, word_type key7, word_type key9) {
                        word_type D9 = input >> 7, D7 = input & 0x7F;
                        D9 = s9_substitution[D9] ^ D7;
                        D7 = (s7_substitution[D7] ^ key7 ^ D9) & 0x7F;
                        D9 = s9_substitution[D9 ^ key9] ^ D7;
                        return static_cast<word_type>(D7 << 9) | D9;
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MISTY1_FUNCTIONS_CPP_HPP
