//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KASUMI_FUNCTIONS_CPP_HPP
#define CRYPTO3_KASUMI_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/kasumi/kasumi_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct kasumi_functions : public kasumi_policy {
                    constexpr static const std::size_t word_bits = kasumi_policy::word_bits;
                    typedef typename kasumi_policy::word_type word_type;

                    static inline word_type FI(word_type I, word_type K) {
                        word_type D9 = (I >> 7);
                        word_type D7 = (I & 0x7F);
                        D9 = s9_substitution[D9] ^ D7;
                        D7 = s7_substitution[D7] ^ (D9 & 0x7F);

                        D7 ^= (K >> 9);
                        D9 = s9_substitution[D9 ^ (K & 0x1FF)] ^ D7;
                        D7 = s7_substitution[D7] ^ (D9 & 0x7F);
                        return static_cast<word_type>(D7 << 9) | D9;
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KASUMI_FUNCTIONS_CPP_HPP
