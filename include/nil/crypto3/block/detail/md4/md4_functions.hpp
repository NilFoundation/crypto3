//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MD4_FUNCTIONS_HPP
#define CRYPTO3_MD4_FUNCTIONS_HPP

#include <array>

#include <nil/crypto3/block/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct md4_functions : public basic_functions<32> {
                    static word_type ff(word_type x, word_type y, word_type z) {
                        return (x & y) | (~x & z);
                    }

                    static word_type gg(word_type x, word_type y, word_type z) {
                        return (x & y) | (x & z) | (y & z);
                    }

                    static word_type hh(word_type x, word_type y, word_type z) {
                        return x ^ y ^ z;
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MD4_FUNCTIONS_HPP
