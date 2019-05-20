//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SEED_FUNCTIONS_CPP_HPP
#define CRYPTO3_SEED_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/basic_functions.hpp>

#include <nil/crypto3/utilities/loadstore.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t WordBits>
                struct seed_functions : public basic_functions<WordBits> {
                    typedef typename basic_functions<WordBits>::word_type word_type;

                    constexpr static const std::size_t constants_size = 256;
                    typedef std::array<word_type, constants_size> constants_type;

                    inline static word_type g(word_type X, const constants_type &s0, const constants_type &s1,
                                              const constants_type &s2, const constants_type &s3) {
                        return (s0[get_byte(3, X)] ^ s1[get_byte(2, X)] ^ s2[get_byte(1, X)] ^ s3[get_byte(0, X)]);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_SEED_FUNCTIONS_CPP_HPP
