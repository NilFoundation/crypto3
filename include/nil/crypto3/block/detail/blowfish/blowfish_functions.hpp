//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOWFISH_FUNCTIONS_CPP_HPP
#define CRYPTO3_BLOWFISH_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/basic_functions.hpp>

#include <nil/crypto3/utilities/loadstore.hpp>
#include <nil/crypto3/utilities/secmem.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t WordBits>
                struct blowfish_functions : public basic_functions<WordBits> {
                    typedef typename basic_functions<WordBits>::word_type word_type;

                    constexpr static const std::size_t constants_size = 256;
                    typedef std::array<word_type, constants_size> constants_type;

                    constexpr static const std::size_t plain_constants_size = constants_size * 4;
                    typedef std::array<word_type, plain_constants_size> plain_constants_type;

                    inline static word_type bff(word_type X, const plain_constants_type &constants) {
                        return ((constants[get_byte(0, X)] + constants[256 + get_byte(1, X)]) ^
                                constants[512 + get_byte(2, X)]) + constants[768 + get_byte(3, X)];
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_BLOWFISH_FUNCTIONS_CPP_HPP
