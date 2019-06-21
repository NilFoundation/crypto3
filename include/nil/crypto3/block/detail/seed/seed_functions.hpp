//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SEED_FUNCTIONS_CPP_HPP
#define CRYPTO3_SEED_FUNCTIONS_CPP_HPP

#include <boost/endian/arithmetic.hpp>

#include <nil/crypto3/block/detail/basic_functions.hpp>

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
                        return (s0[basic_functions<WordBits>::template extract_uint_t<CHAR_BIT>(X, 3)] ^
                                s1[basic_functions<WordBits>::template extract_uint_t<CHAR_BIT>(X, 2)] ^
                                s2[basic_functions<WordBits>::template extract_uint_t<CHAR_BIT>(X, 1)] ^
                                s3[basic_functions<WordBits>::template extract_uint_t<CHAR_BIT>(X, 0)]);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_SEED_FUNCTIONS_CPP_HPP
