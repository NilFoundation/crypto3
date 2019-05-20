//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_XTEA_FUNCTIONS_CPP_HPP
#define CRYPTO3_XTEA_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t WordBits>
                struct xtea_functions : public basic_functions<WordBits> {
                    typedef typename basic_functions<WordBits>::word_type word_type;
                };
            }
        }
    }
}

#endif //CRYPTO3_MISTY1_FUNCTIONS_CPP_HPP
