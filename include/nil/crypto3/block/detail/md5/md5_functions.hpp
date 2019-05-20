//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MD5_FUNCTIONS_HPP
#define CRYPTO3_MD5_FUNCTIONS_HPP

#include <nil/crypto3/block/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct md5_functions : public basic_functions<32> {
                    static word_type ff(word_type x, word_type y, word_type z) {
                        return (x & y) | (~x & z);
                    }

                    static word_type gg(word_type x, word_type y, word_type z) {
                        return (x & z) | (y & ~z);
                        // return F(z, x, y);
                    }

                    static word_type hh(word_type x, word_type y, word_type z) {
                        return x ^ y ^ z;
                    }

                    static word_type ii(word_type x, word_type y, word_type z) {
                        return y ^ (x | ~z);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_MD5_FUNCTIONS_HPP
