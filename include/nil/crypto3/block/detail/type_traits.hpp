//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_TYPE_TRAITS_HPP
#define CRYPTO3_TYPE_TRAITS_HPP

#include <type_traits>
#include <iterator>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<typename T>
                class is_stream_encrypter {
                    typedef char yes;
                    typedef long no;

                    template<typename C>
                    static yes check(typename C::digest_type *);

                    template<typename C>
                    static no check(...);

                public:
                    enum {
                        value = sizeof(check<T>(0)) == sizeof(yes)
                    };
                };
            }
        }
    }
}

#endif //CRYPTO3_TYPE_TRAITS_HPP
