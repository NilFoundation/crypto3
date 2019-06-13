//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_NOP_FINALIZER_HPP
#define CRYPTO3_NOP_FINALIZER_HPP

namespace nil {
    namespace crypto3 {
        namespace hash {
            struct nop_finalizer {
                template<typename T>
                void operator()(T &) {
                }
            };
        }
    }
}

#endif //CRYPTO3_NOP_FINALIZER_HPP
