//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_NOP_FINALIZER_HPP
#define CRYPTO3_HASH_NOP_FINALIZER_HPP

namespace nil {
    namespace crypto3 {
        namespace hash {
            struct nop_finalizer {
                template<typename T>
                void operator()(T &) {
                }
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_NOP_FINALIZER_HPP
