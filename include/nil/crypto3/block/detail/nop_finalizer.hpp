//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_NOP_FINALIZER_HPP
#define CRYPTO3_BLOCK_NOP_FINALIZER_HPP

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct nop_finalizer {
                    template<typename T>
                    void operator()(T &) {
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_NOP_FINALIZER_HPP
