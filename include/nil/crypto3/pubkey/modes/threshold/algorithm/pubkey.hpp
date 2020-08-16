//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_ALGORITHM_HPP
#define CRYPTO3_PUBKEY_ALGORITHM_HPP

#include <cstdint>

#include <nil/crypto3/pubkey/detail/modes/isomorphic.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            /*!
             * @brief
             * @tparam Cipher
             */
            template<typename Scheme>
            struct nop_padding {
                typedef std::size_t size_type;

                typedef Scheme scheme_type;
            };
        }    // namespace pubkey

        /*!
         * @defgroup pubkey Public Key Schemes
         *
         * @brief
         *
         * @defgroup pubkey_algorithms Algorithms
         * @ingroup pubkey
         * @brief Algorithms are meant to provide scheme operations interfaces
         * similar to STL algorithms' one.
         */
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_HPP
