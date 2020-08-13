//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_EME_ENCRYPTION_PAD_HPP
#define CRYPTO3_PUBKEY_EME_ENCRYPTION_PAD_HPP

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace padding {
                /*!
                 * @brief Encoding Method for Encryption
                 * @tparam Scheme
                 * @tparam Hash
                 */
                template<typename Scheme, typename Hash>
                struct eme {
                    typedef Scheme scheme_type;
                    typedef Hash hash_type;

                    typedef typename scheme_type::key_type key_type;
                };
            }
        }
    }    // namespace crypto3
}    // namespace nil

#endif
