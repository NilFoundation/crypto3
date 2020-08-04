//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_BLS_HPP
#define CRYPTO3_PUBKEY_BLS_HPP

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename CurveType>
            struct bls_public_key {
                typedef CurveType curve_type;
            };

            template<typename CurveType>
            struct bls_private_key {
                typedef CurveType curve_type;
            };

            template<typename CurveType>
            struct bls {
                typedef CurveType curve_type;

                typedef bls_public_key<curve_type> public_key_type;
                typedef bls_private_key<curve_type> private_key_type;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif
