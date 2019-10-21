//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_ISO18033_FUNCTIONS_HPP
#define CRYPTO3_KDF_ISO18033_FUNCTIONS_HPP

#include <nil/crypto3/kdf/detail/kdf_iso18033/kdf_iso18033_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename Hash>
                struct kdf_iso18033_functions : public kdf_iso18033_policy<Hash> {
                    typedef kdf_iso18033_policy<Hash> policy_type;

                    typedef typename policy_type::hash_type hash_type;
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_FUNCTIONS_HPP
