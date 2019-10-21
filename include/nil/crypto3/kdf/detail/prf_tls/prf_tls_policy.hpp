//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_PRF_TLS_POLICY_HPP
#define CRYPTO3_KDF_PRF_TLS_POLICY_HPP

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<std::size_t Version, typename MessageAuthenticationCode1, typename MessageAuthenticationCode2>
                struct prf_tls_policy {
                    constexpr static const std::size_t version = Version;
                    typedef MessageAuthenticationCode1 mac_type1;
                    typedef MessageAuthenticationCode2 mac_type2;
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_POLICY_HPP
