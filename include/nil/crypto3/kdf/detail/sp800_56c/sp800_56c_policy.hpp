//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_SP800_56C_POLICY_HPP
#define CRYPTO3_KDF_SP800_56C_POLICY_HPP

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename MessageAuthenticationCode>
                struct sp800_56c_policy {
                    typedef MessageAuthenticationCode mac_type;

                    constexpr static const std::size_t min_key_bits = mac_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = mac_type::max_key_bits;
                    typedef typename mac_type::key_type key_type;
                };
            }
        }
    }
}

#endif    // CRYPTO3_HKDF_POLICY_HPP
