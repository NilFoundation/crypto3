//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_SP800_108_FUNCTIONS_HPP
#define CRYPTO3_KDF_SP800_108_FUNCTIONS_HPP

#include <nil/crypto3/kdf/detail/sp800_108/sp800_108_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename MessageAuthenticationCode, template<typename> class Mode>
                struct sp800_108_functions : public sp800_108_policy<MessageAuthenticationCode, Mode> {
                    typedef sp800_108_policy<MessageAuthenticationCode, Mode> policy_type;
                    typedef typename policy_type::mode_type mode_type;
                    typedef typename policy_type::mac_type mac_type;
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_FUNCTIONS_HPP
