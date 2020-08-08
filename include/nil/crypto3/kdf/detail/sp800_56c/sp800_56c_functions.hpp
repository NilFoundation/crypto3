//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_SP800_56C_FUNCTIONS_HPP
#define CRYPTO3_KDF_SP800_56C_FUNCTIONS_HPP

#include <nil/crypto3/kdf/detail/sp800_56c/sp800_56c_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename MessageAuthenticationCode>
                struct sp800_56c_functions : public sp800_56c_policy<MessageAuthenticationCode> {
                    typedef sp800_56c_policy<MessageAuthenticationCode> policy_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    typedef typename policy_type::key_type key_type;
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_FUNCTIONS_HPP
