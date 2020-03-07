//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PBKDF_PBKDF1_FUNCTIONS_HPP
#define CRYPTO3_PBKDF_PBKDF1_FUNCTIONS_HPP

#include <nil/crypto3/pbkdf/detail/pbkdf1/pbkdf1_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pbkdf {
            namespace detail {
                template<typename Hash>
                struct pkcs5_pkbdf1_functions : public pkcs5_pkbdf1_policy<Hash> {
                    typedef pkcs5_pkbdf1_policy<Hash> policy_type;

                    typedef typename policy_type::hash_type hash_type;

                    constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                    typedef typename policy_type::salt_type salt_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    typedef typename policy_type::digest_type digest_type;
                };
            }    // namespace detail
        }        // namespace pbkdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PBKDF1_FUNCTIONS_HPP
