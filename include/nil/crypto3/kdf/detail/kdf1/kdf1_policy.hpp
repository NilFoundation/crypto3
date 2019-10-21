//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_KDF1_POLICY_HPP
#define CRYPTO3_KDF_KDF1_POLICY_HPP

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename Hash>
                struct kdf1_policy {
                    typedef Hash hash_type;

                    constexpr static const std::size_t digest_bits = hash_type::digest_bits;
                    typedef typename hash_type::digest_type digest_type;
                };
            }
        }
    }
}

#endif    // CRYPTO3_HKDF_POLICY_HPP
