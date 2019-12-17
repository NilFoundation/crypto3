//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_HKDF_HPP
#define CRYPTO3_KDF_HKDF_HPP

#include <nil/crypto3/kdf/detail/hkdf/hkdf_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            template<typename Hash>
            struct hmac;
        }
        namespace kdf {
            /*!
             * @brief
             * @tparam Hash
             * @tparam MessageAuthenticationCode
             */
            template<typename Hash, typename MessageAuthenticationCode = mac::hmac<Hash>>
            class hkdf {
                typedef detail::hkdf_functions<MessageAuthenticationCode> policy_type;

            public:
                typedef MessageAuthenticationCode mac_type;
                typedef Hash hash_type;

                constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                typedef typename policy_type::key_type key_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                static inline digest_type process(const key_type &key) {
                    digest_type digest;
                    compute(digest, key);
                    return digest;
                }

                static inline void process(digest_type &digest, const key_type &key) {
                    policy_type::extract(digest, secret, secret_len, salt, salt_len, nullptr, 0);
                    return policy_type::expand(digest, key, nullptr, 0, label, label_len);
                }

            protected:
                mac_type mac;
            };
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil
#endif
