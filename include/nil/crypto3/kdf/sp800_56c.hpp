//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_SP800_56C_HPP
#define CRYPTO3_KDF_SP800_56C_HPP

#include <nil/crypto3/kdf/detail/sp800_56c/sp800_56c_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            /*!
             * @brief NIST SP 800-56C KDF
             * @tparam MessageAuthenticationCode
             * @tparam KeyDerivationFunction
             */
            template<typename MessageAuthenticationCode, typename KeyDerivationFunction>
            class sp800_56c {
                typedef detail::sp800_56c_functions<MessageAuthenticationCode> policy_type;

            public:
                typedef MessageAuthenticationCode mac_type;
                typedef KeyDerivationFunction kdf_type;

                constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                typedef typename policy_type::key_type key_type;

                static void process(const key_type &key) {
                    secure_vector<uint8_t> k_dk;

                    m_prf->set_key(salt, salt_len);
                    m_prf->update(secret, secret_len);
                    m_prf->final(k_dk);

                    // Key Expansion
                    m_exp->kdf(key, key_len, k_dk.data(), k_dk.size(), nullptr, 0, label, label_len);

                    return key_len;
                }
            };
        }    // namespace kdf
    }    // namespace crypto3
}    // namespace nil

#endif
