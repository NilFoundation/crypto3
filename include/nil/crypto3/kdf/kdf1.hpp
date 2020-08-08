//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_KDF1_HPP
#define CRYPTO3_KDF_KDF1_HPP

#include <nil/crypto3/kdf/detail/kdf1/kdf1_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            /*!
             * @brief KDF1, from IEEE 1363
             * @tparam Hash
             * @ingroup kdf
             */
            template<typename Hash>
            class kdf1 {
                typedef detail::kdf1_functions<Hash> policy_type;

            public:
                typedef typename policy_type::hash_type hash_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                constexpr static const std::size_t secret_bits = policy_type::secret_bits;
                typedef typename policy_type::secret_type secret_type;

                constexpr static const std::size_t label_bits = policy_type::label_bits;
                typedef typename policy_type::label_type label_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                static inline digest_type process() {
                    digest_type digest;
                    process(digest);
                    return digest;
                }

                static void process(digest_type &digest) {
                    m_hash->update(secret, secret_len);
                    m_hash->update(label, label_len);
                    m_hash->update(salt, salt_len);

                    if (key_len < m_hash->output_length()) {
                        secure_vector<uint8_t> v = m_hash->final();
                        copy_mem(key, v.data(), key_len);
                        return key_len;
                    }

                    m_hash->final(key);
                    return m_hash->output_length();
                }

            protected:
                hash_type hash;
            };
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil
#endif
