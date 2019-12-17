//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_KDF2_HPP
#define CRYPTO3_KDF_KDF2_HPP

#include <nil/crypto3/kdf/detail/kdf2/kdf2_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            /*!
             * @brief KDF2 from IEEE 1363
             * @tparam Hash
             */
            template<typename Hash>
            class kdf2 {
                typedef detail::kdf2_functions<Hash> policy_type;

            public:
                typedef typename policy_type::hash_type hash_type;

                static void process() {
                    uint32_t counter = 1;
                    secure_vector<uint8_t> h;

                    size_t offset = 0;
                    while (offset != key_len && counter != 0) {
                        m_hash->update(secret, secret_len);
                        m_hash->update_be(counter++);
                        m_hash->update(label, label_len);
                        m_hash->update(salt, salt_len);
                        m_hash->final(h);

                        const size_t added = std::min(h.size(), key_len - offset);
                        copy_mem(&key[offset], h.data(), added);
                        offset += added;
                    }

                    return offset;
                }
            };
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil

#endif
