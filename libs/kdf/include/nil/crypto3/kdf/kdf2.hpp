//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_KDF2_HPP
#define CRYPTO3_KDF_KDF2_HPP

#include <nil/crypto3/kdf/detail/kdf2/kdf2_functions.hpp>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            /*!
             * @brief KDF2 from IEEE 1363
             * @tparam Hash
             * @ingroup kdf
             */
            template<typename Hash>
            class kdf2 {
                typedef detail::kdf2_functions<Hash> policy_type;

            public:
                typedef typename policy_type::hash_type hash_type;

                constexpr static const std::size_t secret_bits = policy_type::secret_bits;
                typedef typename policy_type::secret_type secret_type;

                constexpr static const std::size_t label_bits = policy_type::label_bits;
                typedef typename policy_type::label_type label_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                static void process() {
                    uint32_t counter = 1;
                    std::vector<uint8_t> h;

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
