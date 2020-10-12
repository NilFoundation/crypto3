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

#ifndef CRYPTO3_KDF_HKDF_FUNCTIONS_HPP
#define CRYPTO3_KDF_HKDF_FUNCTIONS_HPP

#include <nil/crypto3/kdf/detail/hkdf/hkdf_policy.hpp>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename MessageAuthenticationCode>
                struct hkdf_functions : public hkdf_policy<MessageAuthenticationCode> {
                    typedef hkdf_policy<MessageAuthenticationCode> policy_type;
                    typedef typename policy_type::mac_type mac_type;

                    constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                    typedef typename policy_type::salt_type salt_type;

                    constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                    constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                    typedef typename policy_type::key_type key_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    typedef typename policy_type::digest_type digest_type;

                    /*!
                     * @brief HKDF Expansion Step from RFC 5869
                     * @param mac
                     * @param key
                     */
                    static void expand(digest_type &digest, const mac_type &mac) {
                        uint8_t counter = 1;
                        std::vector<uint8_t> h;
                        size_t offset = 0;

                        while (offset != digest_bits && counter != 0) {
                            m_prf->update(h);
                            m_prf->update(label, label_len);
                            m_prf->update(salt, salt_len);
                            m_prf->update(counter++);
                            m_prf->final(h);

                            const size_t written = std::min(h.size(), digest_bits - offset);
                            copy_mem(&key[offset], h.data(), written);
                            offset += written;
                        }

                        return offset;
                    }

                    /*!
                     * @brief HKDF Extraction Step from RFC 5869
                     * @tparam SecretInputIterator
                     * @param key
                     */
                    static void extract(digest_type &digest, const mac_type &mac) {
                        std::vector<uint8_t> prk;

                        m_prf->update(secret, secret_len);
                        m_prf->final(prk);

                        const size_t written = std::min(prk.size(), digest_bits);
                        copy_mem(&key[0], prk.data(), written);
                        return written;
                    }
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_FUNCTIONS_HPP
