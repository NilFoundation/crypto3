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

#ifndef CRYPTO3_KDF_SP800_56C_HPP
#define CRYPTO3_KDF_SP800_56C_HPP

#include <nil/crypto3/kdf/detail/sp800_56c/sp800_56c_functions.hpp>

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            /*!
             * @brief NIST SP 800-56C KDF
             * @tparam MessageAuthenticationCode
             * @tparam KeyDerivationFunction
             * @ingroup kdf
             */
            template<typename MessageAuthenticationCode, typename KeyDerivationFunction>
            class sp800_56c {
                typedef detail::sp800_56c_functions<MessageAuthenticationCode> policy_type;

            public:
                typedef MessageAuthenticationCode mac_type;
                typedef KeyDerivationFunction kdf_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                typedef typename policy_type::key_type key_type;

                sp800_56c(const salt_type &key) : mac(key) {
                }

                static void process(const key_type &key) {
                    std::vector<uint8_t> k_dk;

                    m_prf->set_key(salt, salt_len);
                    m_prf->update(secret, secret_len);
                    m_prf->final(k_dk);

                    // Key Expansion
                    m_exp->kdf(key, key_len, k_dk.data(), k_dk.size(), nullptr, 0, label, label_len);

                    return key_len;
                }

                mac_type mac;
            };
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil

#endif
