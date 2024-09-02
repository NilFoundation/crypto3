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

#ifndef CRYPTO3_KDF_HKDF_HPP
#define CRYPTO3_KDF_HKDF_HPP

#include <nil/crypto3/detail/pack.hpp>

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
             * @ingroup kdf
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

                constexpr static const std::size_t secret_bits = policy_type::secret_bits;
                typedef typename policy_type::secret_type secret_type;

                constexpr static const std::size_t label_bits = policy_type::label_bits;
                typedef typename policy_type::label_type label_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;

                hkdf(const secret_type &secret, const salt_type &salt = salt_type()) :
                    extract_mac(salt.size() ? salt : [&]() -> salt_type {
                        salt_type ret;
                        ret.fill(0);
                        pack(hash_type::digest_bits, ret);
                        return ret;
                    }()),
                    expand_mac(secret) {
                }

                inline digest_type process(const key_type &key) {
                    digest_type digest;
                    compute(digest, key);
                    return digest;
                }

                inline void process(digest_type &digest, const key_type &key) {
                    policy_type::extract(digest, expand_mac, salt, salt_len, nullptr, 0);
                    policy_type::expand(digest, extract_mac);
                }

            protected:
                mac_type extract_mac, expand_mac;
            };
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil
#endif
