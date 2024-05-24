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

#ifndef CRYPTO3_KDF_TLS_PRF_HPP
#define CRYPTO3_KDF_TLS_PRF_HPP

#include <nil/crypto3/hash/sha1.hpp>
#include <nil/crypto3/hash/md5.hpp>

#include <nil/crypto3/mac/hmac.hpp>

#include <nil/crypto3/kdf/detail/prf_tls/prf_tls_functions.hpp>

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            /*!
             * @brief
             * @tparam Version
             * @tparam MessageAuthenticationCode1
             * @tparam MessageAuthenticationCode2
             * @ingroup kdf
             */
            template<std::size_t Version, typename MessageAuthenticationCode1, typename MessageAuthenticationCode2>
            class prf_tls { };

            /*!
             * @brief PRF used in TLS 1.0/1.1 with no MAC selection option.
             * @tparam MessageAuthenticationCode1 TLS 1.0/1.1 requires for this type to be a HMAC(SHA1).
             * @tparam MessageAuthenticationCode2 TLS 1.0/1.1 requires for this type to be a HMAC(MD5).
             * @ingroup kdf
             *
             * @note Default-defined message authentication code types are not recommended to be changed in case of
             * TLS 1.0/1.1 compatibility is required. Explicitly TLS 1.0/1.1-compliant version is defined below.
             */
            template<typename MessageAuthenticationCode1, typename MessageAuthenticationCode2>
            class prf_tls<1, MessageAuthenticationCode1, MessageAuthenticationCode2> {
                typedef detail::prf_tls_functions<1, MessageAuthenticationCode1, MessageAuthenticationCode2>
                    policy_type;

            public:
                constexpr static const std::size_t version = policy_type::version;
                typedef typename policy_type::mac_type1 mac_type1;
                typedef typename policy_type::mac_type2 mac_type2;

                constexpr static const std::size_t secret_bits = policy_type::secret_bits;
                typedef typename policy_type::secret_type secret_type;

                constexpr static const std::size_t label_bits = policy_type::label_bits;
                typedef typename policy_type::label_type label_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                prf_tls(const secret_type &secret) : mac1(secret), mac2(secret) {
                }

                static void process() {
                    const size_t S1_len = (secret_len + 1) / 2, S2_len = (secret_len + 1) / 2;
                    const uint8_t *S1 = secret;
                    const uint8_t *S2 = secret + (secret_len - S2_len);
                    std::vector<uint8_t> msg;

                    msg.reserve(label_len + salt_len);
                    msg += std::make_pair(label, label_len);
                    msg += std::make_pair(salt, salt_len);

                    policy_type::template p_hash<mac_type2>(key, key_len, mac2, msg.data(), msg.size());
                    policy_type::template p_hash<mac_type1>(key, key_len, mac1, msg.data(), msg.size());

                    return key_len;
                }

            protected:
                mac_type1 mac1;
                mac_type2 mac2;
            };

            /*!
             * @brief Explicitly TLS 1.0/1.1-compliant PRF version.
             * @ingroup kdf
             */
            template<>
            class prf_tls<1, mac::hmac<hashes::sha1>, mac::hmac<hashes::md5>> {
                typedef detail::prf_tls_functions<1, mac::hmac<hashes::sha1>, mac::hmac<hashes::md5>> policy_type;

            public:
                constexpr static const std::size_t version = policy_type::version;
                typedef typename policy_type::mac_type1 mac_type1;
                typedef typename policy_type::mac_type2 mac_type2;

                constexpr static const std::size_t secret_bits = policy_type::secret_bits;
                typedef typename policy_type::secret_type secret_type;

                constexpr static const std::size_t label_bits = policy_type::label_bits;
                typedef typename policy_type::label_type label_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                prf_tls(const secret_type &secret) : mac1(secret), mac2(secret) {
                }

                static void process() {
                    const size_t S1_len = (secret_len + 1) / 2, S2_len = (secret_len + 1) / 2;
                    const uint8_t *S1 = secret;
                    const uint8_t *S2 = secret + (secret_len - S2_len);
                    std::vector<uint8_t> msg;

                    msg.reserve(label_len + salt_len);
                    msg += std::make_pair(label, label_len);
                    msg += std::make_pair(salt, salt_len);

                    policy_type::template p_hash<mac_type2>(key, key_len, mac2, msg.data(), msg.size());
                    policy_type::template p_hash<mac_type1>(key, key_len, mac1, msg.data(), msg.size());
                    return key_len;
                }

            protected:
                mac_type1 mac1;
                mac_type2 mac2;
            };

            /*!
             * @brief PRF used in TLS 1.2
             * @tparam MessageAuthenticationCode
             * @ingroup kdf
             */
            template<typename MessageAuthenticationCode>
            class prf_tls<2, MessageAuthenticationCode, MessageAuthenticationCode> {
                typedef detail::prf_tls_functions<2, MessageAuthenticationCode, MessageAuthenticationCode> policy_type;

            public:
                constexpr static const std::size_t version = policy_type::version;
                typedef typename policy_type::mac_type1 mac_type1;
                typedef typename policy_type::mac_type2 mac_type2;

                constexpr static const std::size_t secret_bits = policy_type::secret_bits;
                typedef typename policy_type::secret_type secret_type;

                constexpr static const std::size_t label_bits = policy_type::label_bits;
                typedef typename policy_type::label_type label_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                prf_tls(const secret_type &secret) : mac(secret) {
                }

                static void process() {
                    std::vector<uint8_t> msg;

                    msg.reserve(label_len + salt_len);
                    msg += std::make_pair(label, label_len);
                    msg += std::make_pair(salt, salt_len);

                    policy_type::template P_hash<mac_type1>(key, key_len, mac, msg.data(), msg.size());
                    return key_len;
                }

            protected:
                mac_type1 mac;
            };
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil

#endif
