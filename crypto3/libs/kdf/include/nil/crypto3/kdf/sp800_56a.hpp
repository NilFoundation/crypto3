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

#ifndef CRYPTO3_KDF_SP800_56A_HPP
#define CRYPTO3_KDF_SP800_56A_HPP

#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/mac/hmac.hpp>

#include <nil/crypto3/kdf/detail/sp800_56a/sp800_56a_policy.hpp>

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            /*!
             * @brief KDF defined in NIST SP 800-56a revision 2 (Single-step key-derivation function)
             * @tparam Construction
             * @ingroup kdf
             */
            template<typename Construction, typename = void>
            class sp800_56a { };

            /*!
             * @brief Hash version of SP 800-56a KDF.
             * @tparam Hash
             * @ingroup kdf
             */
            template<typename Hash>
            class sp800_56a<Hash, typename std::enable_if<is_hash<Hash>::value>::type> {
            public:
                typedef Hash hash_type;
            };

            /*!
             * @brief MAC version of SP 800-56a KDF.
             * @tparam MessageAuthenticationCode
             * @ingroup kdf
             */
            template<typename MessageAuthenticationCode>
            class sp800_56a<MessageAuthenticationCode,
                            typename std::enable_if<is_mac<MessageAuthenticationCode>::value>::type> {
                typedef detail::sp800_56a_policy<MessageAuthenticationCode> policy_type;

            public:
                typedef typename policy_type::hash_type hash_type;
                typedef typename policy_type::mac_type mac_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                typedef typename policy_type::key_type key_type;

                sp800_56a(const salt_type &salt) : mac(salt) {
                }

                static void process(const key_type &key) {
                    const uint64_t kRepsUpperBound = (1ULL << 32U);

                    const size_t digest_len = auxfunc.output_length();

                    const size_t reps = key.size() / digest_len + ((key.size() % digest_len) ? 1 : 0);

                    if (reps >= kRepsUpperBound) {
                        // See SP-800-56A, point 5.8.1
                        throw std::invalid_argument("SP800-56A KDF requested output too large");
                    }

                    uint32_t counter = 1;
                    std::vector<uint8_t> result;
                    for (size_t i = 0; i < reps; i++) {
                        auxfunc.update_be(counter++);
                        auxfunc.update(secret, secret_len);
                        auxfunc.update(label, label_len);
                        auxfunc.final(result);

                        const size_t offset = digest_len * i;
                        const size_t len = std::min(result.size(), key_len - offset);
                        copy_mem(&key[offset], result.data(), len);
                    }

                    return key_len;
                }

            protected:
                mac_type mac;
            };

            /*!
             * @brief Strictly standard-compliant SP 800-56a version
             * @tparam Hash
             * @ingroup kdf
             */
            template<typename Hash>
            class sp800_56a<mac::hmac<Hash>, typename std::enable_if<is_mac<mac::hmac<Hash>>::value>::type> {
                typedef detail::sp800_56a_policy<mac::hmac<Hash>> policy_type;

            public:
                typedef typename policy_type::hash_type hash_type;
                typedef typename policy_type::mac_type mac_type;

                constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                typedef typename policy_type::salt_type salt_type;

                constexpr static const std::size_t min_key_bits = policy_type::min_key_bits;
                constexpr static const std::size_t max_key_bits = policy_type::max_key_bits;
                typedef typename policy_type::key_type key_type;

                sp800_56a(const salt_type &salt) : mac(salt) {
                }

                static void process(const key_type &key) {
                    mac_type mac(key);

                    const uint64_t kRepsUpperBound = (1ULL << 32U);

                    const size_t digest_len = auxfunc.output_length();

                    const size_t reps = key.size() / digest_len + ((key.size() % digest_len) ? 1 : 0);

                    if (reps >= kRepsUpperBound) {
                        // See SP-800-56A, point 5.8.1
                        throw std::invalid_argument("SP800-56A KDF requested output too large");
                    }

                    uint32_t counter = 1;
                    std::vector<uint8_t> result;
                    for (size_t i = 0; i < reps; i++) {
                        auxfunc.update_be(counter++);
                        auxfunc.update(secret, secret_len);
                        auxfunc.update(label, label_len);
                        auxfunc.final(result);

                        const size_t offset = digest_len * i;
                        const size_t len = std::min(result.size(), key_len - offset);
                        copy_mem(&key[offset], result.data(), len);
                    }

                    return key_len;
                }

            protected:
                mac_type mac;
            };
        }    // namespace kdf
    }        // namespace crypto3
}    // namespace nil

#endif
