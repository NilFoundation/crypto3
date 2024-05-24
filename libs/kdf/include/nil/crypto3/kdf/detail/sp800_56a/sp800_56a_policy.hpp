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

#ifndef CRYPTO3_HKDF_POLICY_HPP
#define CRYPTO3_HKDF_POLICY_HPP

#include <nil/crypto3/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            using namespace nil::crypto3::detail;

            namespace detail {
                template<typename Construction, typename = void>
                struct sp800_56a_policy { };

                template<typename Hash>
                struct sp800_56a_policy<Hash, typename std::enable_if<is_hash<Hash>::value>::type> {
                    typedef Hash hash_type;
                };

                template<typename MessageAuthenticationCode>
                struct sp800_56a_policy<MessageAuthenticationCode,
                                        typename std::enable_if<is_mac<MessageAuthenticationCode>::value>::type> {
                    typedef MessageAuthenticationCode mac_type;
                };

                template<typename Hash>
                struct sp800_56a_policy<mac::hmac<Hash>,
                                        typename std::enable_if<is_mac<mac::hmac<Hash>>::value>::type> {
                    typedef Hash hash_type;
                    typedef mac::hmac<Hash> mac_type;

                    constexpr static const std::size_t min_key_bits = 0;
                    constexpr static const std::size_t max_key_bits = 2ULL >> 32ULL;

                    constexpr static const std::size_t salt_bits = mac_type::key_bits;
                    typedef typename mac_type::key_type salt_type;
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_POLICY_HPP
