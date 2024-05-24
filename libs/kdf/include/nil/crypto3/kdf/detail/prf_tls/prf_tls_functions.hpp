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

#ifndef CRYPTO3_KDF_PRF_TLS_FUNCTIONS_HPP
#define CRYPTO3_KDF_PRF_TLS_FUNCTIONS_HPP

#include <nil/crypto3/kdf/detail/prf_tls/prf_tls_policy.hpp>

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<std::size_t Version, typename MessageAuthenticationCode1, typename MessageAuthenticationCode2>
                struct prf_tls_functions
                    : public prf_tls_policy<Version, MessageAuthenticationCode1, MessageAuthenticationCode2> {
                    typedef prf_tls_policy<Version, MessageAuthenticationCode1, MessageAuthenticationCode2> policy_type;

                    constexpr static const std::size_t version = policy_type::version;
                    typedef typename policy_type::mac_type1 mac_type1;
                    typedef typename policy_type::mac_type2 mac_type2;

                    template<typename MessageAuthenticationCode>
                    static void p_hash(uint8_t out[], size_t out_len, MessageAuthenticationCode &mac,
                                       const uint8_t salt[], size_t salt_len) {
                        std::vector<uint8_t> A(salt, salt + salt_len);
                        std::vector<uint8_t> h;

                        size_t offset = 0;

                        while (offset != out_len) {
                            A = mac.process(A);

                            mac.update(A);
                            mac.update(salt, salt_len);
                            mac.final(h);

                            const size_t writing = std::min(h.size(), out_len - offset);
                            xor_buf(&out[offset], h.data(), writing);
                            offset += writing;
                        }
                    }
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_FUNCTIONS_HPP
