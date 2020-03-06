//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_PRF_TLS_FUNCTIONS_HPP
#define CRYPTO3_KDF_PRF_TLS_FUNCTIONS_HPP

#include <nil/crypto3/kdf/detail/prf_tls/prf_tls_policy.hpp>

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
                        secure_vector<uint8_t> A(salt, salt + salt_len);
                        secure_vector<uint8_t> h;

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
