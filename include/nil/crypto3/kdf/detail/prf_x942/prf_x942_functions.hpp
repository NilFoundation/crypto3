//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_PRF_X942_FUNCTIONS_HPP
#define CRYPTO3_KDF_PRF_X942_FUNCTIONS_HPP

#include <nil/crypto3/kdf/detail/prf_x942/prf_x942_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename Hash>
                struct prf_x942_functions : public prf_x942_policy<Hash> {
                    typedef prf_x942_policy<Hash> policy_type;

                    typedef typename policy_type::hash_type hash_type;

                    std::vector<uint8_t> encode_x942_int(uint32_t n) {
                        uint8_t n_buf[4] = {0};
                        store_be(n, n_buf);
                        return der_encoder().encode(n_buf, 4, OCTET_STRING).get_contents_unlocked();
                    }
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_FUNCTIONS_HPP
