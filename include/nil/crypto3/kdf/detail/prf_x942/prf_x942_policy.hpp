//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_PRF_X942_POLICY_HPP
#define CRYPTO3_KDF_PRF_X942_POLICY_HPP

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename Hash>
                struct prf_x942_policy {
                    typedef Hash hash_type;
                };
            }
        }
    }
}

#endif    // CRYPTO3_HKDF_POLICY_HPP
