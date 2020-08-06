//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PRIVATE_KEY_HPP
#define CRYPTO3_PRIVATE_KEY_HPP

#include <nil/crypto3/pubkey/public_key.hpp>

namespace nil {
    namespace crypto3 {
        template<typename Scheme>
        struct private_key : public public_key<Scheme> {
            typedef typename public_key<Scheme>::scheme_type scheme_type;
            typedef typename scheme_type::private_key_type key_policy_type;

            typedef typename public_key<Scheme>::key_type key_type;
            typedef typename public_key<Scheme>::key_schedule_type key_schedule_type;

            private_key(const key_type &key) : public_key<Scheme>(key), privkey(key) {
            }

            key_schedule_type privkey;
        };
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PRIVATE_KEY_HPP
