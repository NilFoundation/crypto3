//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBLIC_KEY_HPP
#define CRYPTO3_PUBLIC_KEY_HPP

namespace nil {
    namespace crypto3 {
        template<typename Scheme>
        class public_key {
            typedef Scheme scheme_type;
            typedef typename scheme_type::public_key_type key_policy_type;

            typedef typename scheme_type::key_type key_type;
            typedef typename scheme_type::key_schedule_type key_schedule_type;

            public_key(const key_type &key) : pubkey(key) {
            }

        protected:
            key_schedule_type pubkey;
        };
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBLIC_KEY_HPP
