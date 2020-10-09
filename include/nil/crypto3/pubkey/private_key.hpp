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

#include <type_traits>

namespace nil {
    namespace crypto3 {
        template<typename Scheme>
        struct private_key : public public_key<Scheme> {
            typedef typename public_key<Scheme>::scheme_type scheme_type;
            typedef typename scheme_type::private_key_type private_key_policy_type;
            typedef typename public_key<Scheme>::public_key_policy_type public_key_policy_type;

            typedef typename private_key_policy_type::key_type key_type;
            // typedef typename key_policy_type::key_schedule_type key_schedule_type;

            explicit private_key(const key_type &key) : privkey(key) {
                this->pubkey = public_key_policy_type::key_gen(privkey);
            }

            template<typename SeedType>
            explicit private_key(const SeedType &seed) {
                privkey = private_key_policy_type::key_gen(seed);
                this->pubkey = public_key_policy_type::key_gen(privkey);
            }

        protected:
            key_type privkey;
        };
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PRIVATE_KEY_HPP
