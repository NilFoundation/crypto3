//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_AGREEMENT_KEY_HPP
#define CRYPTO3_AGREEMENT_KEY_HPP

#include <nil/crypto3/pubkey/private_key.hpp>

namespace nil {
    namespace crypto3 {
        template<typename Scheme>
        struct agreement_key : public private_key<Scheme> {
            typedef typename private_key<Scheme>::scheme_type scheme_type;
            typedef typename Scheme::key_agreement_policy key_policy_type;
        };
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PRIVATE_KEY_HPP
