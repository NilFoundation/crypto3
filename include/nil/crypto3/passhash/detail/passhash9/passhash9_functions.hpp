//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Nil Foundation AG
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PASSHASH_PASSHASH9_FUNCTIONS_HPP
#define CRYPTO3_PASSHASH_PASSHASH9_FUNCTIONS_HPP

#include <nil/crypto3/passhash/detail/passhash9/basic_passhash9_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace passhash {
            namespace detail {
                template<typename MessageAuthenticationCode, std::size_t Workfactor, typename ParamsType>
                struct passhash9_functions
                    : public basic_passhash9_policy<MessageAuthenticationCode, Workfactor, ParamsType> {
                    typedef basic_passhash9_policy<MessageAuthenticationCode, Workfactor, ParamsType> policy_type;

                    typedef typename policy_type::mac_type mac_type;
                };
            }    // namespace detail
        }        // namespace passhash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PASSHASH9_FUNCTIONS_HPP
