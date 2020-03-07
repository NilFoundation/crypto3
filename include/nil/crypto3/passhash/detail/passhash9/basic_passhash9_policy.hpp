//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Nil Foundation AG
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PASSHASH_BASIC_PASSHASH9_POLICY_HPP
#define CRYPTO3_PASSHASH_BASIC_PASSHASH9_POLICY_HPP

#include <cstdlib>

namespace nil {
    namespace crypto3 {
        namespace passhash {
            namespace detail {
                template<typename MessageAuthenticationCode, std::size_t Workfactor, typename ParamsType>
                struct basic_passhash9_policy {
                    typedef MessageAuthenticationCode mac_type;
                    typedef ParamsType params_type;

                    typedef const char* prefix_type;
                    constexpr static prefix_type prefix = params_type::prefix;

                    constexpr static const std::size_t workfactor = Workfactor;
                    constexpr static const std::size_t workfactor_bits = params_type::workfactor_bits;
                    constexpr static const std::size_t workfactor_scale = params_type::workfactor_scale;

                    constexpr static const std::size_t salt_bits = params_type::salt_bits;
                    constexpr static const std::size_t algid_bits = params_type::algid_bits;
                    constexpr static const std::size_t pbkdf_output_bits = params_type::pbkdf_output_bits;
                };
            }    // namespace detail
        }        // namespace passhash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PASSHASH9_POLICY_HPP
