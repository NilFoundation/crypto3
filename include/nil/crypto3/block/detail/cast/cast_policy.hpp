//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CAST_POLICY_HPP
#define CRYPTO3_CAST_POLICY_HPP

#include <array>

#include <nil/crypto3/block/detail/cast/cast_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t Version, std::size_t KeyBits>
                struct cast_policy;

                template<std::size_t KeyBits>
                struct cast_policy<128, KeyBits> : public cast_functions<128, KeyBits> {
                    constexpr static const std::size_t rounds = cast_functions<128, KeyBits>::rounds;
                };

                template<std::size_t KeyBits>
                struct cast_policy<256, KeyBits> : public cast_functions<256, KeyBits> {
                    constexpr static const std::size_t rounds = cast_functions<256, KeyBits>::rounds;
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CAST_POLICY_HPP
