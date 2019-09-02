//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <nil/crypto3/codec/detail/base_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            namespace detail {
                constexpr typename basic_base_policy<32>::constants_type const basic_base_policy<32>::constants;

                constexpr typename basic_base_policy<32>::inverted_constants_type const
                    basic_base_policy<32>::inverted_constants;

                constexpr typename basic_base_policy<58>::constants_type const basic_base_policy<58>::constants;
                constexpr typename basic_base_policy<58>::inverted_constants_type const basic_base_policy<58>::inverted_constants;

                constexpr typename basic_base_policy<64>::constants_type const basic_base_policy<64>::constants;

                constexpr typename basic_base_policy<64>::inverted_constants_type const
                    basic_base_policy<64>::inverted_constants;
            }    // namespace detail
        }        // namespace codec
    }            // namespace crypto3
}    // namespace nil
