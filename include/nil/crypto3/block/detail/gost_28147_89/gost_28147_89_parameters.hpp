//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_GOST_28147_89_PARAMETERS_HPP
#define CRYPTO3_GOST_28147_89_PARAMETERS_HPP

#include <array>

#include <boost/integer.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                struct gost_28147_89_parameters {
                    typedef uint8_t byte_type;

                    constexpr static const std::size_t parameters_size = 64;
                    typedef std::array<byte_type, parameters_size> parameters_type;
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_GOST_28147_89_POLICY_HPP
