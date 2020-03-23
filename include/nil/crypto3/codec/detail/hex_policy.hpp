//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HEX_POLICY_HPP
#define CRYPTO3_HEX_POLICY_HPP

#include <array>

#include <boost/integer.hpp>

#include <nil/crypto3/detail/inline_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            namespace mode {
                struct upper {
                    typedef const char *constants_type;
                    CRYPTO3_INLINE_VARIABLE(constants_type, constants, ("0123456789ABCDEF"));
                };

                struct lower {
                    typedef const char *constants_type;
                    CRYPTO3_INLINE_VARIABLE(constants_type, constants, ("0123456789abcdef"));
                };
            }    // namespace mode

            namespace detail {
                template<typename Mode>
                struct hex_policy {
                    typedef Mode mode_type;

                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    typedef typename mode_type::constants_type constants_type;
                    CRYPTO3_INLINE_VARIABLE(constants_type, constants, (mode_type::constants()));
                    constexpr static const std::size_t decoded_value_bits = CHAR_BIT;
                    typedef byte_type decoded_value_type;

                    constexpr static const std::size_t encoded_value_bits = CHAR_BIT;
                    typedef byte_type encoded_value_type;

                    constexpr static const std::size_t decoded_block_values = 1;
                    constexpr static const std::size_t decoded_block_bits = decoded_value_bits * decoded_block_values;
                    typedef std::array<decoded_value_type, decoded_block_values> decoded_block_type;

                    constexpr static const std::size_t encoded_block_values = 2;
                    constexpr static const std::uint8_t encoded_block_bits = encoded_block_values * encoded_value_bits;
                    typedef std::array<encoded_value_type, encoded_block_values> encoded_block_type;
                };
            }    // namespace detail
        }        // namespace codec
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HEX_POLICY_HPP
