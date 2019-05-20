//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HEX_POLICY_HPP
#define CRYPTO3_HEX_POLICY_HPP

#include <array>

namespace nil {
    namespace crypto3 {
        namespace codec {
            namespace mode {
                struct upper {
                    typedef const char *constants_type;
                    constexpr static const constants_type constants = "0123456789ABCDEF";
                };

                constexpr upper::constants_type upper::constants;

                /*!
                 *
                 */
                struct lower {
                    typedef const char *constants_type;
                    constexpr static const constants_type constants = "0123456789abcdef";
                };

                constexpr lower::constants_type lower::constants;
            }

            namespace detail {
                template<typename Mode>
                struct hex_policy {
                    typedef Mode mode_type;

                    typedef typename mode_type::constants_type constants_type;
                    constexpr static const constants_type constants = mode_type::constants;

                    constexpr static const std::uint8_t decoded_block_bits = CHAR_BIT;
                    typedef std::array<std::uint8_t, decoded_block_bits / CHAR_BIT> decoded_block_type;

                    constexpr static const std::uint8_t encoded_block_bits = 2u * decoded_block_bits;
                    typedef std::array<std::uint8_t, encoded_block_bits / CHAR_BIT> encoded_block_type;
                };
            }
        }
    }
}

#endif //CRYPTO3_HEX_POLICY_HPP
