//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_CMAC_POLICY_HPP
#define CRYPTO3_MAC_CMAC_POLICY_HPP

#include <boost/integer.hpp>

#include <nil/crypto3/mac/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<typename BlockCipher>
                struct cmac_policy {
                    typedef BlockCipher cipher_type;

                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t block_bits = cipher_type::block_bits;
                    constexpr static const std::size_t block_words = cipher_type::block_words;
                    typedef typename cipher_type::block_type block_type;

                    constexpr static const std::size_t digest_bits = block_bits;
                    typedef static_digest<block_bits> digest_type;

                    constexpr static const std::size_t key_words = cipher_type::key_words;
                    constexpr static const std::size_t key_bits = cipher_type::key_bits;
                    typedef typename cipher_type::key_type key_type;
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CMAC_POLICY_HPP
