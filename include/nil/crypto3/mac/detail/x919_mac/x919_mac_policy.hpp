//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_X919_MAC_POLICY_HPP
#define CRYPTO3_MAC_X919_MAC_POLICY_HPP

#include <boost/container/static_vector.hpp>
#include <boost/integer.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<typename BlockCipher>
                struct x919_mac_policy {
                    typedef BlockCipher cipher_type;

                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t word_bits = cipher_type::word_bits;
                    typedef typename cipher_type::word_type word_type;

                    constexpr static const std::size_t key_bits = cipher_type::key_bits;
                    constexpr static const std::size_t key_words = cipher_type::key_words;
                    typedef boost::container::static_vector<word_type, 2 * key_words> key_type;

                    constexpr static const std::size_t key_schedule_bits = cipher_type::key_schedule_bits;
                    constexpr static const std::size_t key_schedule_words = cipher_type::key_schedule_words;
                    typedef typename cipher_type::key_schedule_type key_schedule_type;

                    constexpr static const std::size_t digest_size = 8;
                    constexpr static const std::size_t digest_bits = 8 * CHAR_BIT;
                    typedef std::array<byte_type, digest_size> digest_type;
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_X919_MAC_POLICY_HPP
