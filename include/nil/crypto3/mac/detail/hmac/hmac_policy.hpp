//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_HMAC_POLICY_HPP
#define CRYPTO3_MAC_HMAC_POLICY_HPP

#include <boost/container/static_vector.hpp>

#include <boost/integer.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<typename Hash>
                struct hmac_policy {
                    typedef Hash hash_type;
                    typedef typename hash_type::construction_type construction_type;

                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t block_bits = construction_type::block_bits;
                    constexpr static const std::size_t block_words = construction_type::block_words;
                    typedef typename construction_type::block_type block_type;

                    constexpr static const std::size_t digest_bits = construction_type::digest_bits;
                    typedef typename construction_type::digest_type result_type;

                    constexpr static const std::size_t min_key_bits = 0;
                    constexpr static const std::size_t max_key_bits = 4096 * CHAR_BIT;
                    typedef boost::container::static_vector<byte_type, max_key_bits / CHAR_BIT> key_type;
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HMAC_POLICY_HPP
