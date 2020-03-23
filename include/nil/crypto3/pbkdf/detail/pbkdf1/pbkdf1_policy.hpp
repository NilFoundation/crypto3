//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PBKDF_PBKDF1_POLICY_HPP
#define CRYPTO3_PBKDF_PBKDF1_POLICY_HPP

namespace nil {
    namespace crypto3 {
        namespace pbkdf {
            namespace detail {
                template<typename Hash>
                struct pkcs5_pkbdf1_policy {
                    typedef Hash hash_type;

                    constexpr static const std::size_t digest_bits = hash_type::digest_bits;
                    typedef typename hash_type::digest_type digest_type;

                    constexpr static const std::size_t salt_bits = CHAR_BIT;
                    constexpr static const std::size_t salt_size = CHAR_BIT / CHAR_BIT;
                    typedef boost::container::small_vector<std::uint8_t, salt_size> salt_type;
                };
            }    // namespace detail
        }        // namespace pbkdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PBKDF1_POLICY_HPP
