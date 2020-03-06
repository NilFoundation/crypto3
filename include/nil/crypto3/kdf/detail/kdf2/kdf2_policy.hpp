//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KDF_KDF2_POLICY_HPP
#define CRYPTO3_KDF_KDF2_POLICY_HPP

#include <boost/container/small_vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename Hash>
                struct kdf2_policy {
                    typedef Hash hash_type;

                    constexpr static const std::size_t salt_bits = CHAR_BIT;
                    constexpr static const std::size_t salt_size = CHAR_BIT / CHAR_BIT;
                    typedef boost::container::small_vector<std::uint8_t, salt_size> salt_type;

                    constexpr static const std::size_t secret_bits = CHAR_BIT;
                    constexpr static const std::size_t secret_size = CHAR_BIT / CHAR_BIT;
                    typedef boost::container::small_vector<std::uint8_t, secret_size> secret_type;

                    constexpr static const std::size_t label_bits = CHAR_BIT;
                    constexpr static const std::size_t label_size = CHAR_BIT / CHAR_BIT;
                    typedef boost::container::small_vector<std::uint8_t, salt_size> label_type;
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_POLICY_HPP
