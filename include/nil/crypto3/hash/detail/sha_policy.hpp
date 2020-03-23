//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_DETAIL_SHA_POLICY_HPP
#define CRYPTO3_HASH_DETAIL_SHA_POLICY_HPP

#include <nil/crypto3/block/detail/shacal/shacal_policy.hpp>

#include <nil/crypto3/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                struct sha_policy {
                    typedef block::detail::shacal_policy cipher_policy;
                    typedef cipher_policy::block_type state_type;

                    constexpr static const std::size_t digest_bits = 160;
                    constexpr static const std::uint8_t ieee1363_hash_id = 0x33;

                    typedef static_digest<digest_bits> digest_type;
                    typedef std::array<std::uint8_t, 15> pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
                                                                   0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};

                    struct iv_generator {
                        state_type const &operator()() const {
                            // First 4 words are the same as MD4
                            static state_type const H0 = {{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0}};
                            return H0;
                        }
                    };
                };

                typedef sha_policy sha0_policy;

            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_SHA_POLICY_HPP
