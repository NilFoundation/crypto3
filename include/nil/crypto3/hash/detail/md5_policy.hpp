//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_DETAIL_MD5_POLICY_HPP
#define CRYPTO3_HASH_DETAIL_MD5_POLICY_HPP

#include <nil/crypto3/block/detail/md5/md5_policy.hpp>

#include <nil/crypto3/hash/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {

                struct md5_policy {
                    typedef block::detail::md5_policy cipher_policy;
                    typedef cipher_policy::block_type state_type;

                    constexpr static const std::size_t digest_bits = cipher_policy::block_bits;
                    typedef hash::static_digest <digest_bits> digest_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            // Same as MD4
                            static state_type const H0 = {{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476}};
                            return H0;
                        }
                    };

                };

            } // namespace detail
        }
    }
} // namespace nil

#endif // CRYPTO3_HASH_DETAIL_MD5_POLICY_HPP
