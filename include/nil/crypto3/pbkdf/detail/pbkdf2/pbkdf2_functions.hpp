//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PBKDF_PBKDF2_FUNCTIONS_HPP
#define CRYPTO3_PBKDF_PBKDF2_FUNCTIONS_HPP

#include <nil/crypto3/pbkdf/detail/pbkdf2/pbkdf2_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pbkdf {
            namespace detail {
                template<typename MessageAuthenticationCode>
                struct pbkdf2_functions : public pbkdf2_policy<MessageAuthenticationCode> {
                    typedef pbkdf2_policy<MessageAuthenticationCode> policy_type;

                    typedef typename policy_type::mac_type mac_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    typedef typename policy_type::digest_type digest_type;

                    constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                    typedef typename policy_type::salt_type salt_type;

                    /**
                     * Round up
                     * @param n a non-negative integer
                     * @param align_to the alignment boundary
                     * @return n rounded up to a multiple of align_to
                     */
                    static inline std::size_t round_up(std::size_t n, std::size_t align_to) {
                        BOOST_ASSERT_MSG(align_to != 0, "align_to must not be 0");

                        if (n % align_to) {
                            n += align_to - (n % align_to);
                        }
                        return n;
                    }
                };
            }    // namespace detail
        }        // namespace pbkdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PBKDF1_FUNCTIONS_HPP
