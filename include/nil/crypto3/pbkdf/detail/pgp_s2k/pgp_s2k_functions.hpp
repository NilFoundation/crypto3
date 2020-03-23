//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PBKDF_PGP_S2K_FUNCTIONS_HPP
#define CRYPTO3_PBKDF_PGP_S2K_FUNCTIONS_HPP

#include <nil/crypto3/pbkdf/detail/pgp_s2k/pgp_s2k_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pbkdf {
            namespace detail {
                template<typename Hash>
                struct pgp_s2k_functions : public pgp_s2k_policy<Hash> {
                    typedef typename pgp_s2k_policy<Hash>::hash_type hash_type;

                    typedef pgp_s2k_policy<Hash> policy_type;

                    constexpr static const std::size_t round_constants_size = policy_type::round_constants_size;
                    typedef typename policy_type::round_constants_type round_constants_type;

                    /**
                     * RFC 4880 encodes the iteration count to a single-byte value
                     */
                    static std::uint8_t encode_count(std::size_t iterations) {
                        /*
                    Only 256 different iterations are actually representable in OpenPGP format ...
                    */
                        for (std::size_t c = 0; c < policy_type::round_constants_size; ++c) {
                            const uint32_t decoded_iter = policy_type::round_constants[c];
                            if (decoded_iter >= iterations) {
                                return static_cast<uint8_t>(c);
                            }
                        }

                        return 255;
                    }

                    static std::size_t decode_count(std::uint8_t encoded_iter) {
                        return policy_type::round_constants[encoded_iter];
                    }
                };
            }    // namespace detail
        }        // namespace pbkdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PGP_S2K_FUNCTIONS_HPP
