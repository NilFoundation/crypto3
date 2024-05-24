//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
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
