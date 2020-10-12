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
