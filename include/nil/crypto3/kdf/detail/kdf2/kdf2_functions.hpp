//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_KDF_KDF2_FUNCTIONS_HPP
#define CRYPTO3_KDF_KDF2_FUNCTIONS_HPP

#include <nil/crypto3/kdf/detail/kdf2/kdf2_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace kdf {
            namespace detail {
                template<typename Hash>
                struct kdf2_functions : public kdf2_policy<Hash> {
                    typedef kdf2_policy<Hash> policy_type;

                    typedef typename policy_type::hash_type hash_type;

                    constexpr static const std::size_t secret_bits = policy_type::secret_bits;
                    typedef typename policy_type::secret_type secret_type;

                    constexpr static const std::size_t label_bits = policy_type::label_bits;
                    typedef typename policy_type::label_type label_type;

                    constexpr static const std::size_t salt_bits = policy_type::salt_bits;
                    typedef typename policy_type::salt_type salt_type;
                };
            }    // namespace detail
        }        // namespace kdf
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HKDF_FUNCTIONS_HPP
