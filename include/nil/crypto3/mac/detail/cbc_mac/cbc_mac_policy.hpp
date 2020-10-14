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

#ifndef CRYPTO3_MAC_CBC_MAC_POLICY_HPP
#define CRYPTO3_MAC_CBC_MAC_POLICY_HPP

#include <boost/integer.hpp>

#include <nil/crypto3/mac/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<typename BlockCipher>
                struct cbc_mac_policy {
                    typedef BlockCipher cipher_type;

                    constexpr static const std::size_t block_bits = cipher_type::block_bits;
                    constexpr static const std::size_t block_words = cipher_type::block_words;
                    typedef typename cipher_type::block_type block_type;

                    constexpr static const std::size_t state_bits = block_bits;
                    constexpr static const std::size_t state_words = block_words;
                    typedef block_type state_type;

                    constexpr static const std::size_t digest_bits = block_bits;
                    typedef static_digest<block_bits> digest_type;

                    constexpr static const std::size_t key_words = cipher_type::key_words;
                    constexpr static const std::size_t key_bits = cipher_type::key_bits;
                    typedef typename cipher_type::key_type key_type;
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CBC_MAC_POLICY_HPP
