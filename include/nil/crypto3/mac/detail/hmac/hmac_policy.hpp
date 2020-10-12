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

#ifndef CRYPTO3_MAC_HMAC_POLICY_HPP
#define CRYPTO3_MAC_HMAC_POLICY_HPP

#include <boost/container/static_vector.hpp>

#include <boost/integer.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                template<typename Hash>
                struct hmac_policy {
                    typedef Hash hash_type;
                    typedef typename hash_type::construction_type construction_type;

                    typedef typename boost::uint_t<CHAR_BIT>::exact byte_type;

                    constexpr static const std::size_t block_bits = construction_type::block_bits;
                    constexpr static const std::size_t block_words = construction_type::block_words;
                    typedef typename construction_type::block_type block_type;

                    constexpr static const std::size_t digest_bits = construction_type::digest_bits;
                    typedef typename construction_type::digest_type result_type;

                    constexpr static const std::size_t min_key_bits = 0;
                    constexpr static const std::size_t max_key_bits = 4096 * CHAR_BIT;
                    typedef boost::container::static_vector<byte_type, max_key_bits / CHAR_BIT> key_type;
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HMAC_POLICY_HPP
