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

#ifndef CRYPTO3_MAC_POLY1305_POLICY_HPP
#define CRYPTO3_MAC_POLY1305_POLICY_HPP

#include <boost/integer.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/crypto3/mac/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            namespace detail {
                struct poly1305_policy : public basic_functions<64> {
                    typedef basic_functions<64> policy_type;

                    typedef typename policy_type::byte_type byte_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t block_words = 2;
                    constexpr static const std::size_t block_bits = block_words * word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t key_words = 32;
                    constexpr static const std::size_t key_bits = key_words * CHAR_BIT;
                    typedef std::array<byte_type, key_words> key_type;

                    constexpr static const std::size_t key_schedule_words = 8;
                    constexpr static const std::size_t key_schedule_bits = key_schedule_words * word_bits;
                    typedef std::array<word_type, key_schedule_words> key_schedule_type;

                    constexpr static const std::size_t state_size = 16;
                    typedef std::array<byte_type, state_size> state_type;
                };
            }    // namespace detail
        }        // namespace mac
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_POLY1305_POLICY_HPP
