//---------------------------------------------------------------------------//
// Copyright (c) 2020 Pavel Kharitonov <ipavrus@nil.foundation>
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
//---------------------------------------------------------------------------////

#ifndef CRYPTO3_TIGER_PADDING_HPP
#define CRYPTO3_TIGER_PADDING_HPP

#include <nil/crypto3/detail/inject.hpp>
#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/octet.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename Hash>
                class tiger_padding {
                    typedef Hash policy_type;

                    typedef typename policy_type::digest_endian endian_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    typedef typename policy_type::digest_type digest_type;

                    typedef ::nil::crypto3::detail::injector<endian_type, word_bits, block_words, block_bits>
                        injector_type;

                public:
                    void operator()(block_type &block, std::size_t &block_seen) {
                        using namespace nil::crypto3::detail;
                        // Remove garbage
                        block_type block_of_zeros;
                        std::size_t seen_copy = block_seen;
                        std::fill(block_of_zeros.begin(), block_of_zeros.end(), 0);
                        injector_type::inject(block_of_zeros, block_bits - block_seen, block, seen_copy);

                        // Get bit 1 in the endianness used by the hashes
                        std::array<octet_type, word_bits / octet_bits> bit_one = {{0x01}};
                        std::array<word_type, 1> bit_one_word {};
                        pack<stream_endian::big_octet_big_bit, endian_type, octet_bits, word_bits>(
                            bit_one.begin(), bit_one.end(), bit_one_word.begin());

                        // Add 1 bit to block
                        injector_type::inject(bit_one_word[0], 8, block, block_seen);
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TIGERS_PADDING_HPP
