//---------------------------------------------------------------------------//
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_KECCAK_PADDING_HPP
#define CRYPTO3_KECCAK_PADDING_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>
#include <nil/crypto3/detail/inject.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                // pad10*1 scheme
                template<typename Policy>
                class keccak_1600_padder {
                    typedef Policy policy_type;

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

                    typedef ::nil::crypto3::detail::injector<stream_endian::big_octet_big_bit, stream_endian::little_octet_little_bit, word_bits,
                                                             block_words>
                        injector_type;

                    bool is_last;

                public:
                    keccak_1600_padder() : is_last(true) {
                    }

                    static std::vector<block_type> get_padded_blocks(const block_type& block, std::size_t block_seen) {
                        using namespace nil::crypto3::detail;

                        std::vector<block_type> padded_blocks;
                        block_type new_block = block;
                        // set variable to 10
                        word_type padding_start = high_bits<word_bits>(~word_type(), 1);
                        // get how many bits from it could fit into current block
                        const std::size_t padding_start_bits_for_first_block = std::min(block_bits - block_seen, std::size_t{2});
                        // inject this amount of bits
                        injector_type::inject(padding_start, padding_start_bits_for_first_block, new_block, block_seen);

                        if (block_seen == block_bits) {
                            // if current block is full, copy it to result vector, reset counter. Since we need
                            // to add, at least, the last 1 bit (and mb the rest of padding_start)
                            padded_blocks.push_back(new_block);
                            block_seen = 0;
                        }

                        if (padding_start_bits_for_first_block < 2) {
                            // if not all padding_start was injected, we inject the rest of the padding_start to the next block
                            injector_type::inject(padding_start, 2 - padding_start_bits_for_first_block, new_block,
                                                    block_seen, padding_start_bits_for_first_block);
                        }

                        // fill the rest of the block with zeros
                        block_type zeros;
                        std::fill(zeros.begin(), zeros.end(), 0);
                        injector_type::inject(zeros, block_bits - 1 - block_seen, new_block, block_seen);

                        // add the last 1
                        injector_type::inject(high_bits<word_bits>(~word_type(), 1), 1, new_block,
                                                block_seen);

                        padded_blocks.push_back(new_block);

                        BOOST_ASSERT(block_seen == block_bits);

                        return padded_blocks;
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_PADDING_HPP
