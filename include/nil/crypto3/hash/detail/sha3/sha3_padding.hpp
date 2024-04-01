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

#ifndef CRYPTO3_SHA3_PADDING_HPP
#define CRYPTO3_SHA3_PADDING_HPP

#include <nil/crypto3/detail/inject.hpp>
#include <nil/crypto3/detail/unbounded_shift.hpp>
#include <nil/crypto3/hash/detail/keccak/keccak_padding.hpp>
#include <nil/crypto3/hash/detail/sha3/sha3_policy.hpp>


namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                // pad10*1 scheme
                template<typename Policy>
                class sha3_padder {
                    typedef Policy policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    typedef ::nil::crypto3::detail::injector<stream_endian::big_octet_big_bit, stream_endian::little_octet_little_bit, word_bits,
                                                             block_words>
                        injector_type;

                public:
                    static std::vector<block_type> get_padded_blocks(const block_type& block, std::size_t block_seen) {
                        // SHA3 padding consists of 01 10 0...0 1 (01 + 10*1 keccak padding)
                        using namespace nil::crypto3::detail;

                        std::vector<block_type> padded_blocks;
                        block_type new_block = block;
                        // set variable to 01
                        word_type sha_specific_bits = unbounded_shr(high_bits<word_bits>(~word_type(), 1), 1);
                        // get how many bits from it could fit into current block
                        const std::size_t sha_specific_bits_n_for_first_block = std::min(block_bits - block_seen, std::size_t{2});
                        // inject this amount of bits
                        injector_type::inject(sha_specific_bits, sha_specific_bits_n_for_first_block, new_block, block_seen);

                        if (block_seen == block_bits) {
                            // if current block is full, copy it to result vector, reset counter. Since we need
                            // to add, at least, the last 1 bit (and mb the rest of sha_specific_bits)
                            padded_blocks.push_back(new_block);
                            block_seen = 0;
                        }

                        if (sha_specific_bits_n_for_first_block < 2) {
                            // if not all sha_specific_bits was injected, we inject the rest to the next block
                            injector_type::inject(sha_specific_bits, 2 - sha_specific_bits_n_for_first_block, new_block,
                                                    block_seen, sha_specific_bits_n_for_first_block);
                        }

                        auto keccak_padding_result = keccak_1600_padder<Policy>::get_padded_blocks(new_block, block_seen);
                        padded_blocks.insert(padded_blocks.end(), std::make_move_iterator(keccak_padding_result.begin()), std::make_move_iterator(keccak_padding_result.end()));

                        return padded_blocks;
                    }
                };
            }    // namespace detail
        }    // namespace hashes
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SHA3_PADDING_HPP
