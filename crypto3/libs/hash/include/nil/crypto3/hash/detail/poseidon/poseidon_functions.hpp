//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
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

#ifndef CRYPTO3_HASH_POSEIDON_FUNCS_HPP
#define CRYPTO3_HASH_POSEIDON_FUNCS_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename Policy>
                struct poseidon_functions {
                private:
                    typedef poseidon_permutation<Policy> permutation_type;

                public:
                    constexpr static const std::size_t block_words = Policy::block_words;
                    constexpr static const std::size_t state_words = Policy::state_words;

                    typedef typename Policy::word_type word_type;
                    typedef typename Policy::block_type block_type;
                    typedef typename Policy::state_type state_type;

                    static void permute(state_type& state) {
                        permutation_type::permute(state);
                    }

                    static void absorb(const block_type block, state_type& state) {
                        for (std::size_t i = 0; i < block_words; ++i) {
                            state[i] += block[i];
                        }
                    }

                    static std::vector<block_type> get_padded_blocks(block_type block, std::size_t words_filled) {
                        if (words_filled == 0) {
                            // If no words provided in the last block, we don't want to trigger a permutation.
                            // With empty vector no absorb() will be called
                            return {};
                        }
                        for (std::size_t idx_to_zero = words_filled; idx_to_zero < block_words; ++idx_to_zero) {
                            block[idx_to_zero] = 0u;
                        }
                        return {block};
                    }

                };

            }    // namespace detail
        }    // namespace hashes
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_FUNCS_HPP
