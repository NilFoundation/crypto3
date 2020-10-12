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

#ifndef CRYPTO3_KECCAK_FINALIZER_HPP
#define CRYPTO3_KECCAK_FINALIZER_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_policy.hpp>

#include <boost/endian/conversion.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename PolicyType>
                class keccak_1600_finalizer {
                    typedef PolicyType policy_type;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    constexpr static const std::size_t digest_blocks = digest_bits / block_bits;
                    constexpr static const std::size_t last_digest_bits = digest_bits % block_bits;
                    constexpr static const std::size_t last_digest_words =
                        last_digest_bits / word_bits + ((last_digest_bits % word_bits) ? 1 : 0);

                    typedef typename policy_type::digest_type digest_type;
                    typedef keccak_1600_functions<digest_bits> policy_func_type;

                public:
                    void operator()(state_type &state) {
                        state_type temp_state;
                        std::fill(temp_state.begin(), temp_state.end(), 0);

                        for (std::size_t i = 0; i != digest_blocks; ++i) {
                            for (std::size_t j = 0; j != block_words; ++j)
                                temp_state[i * block_words + j] = state[j];

                            for (std::size_t i = 0; i != state_words; ++i)
                                boost::endian::endian_reverse_inplace(state[i]);

                            policy_func_type::permute(state);

                            for (std::size_t i = 0; i != state_words; ++i)
                                boost::endian::endian_reverse_inplace(state[i]);
                        }

                        if (last_digest_bits) {
                            for (std::size_t j = 0; j != last_digest_words; ++j)
                                temp_state[digest_blocks * block_words + j] = state[j];
                        }

                        state = temp_state;
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_KECCAK_FINALIZER_HPP
