//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_NIL_POSEIDON_SPONGE_HPP
#define CRYPTO3_HASH_NIL_POSEIDON_SPONGE_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename Policy>
                struct poseidon_sponge_construction_custom {
                    // This is a quite strange sponge. It has rate = 3 on first absorb, then rate = 2.
                    // E.g., we have ABCDEFG values as input. Rate is 3, Capacity is 1: (full state: 0|0|0|0). Values are consumed as:
                    // 0|0|0|0 -absorb-> A|B|C|0 -permute-> S1|S2|S3|S4 -> S4|0|0|0 -absorb-> S4|D|E|0 -permute->
                    //   S1'|S2'|S3'|S4' -> S4'|0|0|0 -> ...
                    // As we could see, it does not fit into standard sponge construction, where permutation is called each Rate
                    // elements (each Rate - 1 instead). State is zeroed after the permutation. Only the first element is returned
                    // from squeeze(), not Rate elements...
                public:
                    using permutation_type = poseidon_permutation<Policy>;

                    using word_type = typename Policy::word_type;
                    using state_type = typename Policy::state_type;
                    using block_type = typename Policy::block_type; // `block` is used to fit other code (e.g. accumulator)
                    using digest_type = typename Policy::digest_type;

                    constexpr static const std::size_t state_words = Policy::state_words;
                    constexpr static const std::size_t block_words = Policy::block_words;
                    constexpr static const std::size_t digest_words = Policy::digest_words;

                    poseidon_sponge_construction_custom() {
                        reset();
                    }

                    poseidon_sponge_construction_custom(word_type word) {
                        // Currently used for hack in zk fiat-shamir scheme challenge extraction
                        reset();
                        state_[0] = word;
                    }

                    void absorb(const block_type &block) {
                        for (auto &word: block) {
                            absorb(word);
                        }
                    }

                    void absorb_with_padding(const block_type &block,
                                             const std::size_t last_block_words_filled = block_words) {
                        // No extra padding, just consume block as is
                        for (std::size_t i = 0; i < last_block_words_filled; ++i) {
                            absorb(block[i]);
                        }
                    }

                    void permute() {
                        permutation_type::permute(state_);

                        // When you permute, the last element becomes first, the others zero out.
                        state_[0] = state_[state_words - 1];
                        for (size_t i = 1; i < state_words; ++i) {
                            state_[i] = 0u;
                        }
                        state_count_ = 1;
                    }

                    void absorb(const word_type &word) {
                        if (state_count_ == state_words) {
                            permute();
                        }
                        state_[state_count_] = word;
                        state_count_++;
                    }

                    const word_type squeeze() { // type differs from canonical sponge, it should be block_type
                        permute();
                        return state_[0];
                    }

                    const digest_type digest() {
                        return squeeze();
                    }

                    void reset() {
                        state_.fill(0u);
                        state_count_ = 1;
                    }

                private:
                    state_type state_;
                    std::size_t state_count_;
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_NIL_POSEIDON_SPONGE_HPP
