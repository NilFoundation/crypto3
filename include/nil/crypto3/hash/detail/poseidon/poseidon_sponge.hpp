//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_SPONGE_HPP
#define CRYPTO3_HASH_POSEIDON_SPONGE_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_permutation.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename policy_type>
                struct poseidon_sponge_construction {
                private:
                    typedef poseidon_permutation<policy_type> permutation_type;
                    std::size_t state_count = 0;

                public:

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    constexpr static const std::size_t block_bits = policy_type::block_bits;

                    typedef typename policy_type::word_type word_type;
                    typedef typename policy_type::digest_endian endian_type;
                    typedef typename policy_type::block_type block_type;

                    std::array<typename policy_type::element_type, policy_type::state_words> state;

                    poseidon_sponge_construction() {
                        for (std::size_t i = 0; i < policy_type::state_words; i++) {
                            this->state[i] = 0;
                        }
                        this->state_count = 1;
                    }

                    void absorb(const std::vector<typename policy_type::element_type>& inputs) {
                        for (auto &input : inputs) {
                            absorb(input);
                        }
                    }

                    void permute() {
                        permutation_type::permute(this->state);

                        // When you permute, the last element becomes first, the others zero out.
                        this->state[0] = this->state[policy_type::state_words - 1];
                        for (size_t i = 1; i < policy_type::state_words; ++i) {
                            this->state[i] = 0;
                        }
                        this->state_count = 1;
                    }

                    void absorb(const typename policy_type::element_type &input) {
                        if (this->state_count == policy_type::state_words) {
                            permute();
                        }

                        this->state[this->state_count] = input;
                        this->state_count++;
                    }

                    const typename policy_type::element_type& squeeze() {
                        permute();
                        return this->state[0];
                    }

                    void reset() {
                        state.clear();
                        this->state_count = 0;
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_SPONGE_HPP
