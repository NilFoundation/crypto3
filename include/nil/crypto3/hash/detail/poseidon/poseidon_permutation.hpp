//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP
#define CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_round_operator.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename poseidon_policy_type>
                struct poseidon_permutation {
                    typedef poseidon_policy_type policy_type;

                    typedef poseidon_round_operator<policy_type> round_operator_type;

                    typedef typename policy_type::word_type element_type;
                    typedef typename round_operator_type::state_vector_type state_vector_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t half_full_rounds = policy_type::half_full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    static inline void permute(state_type &A) {
                        std::size_t round_number = 0;

                        // Converting from std::array to algebra::vector here.
                        state_vector_type A_vector;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A_vector[i] = A[i];
                        }

                        // first half of full rounds
                        for (std::size_t i = 0; i < half_full_rounds; i++) {
                            round_operator_type::full_round(A_vector, round_number++);
                        }

                        // partial rounds
                        for (std::size_t i = 0; i < part_rounds; i++) {
                            round_operator_type::part_round(A_vector, round_number++);
                        }

                        // second half of full rounds
                        for (std::size_t i = half_full_rounds; i < full_rounds; i++) {
                            round_operator_type::full_round(A_vector, round_number++);
                        }

                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] = A_vector[i];
                        }
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP
