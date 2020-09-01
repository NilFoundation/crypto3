//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP
#define CRYPTO3_HASH_POSEIDON_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_constants.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_mds_matrix.hpp>
// #include <nil/algebra/fields/element.hpp>
// #include <nil/algebra/fields/fp.hpp>
// #include <nil/algebra/fields/operations.hpp>
// #include <nil/algebra/fields/detail/operations/fp.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                // filecoin oriented implementation
                template<typename FieldType, std::size_t Arity, bool strength>
                struct poseidon_functions {
                    typedef poseidon_policy<FieldType, Arity, strength> policy_type;
                    typedef poseidon_constants<FieldType, Arity, strength> policy_constants_type;
                    typedef typename FieldType::value_type element_type;
                    typedef typename policy_constants_type::state_vector_type state_vector_type;

                    constexpr static const std::size_t state_bits = policy_type::state_bits;
                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t block_bits = policy_type::block_bits;
                    constexpr static const std::size_t block_words = policy_type::block_words;
                    typedef typename policy_type::block_type block_type;

                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t half_full_rounds = policy_type::half_full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    typedef typename policy_type::word_type word_type;

                    constexpr static const std::size_t grain_lfsr_state_len = 80;

                    static inline void permute(state_type &A) {
                        std::size_t round_number = 0;

                        state_vector_type A_vector;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A_vector[i] = A[i];
                        }

                        // first half of full rounds
                        for(std::size_t i = 0; i < half_full_rounds; i++) {
                            policy_constants_type::arc_sbox_mds_full_round(A_vector, round_number++);
                        }

                        // partial rounds
                        for(std::size_t i = 0; i < part_rounds; i++) {
                            policy_constants_type::arc_sbox_mds_part_round(A_vector, round_number++);
                        }

                        // second half of full rounds
                        for(std::size_t i = 0; i < half_full_rounds; i++) {
                            policy_constants_type::arc_sbox_mds_full_round(A_vector, round_number++);
                        }

                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] = A_vector[i];
                        }
                    }

                    static inline void permute_optimized(state_type &A) {
                        std::size_t round_number = 0;

                        state_vector_type A_vector;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A_vector[i] = A[i];
                        }

                        // first half of full rounds
                        for(std::size_t i = 0; i < half_full_rounds; i++) {
                            policy_constants_type::arc_sbox_mds_full_round_optimized_first(A_vector, round_number++);
                        }

                        // partial rounds
                        policy_constants_type::arc_mds_part_round_optimized_init(A_vector, round_number);
                        for(std::size_t i = 0; i < part_rounds - 1; i++) {
                            policy_constants_type::sbox_arc_mds_part_round_optimized(A_vector, round_number++);
                        }
                        // last partial round
                        policy_constants_type::sbox_mds_part_round_optimized_last(A_vector, round_number++);

                        // second half of full rounds
                        for(std::size_t i = 0; i < half_full_rounds; i++) {
                            policy_constants_type::arc_sbox_mds_full_round_optimized_last(A_vector, round_number++);
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

