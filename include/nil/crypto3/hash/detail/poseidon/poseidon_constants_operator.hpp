//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP
#define CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_mds_matrix.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_lfsr.hpp>

#include <boost/assert.hpp>

#include <bitset>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, std::size_t Arity, bool strength>
                struct poseidon_constants_operator {
                    typedef poseidon_policy<FieldType, Arity, strength> policy_type;
                    typedef poseidon_mds_matrix<FieldType, Arity, strength> policy_matrix_type;
                    typedef poseidon_lfsr<FieldType, Arity, strength> policy_constants_generator_type;
                    typedef typename FieldType::value_type element_type;
                    typedef typename policy_matrix_type::state_vector_type state_vector_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t half_full_rounds = policy_type::half_full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    constexpr static const std::size_t round_constants_size = (full_rounds + part_rounds) * state_words;
                    constexpr static const std::size_t equivalent_round_constants_size =
                        (full_rounds + 1) * state_words + part_rounds - 1;
                    typedef algebra::vector<element_type, equivalent_round_constants_size> equivalent_round_constants_type;

                    /*
                     * =============================================================================================================
                     * Optimized
                     * =============================================================================================================
                     */

                    inline void arc_sbox_mds_full_round_optimized_first(state_vector_type &A,
                                                                               std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number < half_full_rounds,
                                         "wrong using: arc_sbox_mds_full_round_optimized_first");
                        std::size_t constant_number_base = round_number * state_words;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_equivalent_round_constant(constant_number_base + i);
                            A[i] = A[i] * A[i] * A[i] * A[i] * A[i];
                        }
                        policy_matrix.product_with_mds_matrix(A);
                    }

                    inline void arc_sbox_mds_full_round_optimized_last(state_vector_type &A,
                                                                              std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds + part_rounds,
                                         "wrong using: arc_sbox_mds_full_round_optimized_last");
                        std::size_t constant_number_base =
                            (half_full_rounds + 1) * state_words + (part_rounds - 1) +
                            (round_number - half_full_rounds - part_rounds) * state_words;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_equivalent_round_constant(constant_number_base + i);
                            A[i] = A[i] * A[i] * A[i] * A[i] * A[i];
                        }
                        policy_matrix.product_with_mds_matrix(A);
                    }

                    inline void arc_mds_part_round_optimized_init(state_vector_type &A,
                                                                         std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds,
                                         "wrong using: arc_mds_part_round_optimized_init");
                        std::size_t constant_number_base = half_full_rounds * state_words;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_equivalent_round_constant(constant_number_base + i);
                        }
                        policy_matrix.product_with_equivalent_mds_matrix_init(A, round_number);
                    }

                    inline void sbox_arc_mds_part_round_optimized(state_vector_type &A,
                                                                         std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds &&
                                             round_number < half_full_rounds + part_rounds - 1,
                                         "wrong using: sbox_arc_mds_part_round_optimized");
                        std::size_t constant_number_base =
                            (half_full_rounds + 1) * state_words + (round_number - half_full_rounds - 1) + 1;
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                        A[0] += get_equivalent_round_constant(constant_number_base);
                        policy_matrix.product_with_equivalent_mds_matrix(A, round_number);
                    }

                    inline void sbox_mds_part_round_optimized_last(state_vector_type &A,
                                                                          std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds + part_rounds - 1,
                                         "wrong using: sbox_mds_part_round_optimized_last");
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                        policy_matrix.product_with_equivalent_mds_matrix(A, round_number);
                    }

                    /*
                     * =============================================================================================================
                     * Default
                     * =============================================================================================================
                     */

                    inline void arc_sbox_mds_full_round(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number < half_full_rounds ||
                                             round_number >= half_full_rounds + part_rounds,
                                         "wrong using: arc_sbox_mds_full_round");
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_round_constant(round_number * state_words + i);
                            A[i] = A[i] * A[i] * A[i] * A[i] * A[i];
                        }
                        policy_matrix.product_with_mds_matrix(A);
                    }

                    inline void arc_sbox_mds_part_round(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds &&
                                             round_number < half_full_rounds + part_rounds,
                                         "wrong using: arc_sbox_mds_part_round");
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_round_constant(round_number * state_words + i);
                        }
                        A[0] = A[0] * A[0] * A[0] * A[0] * A[0];
                        policy_matrix.product_with_mds_matrix(A);
                    }

                    // private:
                    constexpr inline const element_type &get_round_constant(std::size_t constant_number) {
                        return round_constants_generator.round_constants[constant_number];
                    }

                    constexpr inline const state_vector_type
                        get_round_constants_slice(std::size_t constants_number_base) {
                        return algebra::slice<state_words>(round_constants_generator.round_constants,
                                                           constants_number_base);
                    }

                    constexpr inline const void generate_equivalent_round_constants() {
                        state_vector_type inv_cip1;
                        state_vector_type agregated_round_constants;
                        std::size_t equivalent_constant_number_base =
                            (half_full_rounds + 1) * state_words - half_full_rounds;

                        for (std::size_t i = 0; i < half_full_rounds * state_words; i++) {
                            equivalent_round_constants[i] = get_round_constant(i);
                            equivalent_round_constants[equivalent_round_constants_size - i - 1] =
                                get_round_constant(round_constants_size - i - 1);
                        }

                        for (std::size_t i = half_full_rounds * state_words;
                             i < half_full_rounds * state_words + state_words;
                             i++) {
                            equivalent_round_constants[i] = get_round_constant(i);
                        }

                        for (std::size_t r = half_full_rounds + part_rounds - 2; r >= half_full_rounds; r--) {
                            agregated_round_constants = get_round_constants_slice((r + 1) * state_words) + inv_cip1;
                            policy_matrix.product_with_inverse_mds_matrix_noalias(agregated_round_constants,
                                                                                        inv_cip1);
                            equivalent_round_constants[equivalent_constant_number_base + r] = inv_cip1[0];
                            inv_cip1[0] = 0;
                        }

                        policy_matrix.product_with_inverse_mds_matrix_noalias(
                            agregated_round_constants, inv_cip1);
                        inv_cip1[0] = 0;
                        for (std::size_t i = 0; i < state_words; i++) {
                            equivalent_round_constants[half_full_rounds * state_words + i] += inv_cip1[i];
                        }
                    }

                    inline const element_type &get_equivalent_round_constant(std::size_t constant_number) {
                        return equivalent_round_constants[constant_number];
                    }

                    constexpr poseidon_constants_operator()
                        : policy_matrix(),
                          round_constants_generator(),
                          equivalent_round_constants()
                    {
                        generate_equivalent_round_constants();
                    }

                    policy_matrix_type policy_matrix;
                    policy_constants_generator_type round_constants_generator;
                    equivalent_round_constants_type equivalent_round_constants;
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP
