//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_ROUND_OPERATOR_HPP
#define CRYPTO3_HASH_POSEIDON_ROUND_OPERATOR_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_constants.hpp>

#include <boost/assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {

                // TODO(martun): Poseidon paper describes an optimized round, which can work faster when
                // the Rate is high. Consider implementing it later.
                template<typename poseidon_policy_type, typename Enable=void>
                class poseidon_round_operator;

                /// Round for the original version, ARC-SBOX-MDS order.
                template<typename poseidon_policy_type>
                class poseidon_round_operator<poseidon_policy_type, 
                                              std::enable_if_t<!poseidon_policy_type::mina_version>> {
                public:
                    typedef poseidon_policy_type policy_type;
                    typedef typename policy_type::field_type field_type;

                    typedef poseidon_constants<policy_type> poseidon_constants_type;
                    typedef typename poseidon_constants_type::round_constants_type round_constants_type;

                    typedef typename field_type::value_type element_type;
                    typedef typename poseidon_constants_type::state_vector_type state_vector_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t half_full_rounds = policy_type::half_full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;
                    constexpr static const std::size_t sbox_power = policy_type::sbox_power;

                    static void full_round(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number < half_full_rounds ||
                                             round_number >= half_full_rounds + part_rounds,
                                         "Wrong usage of the full round function of original Poseidon.");
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_constants().get_round_constant(round_number, i);
                            A[i] = A[i].pow(sbox_power);
                        }
                        get_constants().product_with_mds_matrix(A);
                    }

                    static void part_round(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds &&
                                             round_number < half_full_rounds + part_rounds,
                                         "Wrong usage of the part round function of original Poseidon.");
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_constants().get_round_constant(round_number, i);
                        }
                        A[0] = A[0].pow(sbox_power);
                        get_constants().product_with_mds_matrix(A);
                    }

                private:
                    // Contains all the constants: mds matrix and round constants.
                    // Default constructor selects the right ones.
                    static const poseidon_constants<poseidon_policy_type> get_constants() {
                        static const poseidon_constants<poseidon_policy_type> constants;
                        return constants;
                    }
                };

                /// Rounds for Mina version have SBOX-MDS-ARC order.
                template<typename poseidon_policy_type>
                class poseidon_round_operator<poseidon_policy_type, 
                                              std::enable_if_t<poseidon_policy_type::mina_version>> {
                public:
                    typedef poseidon_policy_type policy_type;
                    typedef typename policy_type::field_type field_type;

                    typedef poseidon_constants<policy_type> poseidon_constants_type;
                    typedef typename poseidon_constants_type::round_constants_type round_constants_type;

                    typedef typename field_type::value_type element_type;
                    typedef typename poseidon_constants_type::state_vector_type state_vector_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t half_full_rounds = policy_type::half_full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;
                    constexpr static const std::size_t sbox_power = policy_type::sbox_power;

                    static void full_round(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number < half_full_rounds ||
                                             round_number >= half_full_rounds + part_rounds,
                                         "Wrong usage of the Full round function of Mina Poseidon.");
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] = A[i].pow(sbox_power);
                        }
                        get_constants().product_with_mds_matrix(A);
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_constants().get_round_constant(round_number, i);
                        }
                    }

                    static void part_round(state_vector_type &A, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds &&
                                             round_number < half_full_rounds + part_rounds,
                                         "Wrong usage of the part round function of Mina Poseidon.");
                        A[0] = A[0].pow(sbox_power);
                        get_constants().product_with_mds_matrix(A);
                        for (std::size_t i = 0; i < state_words; i++) {
                            A[i] += get_constants().get_round_constant(round_number, i);
                        }
                    }

                private:
                    // Contains all the constants: mds matrix and round constants.
                    // Default constructor selects the right ones.
                    static const poseidon_constants<poseidon_policy_type> get_constants() {
                        static const poseidon_constants<poseidon_policy_type> constants;
                        return constants;
                    }
                };

            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_ROUND_OPERATOR_HPP
