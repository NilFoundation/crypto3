//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP
#define CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP

#include <nil/crypto3/algebra/matrix/matrix.hpp>
#include <nil/crypto3/algebra/matrix/math.hpp>
#include <nil/crypto3/algebra/matrix/operators.hpp>
#include <nil/crypto3/algebra/vector/vector.hpp>
#include <nil/crypto3/algebra/vector/math.hpp>
#include <nil/crypto3/algebra/vector/operators.hpp>

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/hash/detail/poseidon/original_constants.hpp>
#include <nil/crypto3/hash/detail/poseidon/kimchi_constants.hpp>

#include <boost/assert.hpp>
#include <type_traits>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {

                template<typename PolicyType>
                class poseidon_constants {
                public:
                    typedef PolicyType policy_type;
                    typedef typename policy_type::word_type element_type;
                    constexpr static const std::size_t state_words = policy_type::state_words;

                    typedef algebra::vector<element_type, state_words> state_vector_type;
                    typedef algebra::matrix<element_type, state_words, state_words> mds_matrix_type;

                    constexpr static const std::size_t Rate = policy_type::block_words;
                    constexpr static const std::size_t full_rounds = policy_type::full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;
                    typedef algebra::matrix<element_type, full_rounds + part_rounds, state_words> round_constants_type;

                    // Choose which constants we want, original or kimchi. We may later add
                    // other sets of constants here.
                    typedef
                        typename std::conditional<PolicyType::mina_version, poseidon_kimchi_constants_data<policy_type>,
                                                  poseidon_original_constants_data<policy_type>>::type
                            constants_data_type;

                    poseidon_constants() {
                        // Transpose the matrix.
                        for (std::size_t i = 0; i < state_words; i++) {
                            for (std::size_t j = 0; j < state_words; j++) {
                                mds_matrix[i][j] = constants_data_type::mds_matrix[j][i];
                            }
                        }
                    }

                    inline const element_type &get_round_constant(std::size_t round, std::size_t i) const {
                        if (round > constants_data_type::round_constants_1.size()) {
                            return constants_data_type::round_constants_2[round][i];
                        }
                        return constants_data_type::round_constants_1[round][i];
                    }

                    inline void product_with_mds_matrix(state_vector_type &A_vector) const {
                        A_vector = algebra::vectmatmul(A_vector, mds_matrix);
                    }

                    mds_matrix_type mds_matrix;
                };
            }    // namespace detail
        }    // namespace hashes
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_CONSTANTS_HPP
