//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_MDS_MATRIX_HPP
#define CRYPTO3_HASH_POSEIDON_MDS_MATRIX_HPP

#include <nil/crypto3/algebra/matrix/matrix.hpp>
#include <nil/crypto3/algebra/matrix/math.hpp>
#include <nil/crypto3/algebra/matrix/operators.hpp>
#include <nil/crypto3/algebra/vector/vector.hpp>
#include <nil/crypto3/algebra/vector/math.hpp>
#include <nil/crypto3/algebra/vector/operators.hpp>

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>

#include <boost/assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, std::size_t Arity, bool strength>
                struct poseidon_mds_matrix {
                    typedef poseidon_policy<FieldType, Arity, strength> policy_type;
                    typedef typename FieldType::value_type element_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    constexpr static const std::size_t half_full_rounds = policy_type::half_full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    typedef algebra::matrix<element_type, state_words, state_words> mds_matrix_type;
                    typedef algebra::vector<element_type, state_words> state_vector_type;
                    typedef algebra::vector<element_type, state_words - 1> substate_vector_type;
                    typedef algebra::matrix<element_type, state_words - 1, state_words - 1> mds_submatrix_type;

                    inline void product_with_mds_matrix(state_vector_type &A_vector) {
                        A_vector = algebra::vectmatmul(A_vector, mds_matrix);
                    }

                    inline void product_with_inverse_mds_matrix_noalias(const state_vector_type &A_vector_in,
                                                                        state_vector_type &A_vector_out) {
                        A_vector_out = algebra::vectmatmul(A_vector_in, mds_matrix_inverse);
                    }

                    inline void product_with_equivalent_mds_matrix_init(state_vector_type &A_vector,
                                                                        std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds,
                                         "wrong using: product_with_equivalent_mds_matrix_init");
                        A_vector = algebra::vectmatmul(A_vector, get_M_i());
                    }

                    inline void product_with_equivalent_mds_matrix(state_vector_type &A_vector,
                                                                   std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds &&
                                             round_number < half_full_rounds + part_rounds,
                                         "wrong using: product_with_equivalent_mds_matrix");
                        const std::size_t matrix_number_base = part_rounds - (round_number - half_full_rounds) - 1;
                        const substate_vector_type &v = get_v(matrix_number_base);
                        state_vector_type temp_vector;
                        element_type A_0 = A_vector[0];
                        temp_vector[0] = get_M_0_0();
                        for (std::size_t i = 1; i < state_words; i++) {
                            temp_vector[i] = get_w_hat(matrix_number_base)[i - 1];
                        }
                        A_vector[0] = algebra::dot(A_vector, temp_vector);
                        for (std::size_t i = 1; i < state_words; i++) {
                            A_vector[i] = A_0 * v[i - 1] + A_vector[i];
                        }
                    }

                    // private:
                    constexpr inline mds_matrix_type generate_mds_matrix() {
                        mds_matrix_type mds_matrix;
                        for (std::size_t i = 0; i < state_words; i++) {
                            for (std::size_t j = 0; j < state_words; j++) {
                                mds_matrix[i][j] = element_type(i + j + state_words).inversed();
                            }
                        }
                        return mds_matrix;
                    }

                    struct equivalent_mds_matrix_type {
                        typedef std::array<substate_vector_type, part_rounds> subvectors_array;

                        constexpr equivalent_mds_matrix_type(const mds_matrix_type &mds_matrix) :
                            M_i(algebra::get_identity<element_type, state_words>()), w_hat_list(), v_list(), M_0_0() {
                            mds_matrix_type M_mul(mds_matrix);
                            mds_submatrix_type M_hat_inverse;
                            substate_vector_type M_mul_column_slice;

                            for (std::size_t i = 0; i < part_rounds; i++) {
                                M_hat_inverse =
                                    algebra::inverse(algebra::submat<state_words - 1, state_words - 1>(M_mul, 1, 1));
                                w_hat_list[i] = algebra::matvectmul(
                                    M_hat_inverse, algebra::slice<state_words - 1>(M_mul.column(0), 1));
                                v_list[i] = algebra::slice<state_words - 1>(M_mul.row(0), 1);
                                for (std::size_t j = 1; j < state_words; j++) {
                                    for (std::size_t k = 1; k < state_words; k++) {
                                        M_i[j][k] = M_mul[j][k];
                                    }
                                }
                                M_mul = algebra::matmul(mds_matrix, M_i);
                            }
                            M_0_0 = mds_matrix[0][0];
                        }

                        mds_matrix_type M_i;
                        subvectors_array w_hat_list;
                        subvectors_array v_list;
                        element_type M_0_0;
                    };

                    inline const substate_vector_type &get_w_hat(std::size_t w_hat_number) {
                        return equivalent_mds_matrix.w_hat_list[w_hat_number];
                    }
                    inline const substate_vector_type &get_v(std::size_t v_number) {
                        return equivalent_mds_matrix.v_list[v_number];
                    }
                    inline const element_type &get_M_0_0() {
                        return equivalent_mds_matrix.M_0_0;
                    }
                    inline const mds_matrix_type &get_M_i() {
                        return equivalent_mds_matrix.M_i;
                    }

                    constexpr poseidon_mds_matrix() :
                        mds_matrix(generate_mds_matrix()), mds_matrix_inverse(algebra::inverse(mds_matrix)),
                        equivalent_mds_matrix(mds_matrix) {
                    }

                    mds_matrix_type mds_matrix;
                    mds_matrix_type mds_matrix_inverse;
                    equivalent_mds_matrix_type equivalent_mds_matrix;
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_MDS_MATRIX_HPP
