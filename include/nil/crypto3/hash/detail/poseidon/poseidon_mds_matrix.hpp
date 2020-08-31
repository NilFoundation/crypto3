//---------------------------------------------------------------------------//
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_POSEIDON_MDS_MATRIX_HPP
#define CRYPTO3_HASH_POSEIDON_MDS_MATRIX_HPP

#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>

#include <boost/assert.hpp>
// #include <boost/multiprecision/cpp_int.hpp>
#include <boost/numeric/ublas/vector.hpp>
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/lu.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, std::size_t Arity, bool strength>
                struct poseidon_mds_matrix {
                    typedef poseidon_policy<FieldType, Arity, strength> policy_type;
                    typedef typename FieldType::value_type ElementType;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    constexpr static const std::size_t half_full_rounds = policy_type::half_full_rounds;
                    constexpr static const std::size_t part_rounds = policy_type::part_rounds;

                    typedef boost::numeric::ublas::matrix<ElementType> mds_matrix_type;
                    typedef boost::numeric::ublas::vector<ElementType> state_vector_type;
                    typedef cotila::matrix<ElementType, state_words, state_words> mds_matrix_type_cotila;
                    typedef cotila::vector<ElementType, state_words> state_vector_type_cotila;
                    typedef cotila::vector<ElementType, state_words - 1> substate_vector_type_cotila;
                    typedef cotila::matrix<ElementType, state_words - 1, state_words - 1> submatrix_type_cotila;
                    typedef std::array<state_vector_type, part_rounds> subvectors_collection;
                    typedef std::array<substate_vector_type_cotila, part_rounds> subvectors_collection_cotila;
                    // (M', M_0_0, w_hat_list, v_list)
                    enum : std::size_t { M_i, M_0_0, w_hat_list, v_list };
                    typedef std::tuple<mds_matrix_type, ElementType, subvectors_collection,
                        subvectors_collection> equivalent_mds_matrix_type;
                    typedef std::tuple<mds_matrix_type_cotila, ElementType, subvectors_collection_cotila,
                        subvectors_collection_cotila> equivalent_mds_matrix_type_cotila;

                    static inline void from_cotila(state_vector_type_cotila &A_from, state_vector_type &A_to) {
                        for (std::size_t i = 0; i < state_words; i++) {
                            A_to[i] = A_from[i];
                        }
                    }
                    static inline void to_cotila(const state_vector_type &A_from, state_vector_type_cotila &A_to) {
                        for (std::size_t i = 0; i < state_words; i++) {
                            A_to[i] = A_from[i];
                        }
                    }
                    static inline state_vector_type_cotila vect_matr_mul(const state_vector_type_cotila &A_vect, const mds_matrix_type_cotila &matr) {
                        typedef cotila::matrix<ElementType, 1, state_words> state_vect_by_matr_type_cotila;

                        state_vect_by_matr_type_cotila state_vect_by_matr_cotila;
                        for (std::size_t i = 0; i < state_words; i++) {
                            state_vect_by_matr_cotila[0][i] = A_vect[i];
                        }
                        state_vect_by_matr_cotila = cotila::matmul(state_vect_by_matr_cotila, matr);
                        state_vector_type_cotila A_out;
                        for (std::size_t i = 0; i < state_words; i++) {
                            A_out[i] = state_vect_by_matr_cotila[0][i];
                        }
                        return A_out;
                    }
                    static inline ElementType inner_prod_cotila(const state_vector_type_cotila &A_vect, const state_vector_type_cotila &B_vect) {
                        ElementType res(0);
                        for (std::size_t i = 0; i < state_words; i++) {
                            res += A_vect[i] * B_vect[i];
                        }
                        return res;
                    }

                    static inline void product_with_mds_matrix(state_vector_type &A_vector) {
                        // A_vector = boost::numeric::ublas::prod(A_vector, get_mds_matrix());
                        state_vector_type_cotila A_vector_cotila;
                        to_cotila(A_vector, A_vector_cotila);
                        A_vector_cotila = vect_matr_mul(A_vector_cotila, get_mds_matrix_cotila());
                        from_cotila(A_vector_cotila, A_vector);
                    }

                    static inline void product_with_inverse_mds_matrix_noalias(const state_vector_type &A_vector_in, state_vector_type &A_vector_out) {
                        // BOOST_ASSERT_MSG(&A_vector_in != &A_vector_out, "wrong using: product_with_inverse_mds_matrix_noalias");
                        // boost::numeric::ublas::noalias(A_vector_out) = boost::numeric::ublas::prod(A_vector_in, get_inverse_mds_matrix());
                        state_vector_type_cotila A_vector_cotila;
                        to_cotila(A_vector_in, A_vector_cotila);
                        A_vector_cotila = vect_matr_mul(A_vector_cotila, get_inverse_mds_matrix_cotila());
                        from_cotila(A_vector_cotila, A_vector_out);
                    }

                    static inline void product_with_equivalent_mds_matrix_init(state_vector_type &A_vector, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds, "wrong using: product_with_equivalent_mds_matrix_init");
                        // A_vector = boost::numeric::ublas::prod(A_vector, std::get<M_i>(get_equivalent_mds_matrix()));
                        state_vector_type_cotila A_vector_cotila;
                        to_cotila(A_vector, A_vector_cotila);
                        A_vector_cotila = vect_matr_mul(A_vector_cotila, std::get<M_i>(get_equivalent_mds_matrix_cotila()));
                        from_cotila(A_vector_cotila, A_vector);
                    }

                    static inline void product_with_equivalent_mds_matrix(state_vector_type &A_vector, std::size_t round_number) {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds
                            && round_number < half_full_rounds + part_rounds, "wrong using: product_with_equivalent_mds_matrix");
                        using namespace boost::numeric::ublas;
                        state_vector_type_cotila A_vector_cotila;
                        to_cotila(A_vector, A_vector_cotila);
                        const std::size_t matrix_number_base = part_rounds - (round_number - half_full_rounds) - 1;
                        const substate_vector_type_cotila &v_cotila = get_v_cotila(matrix_number_base);
                        state_vector_type_cotila temp_vector_cotila;
                        ElementType A_0_cotila = A_vector_cotila[0];
                        temp_vector_cotila[0] = get_M_0_0_cotila();
                        for (std::size_t i = 1; i < state_words; i++) {
                            temp_vector_cotila[i] = get_w_hat_cotila(matrix_number_base)[i - 1];
                        }
                        A_vector_cotila[0] = inner_prod_cotila(A_vector_cotila, temp_vector_cotila);
                        for (std::size_t i = 1; i < state_words; i++) {
                            A_vector_cotila[i] = A_0_cotila * v_cotila[i - 1] + A_vector_cotila[i];
                        }
                        from_cotila(A_vector_cotila, A_vector);
                    }

                // private:
                    static inline const mds_matrix_type_cotila &get_mds_matrix_cotila() {
                        static const mds_matrix_type_cotila mds_matrix_cotila = [](){
                            mds_matrix_type_cotila mds_matrix_cotila;
                            for (std::size_t i = 0; i < state_words; i++) {
                                for (std::size_t j = 0; j < state_words; j++) {
                                    mds_matrix_cotila[i][j] = ElementType(i + j + Arity).get_inverse();
                                }
                            }
                            return mds_matrix_cotila;
                        }();
                        return mds_matrix_cotila;
                    }

                    static inline const mds_matrix_type_cotila &get_inverse_mds_matrix_cotila() {
                        static const mds_matrix_type_cotila inverse_mds_matrix_cotila = [](){
                            mds_matrix_type_cotila inverse_mds_matrix_cotila = cotila::inverse(get_mds_matrix_cotila());
                            return inverse_mds_matrix_cotila;
                        }();
                        return inverse_mds_matrix_cotila;
                    }

                    static inline const equivalent_mds_matrix_type_cotila &get_equivalent_mds_matrix_cotila() {
                        static const equivalent_mds_matrix_type_cotila equivalent_mds_matrix_cotila = [](){
                            typedef cotila::matrix<ElementType, state_words - 1, 1> M_mul_column_slice_matr_type;

                            mds_matrix_type_cotila M_mul(get_mds_matrix_cotila());
                            submatrix_type_cotila M_hat_inverse;
                            substate_vector_type_cotila M_mul_column_slice;
                            M_mul_column_slice_matr_type M_mul_column_slice_matr;

                            mds_matrix_type_cotila M_i = cotila::identity<ElementType, state_words>;
                            subvectors_collection_cotila w_hat_list;
                            subvectors_collection_cotila v_list;
                            ElementType M_0_0;

                            for (std::size_t i = 0; i < part_rounds; i++) {
                                M_hat_inverse = cotila::inverse(cotila::submat<state_words - 1, state_words - 1>(M_mul, 1, 1));
                                M_mul_column_slice = cotila::slice<state_words - 1>(M_mul.column(0), 1);
                                for (std::size_t j = 0; j < state_words - 1; j++) {
                                    M_mul_column_slice_matr[j][0] = M_mul_column_slice[j];
                                }
                                w_hat_list[i] = cotila::matmul(M_hat_inverse, M_mul_column_slice_matr).column(0);
                                v_list[i] = cotila::slice<state_words - 1>(M_mul.row(0), 1);
                                for (std::size_t j = 1; j < state_words; j++) {
                                    for (std::size_t k = 1; k < state_words; k++) {
                                        M_i[j][k] = M_mul[j][k];
                                    }
                                }
                                M_mul = cotila::matmul(get_mds_matrix_cotila(), M_i);
                            }
                            return equivalent_mds_matrix_type_cotila{M_i, get_mds_matrix_cotila()[0][0], w_hat_list, v_list};
                        }();
                        return equivalent_mds_matrix_cotila;
                    }

                    static inline const substate_vector_type_cotila &get_w_hat_cotila(std::size_t w_hat_number) {
                        return std::get<w_hat_list>(get_equivalent_mds_matrix_cotila())[w_hat_number];
                    }
                    static inline const substate_vector_type_cotila &get_v_cotila(std::size_t v_number) {
                        return std::get<v_list>(get_equivalent_mds_matrix_cotila())[v_number];
                    }
                    static inline const ElementType &get_M_0_0_cotila() {
                        return std::get<M_0_0>(get_equivalent_mds_matrix_cotila());
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_MDS_MATRIX_HPP
