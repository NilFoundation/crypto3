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
#include <nil/algebra/fields/operations.hpp>

#include <boost/assert.hpp>
#include <boost/multiprecision/cpp_int.hpp>
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
                    typedef std::array<state_vector_type, part_rounds> subvectors_collection;
                    // (M', M_0_0, w_hat_list, v_list)
                    enum : std::size_t { M_i, M_0_0, w_hat_list, v_list };
                    typedef std::tuple<mds_matrix_type, ElementType, subvectors_collection,
                        subvectors_collection> equivalent_mds_matrix_type;

                    inline void product_with_mds_matrix(const state_vector_type &A_vector_in, state_vector_type &A_vector_out) const {

                        A_vector_out = boost::numeric::ublas::prod(A_vector_in, get_mds_matrix());
                    }

                    inline void product_with_inverse_mds_matrix(const state_vector_type &A_vector_in, state_vector_type &A_vector_out) const {

                        A_vector_out = boost::numeric::ublas::prod(A_vector_in, get_inverse_mds_matrix());
                    }

                    inline void product_with_equivalent_mds_matrix_init(const state_vector_type &A_vector_in, state_vector_type &A_vector_out, std::size_t round_number) const {
                        BOOST_ASSERT_MSG(round_number == half_full_rounds, "wrong using: product_with_equivalent_mds_matrix_init");
                        A_vector_out = boost::numeric::ublas::prod(A_vector_in, std::get<M_i>(get_equivalent_mds_matrix()));
                    }


                    inline void product_with_equivalent_mds_matrix(const state_vector_type &A_vector_in, state_vector_type &A_vector_out, std::size_t round_number) const {
                        BOOST_ASSERT_MSG(round_number >= half_full_rounds
                                        && round_number < half_full_rounds + part_rounds, "wrong using: product_with_equivalent_mds_matrix");
                        const std::size_t matrix_number_base = part_rounds - (round_number - half_full_rounds) - 1;
                        const state_vector_type &w_hat = get_w_hat(matrix_number_base);
                        const state_vector_type &v = get_v(matrix_number_base);
                        state_vector_type temp_vector(state_words);
                        ElementType A_0 = A_vector_in[0];
                        temp_vector[0] = get_M_0_0();
                        boost::numeric::ublas::subrange(temp_vector, 1, temp_vector.size()) = w_hat;
                        A_vector_out[0] = boost::numeric::ublas::inner_prod(A_vector_in, temp_vector);
                        for (std::size_t i = 1; i < state_words; i++) {
                            A_vector_out[i] = A_0 * v[i - 1] + A_vector_in[i];
                        }
                    }

                // private:
                    // See http://www.crystalclearsoftware.com/cgi-bin/boost_wiki/wiki.pl?LU_Matrix_Inversion
                    inline bool InvertMatrix(const mds_matrix_type &mds_matrix, mds_matrix_type &inverse) const {
                        mds_matrix_type mds_matrix_temp(mds_matrix);
                        // using namespace boost::numeric::ublas;
                        typedef boost::numeric::ublas::permutation_matrix<std::size_t> pmatrix;
                        // create a permutation matrix for the LU-factorization
                        pmatrix pm(mds_matrix_temp.size1());
                        // perform LU-factorization
                        int res = boost::numeric::ublas::lu_factorize(mds_matrix_temp, pm);
                        if( res != 0 )
                            return false;
                        // create identity matrix of "inverse"
                        inverse.assign(boost::numeric::ublas::identity_matrix<ElementType>(mds_matrix_temp.size1()));
                        // backsubstitute to get the inverse
                        boost::numeric::ublas::lu_substitute(mds_matrix_temp, pm, inverse);
                        return true;
                    }

                    inline const mds_matrix_type &get_inverse_mds_matrix() const {
                        static const mds_matrix_type inverse_mds_matrix = [this](){
                            // cout << "get_inverse_mds_matrix" << '\n';
                            mds_matrix_type inverse_mds_matrix(state_words, state_words);
                            BOOST_ASSERT_MSG(InvertMatrix(get_mds_matrix(), inverse_mds_matrix), "MDS matrix is not invertible");
                            return inverse_mds_matrix;
                        }();
                        return inverse_mds_matrix;
                    }

                    inline const mds_matrix_type &get_mds_matrix() const {
                        static const mds_matrix_type mds_matrix = [](){
                            // cout << "generate_mds_matrix" << '\n';
                            mds_matrix_type mds_matrix(state_words, state_words);
                            for (std::size_t i = 0; i < state_words; i++) {
                                for (std::size_t j = 0; j < state_words; j++) {
                                    // TODO: change according to algebra interface
                                    mds_matrix.insert_element(i, j, ElementType(
                                        cpp_int(i + (j + state_words))
                                    ).get_inverse());
                                }
                            }
                            return mds_matrix;
                        }();
                        return mds_matrix;
                    }

                    inline const equivalent_mds_matrix_type &get_equivalent_mds_matrix() const {
                        static const equivalent_mds_matrix_type equivalent_mds_matrix = [this](){
                            const mds_matrix_type mds_matrix = get_mds_matrix();
                            mds_matrix_type M_mul(mds_matrix);
                            mds_matrix_type M_i(
                                boost::numeric::ublas::identity_matrix<ElementType>(M_mul.size1()));
                            mds_matrix_type M_hat_inverse(state_words - 1, state_words - 1);
                            subvectors_collection w_hat_list;
                            subvectors_collection v_list;
                            for (std::size_t i = 0; i < part_rounds; i++) {
                                InvertMatrix(boost::numeric::ublas::subrange(M_mul, 1, M_mul.size1(), 1, M_mul.size2()),
                                    M_hat_inverse);
                                w_hat_list[i] = boost::numeric::ublas::prod(M_hat_inverse,
                                    boost::numeric::ublas::subrange(
                                        boost::numeric::ublas::column(M_mul, 0), 1, M_mul.size1()));
                                v_list[i] = boost::numeric::ublas::subrange(
                                    boost::numeric::ublas::row(M_mul, 0), 1, M_mul.size2());
                                boost::numeric::ublas::subrange(M_i, 1, M_i.size1(), 1, M_i.size2()) =
                                    boost::numeric::ublas::subrange(M_mul, 1, M_mul.size1(), 1, M_mul.size2());
                                M_mul = boost::numeric::ublas::prod(mds_matrix, M_i);
                            }
                            return equivalent_mds_matrix_type{M_i, mds_matrix(0, 0), w_hat_list, v_list};
                        }();
                        return equivalent_mds_matrix;
                    }

                    inline const state_vector_type &get_w_hat(std::size_t w_hat_number) const {
                        return std::get<w_hat_list>(get_equivalent_mds_matrix())[w_hat_number];
                    }
                    inline const state_vector_type &get_v(std::size_t v_number) const {
                        return std::get<v_list>(get_equivalent_mds_matrix())[v_number];
                    }
                    inline const ElementType &get_M_0_0() const {
                        return std::get<M_0_0>(get_equivalent_mds_matrix());
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_MDS_MATRIX_HPP
