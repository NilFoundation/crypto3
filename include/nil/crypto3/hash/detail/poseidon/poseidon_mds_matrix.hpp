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
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/numeric/ublas/vector.hpp>
#include <boost/numeric/ublas/matrix.hpp>
#include <boost/numeric/ublas/lu.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename FieldType, typename ElementType, std::size_t Arity, bool strength>
                struct poseidon_mds_matrix {
                    typedef poseidon_policy<FieldType, ElementType, Arity, strength> policy_type;

                    constexpr static const std::size_t state_words = policy_type::state_words;
                    typedef typename policy_type::state_type state_type;

                    typedef boost::numeric::ublas::matrix<ElementType> mds_matrix_type;
                    typedef boost::numeric::ublas::vector<ElementType> state_vector_type;

                    inline void product_with_mds_matrix(state_vector_type const &A_vector_in,
                                                        state_vector_type &A_vector_out) const {
                        A_vector_out = boost::numeric::ublas::prod(A_vector_in, get_mds_matrix());
                    }

                    inline void product_with_inverse_mds_matrix(state_vector_type const &A_vector_in,
                                                                state_vector_type &A_vector_out) const {
                        A_vector_out = boost::numeric::ublas::prod(A_vector_in, get_inverse_mds_matrix());
                    }

                    // private:
                    // See http://www.crystalclearsoftware.com/cgi-bin/boost_wiki/wiki.pl?LU_Matrix_Inversion
                    inline bool InvertMatrix(mds_matrix_type const &mds_matrix, mds_matrix_type &inverse) const {
                        // mds_matrix_type mds_matrix = get_mds_matrix();
                        mds_matrix_type mds_matrix_temp(mds_matrix);
                        // using namespace boost::numeric::ublas;
                        typedef boost::numeric::ublas::permutation_matrix<std::size_t> pmatrix;
                        // create a permutation matrix for the LU-factorization
                        pmatrix pm(mds_matrix_temp.size1());
                        // perform LU-factorization
                        int res = boost::numeric::ublas::lu_factorize(mds_matrix_temp, pm);
                        if (res != 0)
                            return false;
                        // create identity matrix of "inverse"
                        inverse.assign(boost::numeric::ublas::identity_matrix<ElementType>(mds_matrix_temp.size1()));
                        // backsubstitute to get the inverse
                        boost::numeric::ublas::lu_substitute(mds_matrix_temp, pm, inverse);
                        return true;
                    }

                    inline mds_matrix_type const &get_inverse_mds_matrix() const {
                        static mds_matrix_type const inverse_mds_matrix = [this]() {
                            // cout << "get_inverse_mds_matrix" << '\n';
                            mds_matrix_type inverse_mds_matrix(state_words, state_words);
                            BOOST_ASSERT_MSG(InvertMatrix(get_mds_matrix(), inverse_mds_matrix),
                                             "MDS matrix is not invertible");
                            return inverse_mds_matrix;
                        }();
                        return inverse_mds_matrix;
                    }

                    inline mds_matrix_type const &get_mds_matrix() const {
                        static mds_matrix_type const mds_matrix = []() {
                            // cout << "generate_mds_matrix" << '\n';
                            mds_matrix_type mds_matrix(state_words, state_words);
                            for (std::size_t i = 0; i < state_words; i++) {
                                for (std::size_t j = 0; j < state_words; j++) {
                                    mds_matrix.insert_element(
                                        i, j,
                                        FieldType(boost::multiprecision::cpp_int(i + (j + state_words))).get_inverse());
                                }
                            }
                            return mds_matrix;
                        }();
                        return mds_matrix;
                    }

                    // inline
                };

            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_POSEIDON_MDS_MATRIX_HPP
