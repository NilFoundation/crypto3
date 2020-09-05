//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_MATRIX_MATH_HPP
#define ALGEBRA_MATRIX_MATH_HPP

#include <algorithm>

#include <nil/algebra/vector/vector.hpp>
#include <nil/algebra/vector/math.hpp>

#include <nil/algebra/matrix/matrix.hpp>
#include <nil/algebra/matrix/utility.hpp>

#include <nil/algebra/scalar/math.hpp>

namespace nil {
    namespace algebra {

        /** \addtogroup matrix
         *  @{
         */

        /** @brief computes the matrix product
         *  @param a an \f$M \times N\f$ matrix
         *  @param b an \f$N \times P\f$ matrix
         *  @return an \f$ M \times P \f$ matrix \f$ \textbf{a}\textbf{b} \f$ of type T such that
         *  \f$ \left(\textbf{ab}\right)_{ij} = \sum\limits_{k=1}^{N}\textbf{a}_{ik}\textbf{b}_{kj} \f$
         *
         *  Computes the product of two matrices.
         */
        template <typename T, std::size_t M, std::size_t N, std::size_t P>
        constexpr matrix<T, M, P> matmul(const matrix<T, M, N> &a,
                                                                        const matrix<T, N, P> &b) {
            return generate<M, P>([&a, &b](auto i, auto j){return sum(a.row(i)*b.column(j));});
        }

        template <typename T, std::size_t M, std::size_t N>
        constexpr vector<T, N> vectmatmul(const vector<T, M> &v,
                                                                            const matrix<T, M, N> &m) {
            return generate<N>([&v, &m](auto i){return sum(v*m.column(i));});
        }

        /// @private
        template <typename T, std::size_t M, std::size_t N>
        constexpr std::tuple<matrix<T, M, N>, std::size_t, T>
        gauss_jordan_impl(matrix<T, M, N> m) {

            // Define function for determining if an element is negligible
            auto negligible = [](const T &v) { return abs(v) <= 0; };

            T det = 1;
            std::size_t rank = 0;
            std::size_t i = 0, j = 0;
            while (i < M && j < N) {
                // Choose largest magnitude as pivot to avoid adding different magnitudes
                for (std::size_t ip = i + 1; ip < M; ++ip) {
                    if (abs(m[ip][j]) > abs(m[i][j])) {
                        for (std::size_t jp = 0; jp < N; ++jp) {
                            auto tmp = m[ip][jp];
                            m[ip][jp] = m[i][jp];
                            m[i][jp] = tmp;
                        }
                        det *= -1;
                        break;
                    }
                }

                // If m_ij is still 0, continue to the next column
                if (!negligible(m[i][j])) {
                    // Scale m_ij to 1
                    auto s = m[i][j];
                    for (std::size_t jp = 0; jp < N; ++jp)
                        m[i][jp] /= s;
                    det /= s;

                    // Eliminate other values in the column
                    for (std::size_t ip = 0; ip < M; ++ip) {
                        if (ip == i)
                            continue;
                        if (!negligible(m[ip][j])) {
                            auto s = m[ip][j];
                            [&]() { // wrap this in a lambda to get around a gcc bug
                                for (std::size_t jp = 0; jp < N; ++jp)
                                    m[ip][jp] -= s * m[i][jp];
                            }();
                        }
                    }

                    // Increment rank
                    ++rank;

                    // Select next row
                    ++i;
                }
                ++j;
            }
            det = (rank == M) ? det : 0;
            return {m, rank, det};
        }

        /** @brief Compute the reduced row echelon form
         *  @param m an \f$ M \times N \f$ matrix of type T
         *  @return an \f$ M \times N \f$ matrix of type T, the reduced row echelon form
         * of \f$ \textbf{m} \f$
         *
         *  Computes the reduced row echelon form of a matrix using Gauss-Jordan
         * elimination.  The tolerance for determining negligible elements is \f$
         * \max\left(N, M\right) \cdot \epsilon \cdot {\left\lVert \textbf{m}
         * \right\rVert}_\infty \f$.
         */
        template <typename T, std::size_t M, std::size_t N>
        constexpr matrix<T, M, N> rref(const matrix<T, M, N> &m) {
            return std::get<0>(gauss_jordan_impl(m));
        }

        /** @brief Compute the rank
         *  @param m \f$ M \times N \f$ matrix of type T
         *  @return a scalar \f$ \textrm{rank}\left(\textbf{m}\right) \f$
         *
         *  Computes the rank using the reduced row echelon form.
         */
        template <typename T, std::size_t M, std::size_t N>
        constexpr std::size_t rank(const matrix<T, M, N> &m) {
            return std::get<1>(gauss_jordan_impl(m));
        }

        /** @brief computes the matrix inverse
         *  @param m an \f$ M \times M \f$ matrix of type T
         *  @return The inverse of \f$ \textbf{m} \f$, \f$ \textbf{m}^{-1}\f$ such that
         *  \f$ \textbf{m}\textbf{m}^{-1} = \textbf{m}^{-1}\textbf{m} = \textbf{I}_{M}
         * \f$
         *
         *  Computes the inverse of a matrix using the reduced row echelon form.
         */
        template <typename T, std::size_t M>
        constexpr matrix<T, M, M> inverse(const matrix<T, M, M> &m) {
            if (rank(m) < M)
                throw "matrix is not invertible";
            return submat<M, M>(rref(horzcat(m, identity<T, M>)), 0, M);
        }

        /** }@*/

    }    // namespace algebra
}    // namespace nil

#endif // ALGEBRA_MATRIX_MATH_HPP
