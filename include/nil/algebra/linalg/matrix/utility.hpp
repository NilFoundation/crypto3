//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_MATRIX_UTILITY_HPP
#define ALGEBRA_MATRIX_UTILITY_HPP

#include <nil/algebra/linalg/matrix/matrix.hpp>

#include <tuple>

namespace nil {
    namespace algebra {

        /** \addtogroup matrix
         *  @{
         */

        /** @brief applies a function elementwise between many matrices
            *  @param f a function of type F that operates on many scalars of type T and returns a scalar of type U
            *  @param m an \f$ N \times M \f$ matrix of type T
            *  @param matrices additional \f$ N \times M \f$ matrices of type T
            *  @return an \f$ N \times M \f$ matrix of type T with elements described by \f$ f\left(\textbf{m}_{ij}, \ldots\right) \f$
            *
            *  Applies a function elementwise between many matrices.
            */
        template <
                typename F, typename T, typename... Matrices,
                typename U = std::invoke_result_t<F, T, typename Matrices::value_type...>,
                std::size_t N =
                        detail::all_same_value<std::size_t, Matrices::column_size...>::value,
                std::size_t M =
                        detail::all_same_value<std::size_t, Matrices::row_size...>::value>
        constexpr matrix<U, N, M> elementwise(F f, const matrix<T, N, M> &m,
                                                                                    const Matrices &... matrices) {
            matrix<U, N, M> op_applied = {};
            for (std::size_t i = 0; i < N; ++i) {
                for (std::size_t j = 0; j < M; ++j) {
                    op_applied[i][j] =
                            std::apply(f, std::forward_as_tuple(m[i][j], matrices[i][j]...));
                }
            }
            return op_applied;
        }

        /** @brief generates a matrix as a function of its indices
         *  @param f a function that operates on two integer indices
         *  @return an \f$ N \times M \f$ matrix with type matching the return type of f such that \f$ \textbf{m}_{ij} = f(i, j) \f$
         *
         *  Generates a matrix as a function of its indices.
         */
        template <std::size_t N, std::size_t M, typename F>
        constexpr decltype(auto) generate(F &&f) {
            matrix<std::invoke_result_t<F, std::size_t, std::size_t>, N, M> generated =
                    {};
            for (std::size_t i = 0; i < N; ++i) {
                for (std::size_t j = 0; j < M; ++j) {
                    generated[i][j] = std::apply(f, std::forward_as_tuple(i, j));
                }
            }
            return generated;
        }

        /** @brief generates a matrix containing a single value
         *  @param value the scalar value of all elements
         *  @return an \f$ N \times M \f$ matrix of type T such that \f$ \textbf{m}_{ij} = \textrm{value}\ \forall i,j \f$
         *
         *  Generates a matrix with all elements equal to a single value.
         */
        template <std::size_t N, std::size_t M, typename T>
        constexpr matrix<T, N, M> fill(T value) {
            return generate<N, M>([value](std::size_t, std::size_t) { return value; });
        }

        /** @brief the matrix identity
         *
         *  The matrix identity \f$ I_N \f$.
         */
        template <typename T, std::size_t N>
        constexpr matrix<T, N, N> identity
        // const matrix<T, N, N> identity
            = generate<N, N>([](std::size_t i, std::size_t j) { return T(i == j ? 1 : 0); });

        /** @brief horizontally concatenates two matrices
         *  @param a an \f$ M \times N \f$ matrix of type T
         *  @param b an \f$ M \times P \f$ matrix of type T
         *  @return an \f$ M \times \left(N+P\right) \f$ matrix of type T \f$ \left[\textbf{a} \textbf{b}\right] \f$ such that
         *  \f$ \left(\left[\textbf{a} \textbf{b}\right]\right)_{ij} = \begin{cases} \textbf{a}_{ij} & j < N\\ \textbf{b}_{i,\ \left(j - N\right)} & j \ge N \end{cases} \f$
         *
         *  Horizontally concatenates two matrices.
         */
        template<std::size_t M, std::size_t N, std::size_t P, typename T>
        constexpr matrix<T, M, N + P> horzcat(const matrix<T, M, N> &a, const matrix<T, M, P> &b){
                return generate<M, N+P>([&a, &b](std::size_t i, std::size_t j){
                        return j < N ? a[i][j] : b[i][j - N];
                });
        }

        /** @brief extracts the submatrix of a matrix
         *  @param m an \f$ M \times N \f$ matrix of type T
         *  @param a the starting index into the rows
         *  @param b the starting index into the columns
         *  @return an \f$ P \times Q \f$ submatrix \f$ \textbf{m}' \f$ of type T such that
         *  \f$ {\textbf{m}'}_{ij} = \textbf{m}_{\left(a + i\right),\ \left(b + j\right)} \f$
         *
         *  Extracts the submatrix of a matrix.
         */
        template<std::size_t P, std::size_t Q, std::size_t M, std::size_t N, typename T>
        constexpr matrix<T, P, Q> submat(const matrix<T, M, N> &m, std::size_t a, std::size_t b){
                if ((a + P > M) || (b + Q > N)) throw "index out of range";
                return generate<P, Q>([&m, &a, &b](std::size_t i, std::size_t j){
                        return m[a + i][b + j];
                });
        }

        /** }@*/

    }    // namespace algebra
}    // namespace nil

#endif // ALGEBRA_MATRIX_UTILITY_HPP
