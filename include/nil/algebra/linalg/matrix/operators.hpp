//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_MATRIX_OPERATORS_HPP
#define ALGEBRA_MATRIX_OPERATORS_HPP

#include <nil/algebra/linalg/matrix/matrix.h>

namespace nil {
    namespace algebra {

        /** \addtogroup matrix
         *  @{
         */

        /** @brief checks equality of two matrices
         *  @param a an \f$ N \times M \f$ matrix of type T
         *  @param b an \f$ N \times M \f$ matrix of type T
         *  @return true if and only if \f$ \textbf{a}_{ij} = \textbf{b}_{ij}\ \forall i,j \in 1\ .. N \f$
         *
         *  Checks the equality of two matrices.
         */
        template <typename T, std::size_t N, std::size_t M>
        constexpr bool operator==(const matrix<T, N, M> &a,
                                  const matrix<T, N, M> &b) {
            for (std::size_t i = 0; i < N; ++i) {
                for (std::size_t j = 0; j < M; ++j) {
                    if (a[i][j] != b[i][j])
                        return false;
                }
            }
            return true;
        }

        /** @brief checks inequality of two matrices
         *  @param a an \f$ N \times M \f$ matrix of type T
         *  @param b an \f$ N \times M \f$ matrix of type T
         *  @return false if and only if \f$ \textbf{a}_{ij} = \textbf{b}_{ij}\ \forall i,j \in 1\ .. N \f$
         *
         *  Checks the inequality of two matrices.
         */
        template <typename T, std::size_t N, std::size_t M>
        constexpr bool operator!=(const matrix<T, N, M> &a,
                                  const matrix<T, N, M> &b) {
            return !(a == b);
        }

        /** }@*/

    }    // namespace algebra
}    // namespace nil

#endif // ALGEBRA_MATRIX_OPERATORS_HPP
