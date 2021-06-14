//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_MATRIX_CLASS_HPP
#define CRYPTO3_ALGEBRA_MATRIX_CLASS_HPP

#include <array>
#include <tuple>

#include <nil/crypto3/detail/assert.hpp>

#include <nil/crypto3/algebra/vector/utility.hpp>
#include <nil/crypto3/algebra/vector/vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            /** @brief A container representing a matrix
             *    @tparam T scalar type to contain
             *    @tparam N number of rows
             *    @tparam M number of columns
             *
             *    `matrix` is a container representing a matrix.
             *    It is an aggregate type containing a single member array of type
             *    `T[N][M]` which can be initialized with aggregate initialization.
             */
            template<typename T, std::size_t N, std::size_t M>
            struct matrix {
                static_assert(N != 0 && M != 0, "matrix must have have positive dimensions");

                // CRYPTO3_DETAIL_ASSERT_ARITHMETIC(T)

                using value_type = T;
                using size_type = std::size_t;
                static constexpr size_type column_size = N;    ///< Number of rows
                static constexpr size_type row_size = M;       ///< Number of columns

                /** @name Element access */
                ///@{
                /** @brief access specified row
                 *    @param i index of the row to extract
                 *    @return the selected row
                 *
                 *    Extracts a row from the matrix.
                 */
                constexpr vector<T, M> row(std::size_t i) const {
                    if (i >= N)
                        throw "index out of range";
                    return generate<M>([i, this](std::size_t j) { return arrays[i][j]; });
                }

                /** @brief access specified column
                 *    @param i index of the column to extract
                 *    @return the selected row
                 *
                 *    Extracts a column from the matrix
                 */
                constexpr vector<T, N> column(std::size_t i) const {
                    if (i >= M)
                        throw "index out of range";
                    return generate<N>([i, this](std::size_t j) { return arrays[j][i]; });
                }

                /** @brief access specified element
                 *    @param i index of the row
                 *    @return pointer to the specified row
                 *
                 *    This function returns a pointer to the specified row.    The intention
                 *    of this function is to then access the specified element from the
                 *    row pointer.    For a matrix `m`, accessing the element in the 5th row
                 *    and 3rd column can be done with `m[5][3]`.
                 */
                constexpr T *operator[](std::size_t i) {
                    return arrays[i];
                }

                /// @copydoc operator[]
                constexpr T const *operator[](std::size_t i) const {
                    return arrays[i];
                }
                ///@}

            private:
                T arrays[N][M];    ///< @private
            };

            /** \addtogroup matrix
             *    @{
             */

            /** @name matrix deduction guides */
            ///@{

            /** @brief deduction guide for aggregate initialization
             *    @relatesalso matrix
             *
             *    This deduction guide allows matrix to be constructed like this:
             *    \code{.cpp}
             *    matrix m{{{1., 2.}, {3., 4.}}}; // deduces the type of m to be matrix<double, 2, 2>
             *    \endcode
             */
            template<typename T, std::size_t M, std::size_t N>
            matrix(const T (&)[M][N]) -> matrix<T, M, N>;

            ///@}

            /** @}*/

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_MATRIX_CLASS_HPP
