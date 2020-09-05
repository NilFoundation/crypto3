//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_VECTOR_OPERATORS_HPP
#define ALGEBRA_VECTOR_OPERATORS_HPP

#include <nil/algebra/vector/vector.hpp>

namespace nil {
    namespace algebra {

        /** \addtogroup vector
         *  @{
         */

        /** @brief checks equality of two vectors
         *  @param a an N-vector of type T
         *  @param b an N-vector of type T
         *  @return true if and only if \f$ \textbf{a}_i = \textbf{b}_i\ \forall i \in 1\ .. N \f$
         *
         *  Checks the equality of two vectors.
         */
        template<typename T, std::size_t N>
        constexpr bool operator==(const vector<T, N> &a, const vector<T, N> &b) {
            for (std::size_t i = 0; i < vector<T, N>::size; ++i) {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }

        /** @brief checks inequality of two vectors
         *  @param a an N-vector of type T
         *  @param b an N-vector of type T
         *  @return false if and only if \f$ \textbf{a}_i = \textbf{b}_i\ \forall i \in 1\ .. N \f$
         *
         *  Checks the inequality of two vectors.
         */
        template<typename T, std::size_t N>
        constexpr bool operator!=(const vector<T, N> &a, const vector<T, N> &b) {
            return !(a == b);
        }

        /** @brief computes the vector sum
         *  @param a an N-vector of type T
         *  @param b an N-vector of type T
         *  @return \f$ \textbf{a} + \textbf{b} \f$ such that \f$ \left(\textbf{a} + \textbf{b}\right)_i = \textbf{a}_i
         * + \textbf{b}_i \f$
         *
         *  Computes the vector sum.
         */
        template<typename T, std::size_t N>
        constexpr vector<T, N> operator+(const vector<T, N> &a, const vector<T, N> &b) {
            return elementwise(std::plus<T>(), a, b);
        }

        /** @brief computes the Hadamard product
         *  @param a an N-vector of type T
         *  @param b an N-vector of type T
         *  @return \f$ \textbf{a} \circ \textbf{b} \f$ such that \f$ \left(\textbf{a} \circ \textbf{b}\right)_i =
         * \textbf{a}_i \textbf{b}_i \f$
         *
         *  Computes the Hadamard, or elementwise, product of two vectors.
         */
        template<typename T, std::size_t N>
        constexpr vector<T, N> operator*(const vector<T, N> &a, const vector<T, N> &b) {
            return elementwise(std::multiplies<T>(), a, b);
        }

        /** }@*/

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_VECTOR_OPERATORS_HPP
