//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_VECTOR_MATH_HPP
#define ALGEBRA_VECTOR_MATH_HPP

#include <nil/algebra/linalg/vector/utility.hpp>
#include <nil/algebra/linalg/vector/vector.hpp>

namespace nil {
    namespace algebra {

        /** \addtogroup vector
         *  @{
         */

        /** @brief computes the dot product
         *  @param a an N-vector of type T
         *  @param b an N-vector of type T
         *  @return a scalar \f$ \textbf{a} \cdot \textbf{b} \f$ of type T such that
         *  \f$ \left(\textbf{a}\cdot\textbf{b}\right)_i = a_i \overline{b_i} \f$
         *
         *  Computes the dot (inner) product of two vectors.
         */
        template <typename T, std::size_t N>
        constexpr T dot(const vector<T, N> &a, const vector<T, N> &b) {
            T r = 0;
            for (std::size_t i = 0; i < vector<T, N>::size; ++i)
                r += a[i] * b[i];
            return r;
        }

        /** @brief computes the sum of elements
         *  @param v an N-vector of type T
         *  @return a scalar \f$ \sum\limits_{i} v_i \f$ of type T
         *
         *  Computes the sum of the elements of a vector.
         */
        template <typename T, std::size_t N> constexpr T sum(const vector<T, N> &v) {
            return accumulate(v, T(0), std::plus<T>());
        }

        /** @}*/

    }    // namespace algebra
}    // namespace nil

#endif // ALGEBRA_VECTOR_MATH_HPP
