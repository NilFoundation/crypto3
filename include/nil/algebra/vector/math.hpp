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

#include <nil/algebra/vector/utility.hpp>
#include <nil/algebra/vector/vector.hpp>

namespace nil {
    namespace algebra {

        /** \addtogroup vector
         *  @{
         */

        /** @brief computes the elementwise complex conjugate
         *  @param v an N-vector of type T
         *  @return an N-vector \f$ \overline{\textbf{v}} \f$ of type T such that
         *  \f$ \left(\overline{\textbf{v}}\right)_i = \overline{v_i} \f$
         *
         *  Computes the elementwise complex conjugate of a vector.
         */
        template<typename T, std::size_t N>
        constexpr vector<T, N> conj(const vector<T, N> &v) {
            return elementwise(algebra::conj<T>, v);
        }

        /** @brief computes the elementwise square root
         *  @param v an N-vector of type T
         *  @return an N-vector \f$ \begin{bmatrix} \sqrt{v_1} & \ldots &\sqrt{v_N} \end{bmatrix} \f$ of type T
         *
         *  Computes the elementwise square root of a vector.
         */
        template<typename T, std::size_t N>
        constexpr vector<T, N> sqrt(const vector<T, N> &v) {
            return elementwise(static_cast<T (*)(T)>(sqrt), v);
        }

        /** @brief computes the elementwise real
         * @param v an N-vector of type T
         * @return an N-vector \f$ \textbf{u} \f$ of type T such that
         * \f$ \textbf{u}_i = \mathbb{R}\{\textbf{v}_i\} \f$
         *
         * Computes the elementwise real of a vector.
         */
        template<typename T, std::size_t N>
        constexpr vector<detail::remove_complex_t<T>, N> real(const vector<T, N> &v) {
            return elementwise([](auto i) { return std::real(i); }, v);
        }

        /** @brief computes the elementwise imag
         * @param v an N-vector of type T
         * @return an N-vector \f$ \textbf{u} \f$ of type T such that
         * \f$ \textbf{u}_i = \mathbb{I}\{\textbf{v}_i\} \f$
         *
         * Computes the elementwise imag of a vector.
         */
        template<typename T, std::size_t N>
        constexpr vector<detail::remove_complex_t<T>, N> imag(const vector<T, N> &v) {
            return elementwise([](auto i) { return std::imag(i); }, v);
        }

        /** @brief computes the elementwise absolute value
         *  @param v an N-vector of type T
         *  @return an N-vector \f$ \begin{bmatrix} \lvert v_1 \rvert & \ldots & \lvert v_N \rvert \end{bmatrix} \f$ of
         * type T
         *
         *  Computes the elementwise absolute value of a vector.
         */
        template<typename T, std::size_t N>
        constexpr vector<detail::remove_complex_t<T>, N> abs(const vector<T, N> &v) {
            return elementwise(abs<T>, v);
        }

        /** @brief computes the dot product
         *  @param a an N-vector of type T
         *  @param b an N-vector of type T
         *  @return a scalar \f$ \textbf{a} \cdot \textbf{b} \f$ of type T such that
         *  \f$ \left(\textbf{a}\cdot\textbf{b}\right)_i = a_i \overline{b_i} \f$
         *
         *  Computes the dot (inner) product of two vectors.
         */
        template<typename T, std::size_t N>
        constexpr T dot(const vector<T, N> &a, const vector<T, N> &b) {
            T r = 0;
            for (std::size_t i = 0; i < vector<T, N>::size; ++i)
                r += a[i] * conj(b[i]);
            return r;
        }

        /** @brief computes the sum of elements
         *  @param v an N-vector of type T
         *  @return a scalar \f$ \sum\limits_{i} v_i \f$ of type T
         *
         *  Computes the sum of the elements of a vector.
         */
        template<typename T, std::size_t N>
        constexpr T sum(const vector<T, N> &v) {
            return accumulate(v, 0, std::plus<T>());
        }

        /** @brief computes the minimum valued element
         *  @param v an N-vector of type T
         *  @return a scalar \f$ v_i \f$ of type T where \f$ v_i \leq v_j,\ \forall j \f$
         *
         *  Computes the minimum valued element of a vector.
         */
        template<typename T, std::size_t N>
        constexpr T min(const vector<T, N> &v) {
            return accumulate(v, v[0], [](T a, T b) { return std::min(a, b); });
        }

        /** @brief computes the maximum valued element
         *  @param v an N-vector of type T
         *  @return a scalar \f$ v_i \f$ of type T where \f$ v_i \geq v_j,\ \forall j \f$
         *
         *  Computes the maximum valued element of a vector.
         */
        template<typename T, std::size_t N>
        constexpr T max(const vector<T, N> &v) {
            return accumulate(v, v[0], [](T a, T b) { return std::max(a, b); });
        }

        /** @brief computes the index of the minimum valued element
         *  @param v an N-vector of type T
         *  @return an index \f$ i \f$ where \f$ v_i \leq v_j,\ \forall j \f$
         *
         *  Computes the index of the minimum valued element of a vector.
         *  Note: the return value is zero-indexed.
         */
        template<typename T, std::size_t N>
        constexpr std::size_t min_index(const vector<T, N> &v) {
            T min = v[0];
            std::size_t index = 0;
            for (std::size_t i = 0; i < vector<T, N>::size; ++i)
                if (v[i] < min) {
                    index = i;
                    min = v[i];
                }
            return index;
        }

        /** @brief computes the index of the maximum valued element
         *  @param v an N-vector of type T
         *  @return an index \f$ i \f$ where \f$ v_i \geq v_j,\ \forall j \f$
         *
         *  Computes the index of the maximum valued element of a vector.
         *  Note: the return value is zero-indexed.
         */
        template<typename T, std::size_t N>
        constexpr std::size_t max_index(const vector<T, N> &v) {
            T max = v[0];
            std::size_t index = 0;
            for (std::size_t i = 0; i < vector<T, N>::size; ++i)
                if (v[i] > max) {
                    index = i;
                    max = v[i];
                }
            return index;
        }

        /** @}*/

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_VECTOR_MATH_HPP
