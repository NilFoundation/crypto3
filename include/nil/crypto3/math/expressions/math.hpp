//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MATH_EXPRESSION_MATH_HPP
#define CRYPTO3_MATH_EXPRESSION_MATH_HPP

#ifndef CRYPTO3_MATH_EXPRESSION_HPP
#error "math.hpp must not be included directly!"
#endif

#include <boost/math/constants/constants.hpp>

#include <cmath>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace expressions {
                namespace detail {
                    namespace math {

                        /// @brief Sign function
                        template <typename T>
                        T sgn(T x) {
                            return (T{0} < x) - (x < T{0});
                        }

                        /// @brief isnan function with adjusted return type
                        template <typename T>
                        T isnan(T x) {
                            return std::isnan(x);
                        }

                        /// @brief isinf function with adjusted return type
                        template <typename T>
                        T isinf(T x) {
                            return std::isinf(x);
                        }

                        /// @brief Convert radians to degrees
                        template <typename T>
                        T deg(T x) {
                            return x * boost::math::constants::radian<T>();
                        }

                        /// @brief Convert degrees to radians
                        template <typename T>
                        T rad(T x) {
                            return x * boost::math::constants::degree<T>();
                        }

                        /// @brief unary plus
                        template <typename T>
                        T plus(T x) {
                            return x;
                        }

                        /// @brief binary plus
                        template <typename T>
                        T plus(T x, T y) {
                            return x + y;
                        }

                        /// @brief unary minus
                        template <typename T>
                        T minus(T x) {
                            return -x;
                        }

                        /// @brief binary minus
                        template <typename T>
                        T minus(T x, T y) {
                            return x - y;
                        }

                        /// @brief multiply
                        template <typename T>
                        T multiplies(T x, T y) {
                            return x * y;
                        }

                        /// @brief divide
                        template <typename T>
                        T divides(T x, T y) {
                            return x / y;
                        }

                        /// @brief unary not
                        template <typename T>
                        T unary_not(T x) {
                            return !x;
                        }

                        /// @brief logical and
                        template <typename T>
                        T logical_and(T x, T y) {
                            return x && y;
                        }

                        /// @brief logical or
                        template <typename T>
                        T logical_or(T x, T y) {
                            return x || y;
                        }

                        /// @brief less
                        template <typename T>
                        T less(T x, T y) {
                            return x < y;
                        }

                        /// @brief less equals
                        template <typename T>
                        T less_equals(T x, T y) {
                            return x <= y;
                        }

                        /// @brief greater
                        template <typename T>
                        T greater(T x, T y) {
                            return x > y;
                        }

                        /// @brief greater equals
                        template <typename T>
                        T greater_equals(T x, T y) {
                            return x >= y;
                        }

                        /// @brief equals
                        template <typename T>
                        T equals(T x, T y) {
                            return x == y;
                        }

                        /// @brief not equals
                        template <typename T>
                        T not_equals(T x, T y) {
                            return x != y;
                        }

                    } // namespace math
                }    // namespace detail    
            }    // namespace expressions
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_EXPRESSION_MATH_HPP