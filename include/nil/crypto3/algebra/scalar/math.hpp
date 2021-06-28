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

#ifndef CRYPTO3_ALGEBRA_SCALAR_MATH_HPP
#define CRYPTO3_ALGEBRA_SCALAR_MATH_HPP

#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/detail/assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            /** \addtogroup scalar
             *  @{
             */

            /** @brief computes the square root
             *  @param x argument
             *  @return \f$ \sqrt{x} \f$
             *
             *  Computes the square root.
             */
            constexpr double sqrt(double x) {
                if (x < 0)
                    throw "sqrt argument must be positive";
                double prev = 0;
                double est = (1 + x) / 2;
                while (prev != est) {
                    prev = est;
                    est = (est + x / est) / 2;
                }
                return est;
            }

            /** @brief computes the square root
             *  @param x argument
             *  @return \f$ \sqrt{x} \f$
             *
             *  Computes the square root.
             */
            constexpr float sqrt(float x) {
                return sqrt(double(x));
            }

            /** @brief computes the absolute value
             *  @param x argument
             *  @return \f$ \lvert x \rvert \f$
             *
             *  Computes the absolute value.
             */
            template<typename T>
            constexpr nil::crypto3::detail::remove_complex_t<T> abs(T x) {
                // CRYPTO3_DETAIL_ASSERT_ARITHMETIC(T);
                if constexpr (algebra::is_complex_v<T>)
                    return sqrt(x.real() * x.real() + x.imag() * x.imag());
                else
                    return x > 0 ? x : -x;
            }

            /** @brief computes exponents
             *  @param x base
             *  @param n exponent
             *  @return \f$ x^n \f$
             *
             *  Computes the exponentiation of a value to integer powers.
             */
            constexpr double exponentiate(double x, int n) {
                if (n == 0)
                    return 1;
                if (n < 0) {
                    x = 1. / x;
                    n = -n;
                }
                double y = 1.;
                while (n > 1) {
                    if (n % 2 == 0) {
                        n = n / 2.;
                    } else {
                        y *= x;
                        n = (n - 1.) / 2.;
                    }
                    x *= x;
                }
                return x * y;
            }

            /** @brief computes the \f$n\f$th root
             *  @param x argument
             *  @param n degree
             *  @return \f$ \sqrt[\leftroot{-2}\uproot{2}n]{x} \f$
             *
             *  Computes the \f$n\f$th root.
             */
            constexpr double nthroot(double x, int n) {
                if (x < 0)
                    throw "nth root argument must be positive";
                double prev = -1;
                double est = 1;
                while (prev != est) {
                    prev = est;
                    double dxk = 1. / n * (x / exponentiate(prev, n - 1) - prev);
                    est = prev + dxk;
                }
                return est;
            }

            /** @brief computes the complex conjugate
             *  @param x argument
             *  @return \f$ \bar{x} \f$
             *
             *  Computes the complex conjugate.
             */
            template<typename T>
            constexpr T conj(T x) {
                // CRYPTO3_DETAIL_ASSERT_ARITHMETIC(T);
                if constexpr (algebra::is_complex_v<T>)
                    return {x.real(), -x.imag()};
                else
                    return x;
            }

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_SCALAR_MATH_HPP
