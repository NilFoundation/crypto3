//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MATH_EVALUATE_HPP
#define CRYPTO3_MATH_EVALUATE_HPP

#include <algorithm>
#include <vector>

#include <boost/math/tools/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            /*!
             * @brief
             * Naive evaluation of a *single* polynomial, used for testing purposes.
             *
             * The inputs are:
             * - an integer m
             * - a vector coeff representing monomial P of size m
             * - a field element element t
             * The output is the polynomial P(x) evaluated at x = t.
             */
            template<typename FieldValueType, typename ContiguousIterator>
            inline FieldValueType evaluate_polynomial(ContiguousIterator first, ContiguousIterator last,
                                                      const FieldValueType &t, std::size_t m) {
                BOOST_ASSERT(std::size_t(std::distance(first, last)) == m);

                return boost::math::tools::evaluate_polynomial(&*first, t, m);
            }

            template<typename FieldValueType, typename ContiguousContainer>
            inline FieldValueType evaluate_polynomial(const ContiguousContainer &coeff, const FieldValueType &t,
                                                      std::size_t m) {
                return evaluate_polynomial(coeff.begin(), coeff.end(), t, m);
            }

            /*!
             * @brief
             * Naive evaluation of a *single* Lagrange polynomial, used for testing purposes.
             *
             * The inputs are:
             * - an integer m
             * - a domain S = (a_{0},...,a_{m-1}) of size m
             * - a field element element t
             * - an index idx in {0,...,m-1}
             * The output is the polynomial L_{idx,S}(z) evaluated at z = t.
             */
            template<typename FieldValueType, typename InputIterator>
            inline FieldValueType evaluate_lagrange_polynomial(InputIterator first, InputIterator last,
                                                               const FieldValueType &t, std::size_t m,
                                                               std::size_t idx) {
                typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                BOOST_STATIC_ASSERT(std::is_same<value_type, FieldValueType>::value);

                if (m != std::size_t(std::distance(first, last))) {
                    throw std::invalid_argument("expected m == domain.size()");
                }
                if (idx >= m) {
                    throw std::invalid_argument("expected idx < m");
                }

                value_type num = value_type::one();
                value_type denom = value_type::one();

                for (std::size_t k = 0; k < m; ++k) {
                    if (k == idx) {
                        continue;
                    }

                    num *= t - *(first + k);
                    denom *= *(first + idx) - *(first + k);
                }

                return num * denom.inversed();
            }

            template<typename FieldValueType, typename Range>
            inline FieldValueType evaluate_lagrange_polynomial(const Range &domain, const FieldValueType &t,
                                                               std::size_t m, std::size_t idx) {
                typedef FieldValueType value_type;
                BOOST_STATIC_ASSERT(std::is_same<value_type, typename std::iterator_traits<decltype(std::begin(
                                                                 std::declval<Range>()))>::value_type>::value);

                return evaluate_lagrange_polynomial(domain.begin(), domain.end(), t, m, idx);
            }
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_NAIVE_EVALUATE_HPP
