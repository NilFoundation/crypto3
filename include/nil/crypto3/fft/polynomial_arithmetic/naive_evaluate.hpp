//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FFT_NAIVE_EVALUATE_HPP
#define CRYPTO3_ALGEBRA_FFT_NAIVE_EVALUATE_HPP

#include <algorithm>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace fft {

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
            template<typename FieldValueType>
            FieldValueType evaluate_polynomial(const std::size_t &m, const std::vector<FieldValueType> &coeff,
                                               const FieldValueType &t) {
                // if (m != coeff.size())
                //    throw DomainSizeException("expected m == coeff.size()");

                FieldValueType result = FieldValueType::zero();

                /* NB: unsigned reverse iteration: cannot do i >= 0, but can do i < m
                   because unsigned integers are guaranteed to wrap around */
                for (std::size_t i = m - 1; i < m; i--) {
                    result = (result * t) + coeff[i];
                }

                return result;
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
            template<typename FieldValueType>
            FieldValueType evaluate_lagrange_polynomial(const std::size_t &m, const std::vector<FieldValueType> &domain,
                                                        const FieldValueType &t, const std::size_t &idx) {
                // if (m != domain.size())
                //    throw DomainSizeException("expected m == domain.size()");
                // if (idx >= m)
                //    throw InvalidSizeException("expected idx < m");

                FieldValueType num = FieldValueType::one();
                FieldValueType denom = FieldValueType::one();

                for (std::size_t k = 0; k < m; ++k) {
                    if (k == idx) {
                        continue;
                    }

                    num *= t - domain[k];
                    denom *= domain[idx] - domain[k];
                }

                return num * denom.inversed();
            }

        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_NAIVE_EVALUATE_HPP
