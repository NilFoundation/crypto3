//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FFT_NAIVE_EVALUATE_HPP
#define CRYPTO3_ALGEBRA_FFT_NAIVE_EVALUATE_HPP

#include <algorithm>
#include <vector>

namespace nil { 
    namespace crypto3 { 
        namespace algebra {
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
                FieldValueType evaluate_polynomial(const size_t &m, const std::vector<FieldValueType> &coeff, const FieldValueType &t) {
                    if (m != coeff.size())
                        throw DomainSizeException("expected m == coeff.size()");

                    FieldValueType result = FieldValueType::zero();

                    /* NB: unsigned reverse iteration: cannot do i >= 0, but can do i < m
                       because unsigned integers are guaranteed to wrap around */
                    for (size_t i = m - 1; i < m; i--) {
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
                FieldValueType evaluate_lagrange_polynomial(const size_t &m, const std::vector<FieldValueType> &domain, const FieldValueType &t,
                                                    const size_t &idx) {
                    if (m != domain.size())
                        throw DomainSizeException("expected m == domain.size()");
                    if (idx >= m)
                        throw InvalidSizeException("expected idx < m");

                    FieldValueType num = FieldValueType::one();
                    FieldValueType denom = FieldValueType::one();

                    for (size_t k = 0; k < m; ++k) {
                        if (k == idx) {
                            continue;
                        }

                        num *= t - domain[k];
                        denom *= domain[idx] - domain[k];
                    }

                    return num * denom.inversed();
                }
                
            }    // namespace fft
        }        // namespace algebra
    }        // namespace crypto3
}    // namespace nil


#endif    // ALGEBRA_FFT_NAIVE_EVALUATE_HPP
