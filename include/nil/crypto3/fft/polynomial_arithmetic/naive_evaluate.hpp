//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FFT_NAIVE_EVALUATE_HPP
#define CRYPTO3_FFT_NAIVE_EVALUATE_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/fft/tools/exceptions.hpp>

namespace libfqfft {

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
    template<typename FieldT>
    FieldT evaluate_polynomial(const size_t &m, const std::vector<FieldT> &coeff, const FieldT &t) {
        if (m != coeff.size())
            throw DomainSizeException("expected m == coeff.size()");

        FieldT result = FieldT::zero();

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
    template<typename FieldT>
    FieldT evaluate_lagrange_polynomial(const size_t &m, const std::vector<FieldT> &domain, const FieldT &t,
                                        const size_t &idx) {
        if (m != domain.size())
            throw DomainSizeException("expected m == domain.size()");
        if (idx >= m)
            throw InvalidSizeException("expected idx < m");

        FieldT num = FieldT::one();
        FieldT denom = FieldT::one();

        for (size_t k = 0; k < m; ++k) {
            if (k == idx) {
                continue;
            }

            num *= t - domain[k];
            denom *= domain[idx] - domain[k];
        }

        return num * denom.inverse();
    }

}    // namespace libfqfft

#endif    // CRYPTO3_FFT_NAIVE_EVALUATE_HPP
