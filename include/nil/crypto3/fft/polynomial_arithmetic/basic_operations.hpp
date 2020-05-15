//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FFT_BASIC_OPERATIONS_HPP
#define CRYPTO3_FFT_BASIC_OPERATIONS_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/fft/evaluation_domain/domains/basic_radix2_domain_aux.hpp>
#include <nil/crypto3/fft/kronecker_substitution/kronecker_substitution.hpp>
#include <nil/crypto3/fft/tools/exceptions.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace libfqfft {

    /**
     * Returns true if polynomial A is a zero polynomial.
     */
    template<typename FieldT>
    bool _is_zero(const std::vector<FieldT> &a) {
        return std::all_of(a.begin(), a.end(), [](FieldT i) { return i == FieldT::zero(); });
    }

    /**
     * Removes extraneous zero entries from in vector representation of polynomial.
     * Example - Degree-4 Polynomial: [0, 1, 2, 3, 4, 0, 0, 0, 0] -> [0, 1, 2, 3, 4]
     * Note: Simplest condensed form is a zero polynomial of vector form: [0]
     */
    template<typename FieldT>
    void _condense(std::vector<FieldT> &a) {
        while (a.begin() != a.end() && a.back() == FieldT::zero())
            a.pop_back();
    }

    /**
     * Compute the reverse polynomial up to vector size n (degree n-1).
     * Below we make use of the reversal endomorphism definition from
     * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 38].
     */
    template<typename FieldT>
    void _reverse(std::vector<FieldT> &a, const size_t n) {
        std::reverse(a.begin(), a.end());
        a.resize(n);
    }

    /**
     * Computes the standard polynomial addition, polynomial A + polynomial B, and stores result in polynomial C.
     */
    template<typename FieldT>
    void _polynomial_addition(std::vector<FieldT> &c, const std::vector<FieldT> &a, const std::vector<FieldT> &b) {
        if (_is_zero(a)) {
            c = b;
        } else if (_is_zero(b)) {
            c = a;
        } else {
            size_t a_size = a.size();
            size_t b_size = b.size();

            if (a_size > b_size) {
                c.resize(a_size);
                std::transform(b.begin(), b.end(), a.begin(), c.begin(), std::plus<FieldT>());
                std::copy(a.begin() + b_size, a.end(), c.begin() + b_size);
            } else {
                c.resize(b_size);
                std::transform(a.begin(), a.end(), b.begin(), c.begin(), std::plus<FieldT>());
                std::copy(b.begin() + a_size, b.end(), c.begin() + a_size);
            }
        }

        _condense(c);
    }

    /**
     * Computes the standard polynomial subtraction, polynomial A - polynomial B, and stores result in polynomial C.
     */
    template<typename FieldT>
    void _polynomial_subtraction(std::vector<FieldT> &c, const std::vector<FieldT> &a, const std::vector<FieldT> &b) {
        if (_is_zero(b)) {
            c = a;
        } else if (_is_zero(a)) {
            c.resize(b.size());
            std::transform(b.begin(), b.end(), c.begin(), std::negate<FieldT>());
        } else {
            size_t a_size = a.size();
            size_t b_size = b.size();

            if (a_size > b_size) {
                c.resize(a_size);
                std::transform(a.begin(), a.begin() + b_size, b.begin(), c.begin(), std::minus<FieldT>());
                std::copy(a.begin() + b_size, a.end(), c.begin() + b_size);
            } else {
                c.resize(b_size);
                std::transform(a.begin(), a.end(), b.begin(), c.begin(), std::minus<FieldT>());
                std::transform(b.begin() + a_size, b.end(), c.begin() + a_size, std::negate<FieldT>());
            }
        }

        _condense(c);
    }

    /**
     * Perform the multiplication of two polynomials, polynomial A * polynomial B, and stores result in polynomial C.
     */
    template<typename FieldT>
    void _polynomial_multiplication(std::vector<FieldT> &c, const std::vector<FieldT> &a,
                                    const std::vector<FieldT> &b) {
        _polynomial_multiplication_on_fft(c, a, b);
    }

    /**
     * Perform the multiplication of two polynomials, polynomial A * polynomial B, using FFT, and stores result in
     * polynomial C.
     */
    template<typename FieldT>
    void _polynomial_multiplication_on_fft(std::vector<FieldT> &c, const std::vector<FieldT> &a,
                                           const std::vector<FieldT> &b) {
        const size_t n = libff::get_power_of_two(a.size() + b.size() - 1);
        FieldT omega = libff::get_root_of_unity<FieldT>(n);

        std::vector<FieldT> u(a);
        std::vector<FieldT> v(b);
        u.resize(n, FieldT::zero());
        v.resize(n, FieldT::zero());
        c.resize(n, FieldT::zero());

#ifdef MULTICORE
        _basic_parallel_radix2_FFT(u, omega);
        _basic_parallel_radix2_FFT(v, omega);
#else
        _basic_serial_radix2_FFT(u, omega);
        _basic_serial_radix2_FFT(v, omega);
#endif

        std::transform(u.begin(), u.end(), v.begin(), c.begin(), std::multiplies<FieldT>());

#ifdef MULTICORE
        _basic_parallel_radix2_FFT(c, omega.inverse());
#else
        _basic_serial_radix2_FFT(c, omega.inverse());
#endif

        const FieldT sconst = FieldT(n).inverse();
        std::transform(c.begin(), c.end(), c.begin(), std::bind1st(std::multiplies<FieldT>(), sconst));
        _condense(c);
    }

    /**
     * Perform the multiplication of two polynomials, polynomial A * polynomial B, using Kronecker Substitution, and
     * stores result in polynomial C.
     */
    template<typename FieldT>
    void _polynomial_multiplication_on_kronecker(std::vector<FieldT> &c, const std::vector<FieldT> &a,
                                                 const std::vector<FieldT> &b) {
        kronecker_substitution(c, a, b);
    }

    /**
     * Compute the transposed, polynomial multiplication of vector a and vector b.
     * Below we make use of the transposed multiplication definition from
     * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 39].
     */
    template<typename FieldT>
    std::vector<FieldT> _polynomial_multiplication_transpose(const size_t &n, const std::vector<FieldT> &a,
                                                             const std::vector<FieldT> &c) {
        const size_t m = a.size();
        if (c.size() - 1 > m + n)
            throw InvalidSizeException("expected c.size() - 1 <= m + n");

        std::vector<FieldT> r(a);
        _reverse(r, m);
        _polynomial_multiplication(r, r, c);

        /* Determine Middle Product */
        std::vector<FieldT> result;
        for (size_t i = m - 1; i < n + m; i++) {
            result.emplace_back(r[i]);
        }
        return result;
    }

    /**
     * Perform the standard Euclidean Division algorithm.
     * Input: Polynomial A, Polynomial B, where A / B
     * Output: Polynomial Q, Polynomial R, such that A = (Q * B) + R.
     */
    template<typename FieldT>
    void _polynomial_division(std::vector<FieldT> &q, std::vector<FieldT> &r, const std::vector<FieldT> &a,
                              const std::vector<FieldT> &b) {
        size_t d = b.size() - 1;       /* Degree of B */
        FieldT c = b.back().inverse(); /* Inverse of Leading Coefficient of B */

        r = std::vector<FieldT>(a);
        q = std::vector<FieldT>(r.size(), FieldT::zero());

        size_t r_deg = r.size() - 1;
        size_t shift;

        while (r_deg >= d && !_is_zero(r)) {
            if (r_deg >= d)
                shift = r_deg - d;
            else
                shift = 0;

            FieldT lead_coeff = r.back() * c;

            q[shift] += lead_coeff;

            if (b.size() + shift + 1 > r.size())
                r.resize(b.size() + shift + 1);
            auto glambda = [=](FieldT x, FieldT y) { return y - (x * lead_coeff); };
            std::transform(b.begin(), b.end(), r.begin() + shift, r.begin() + shift, glambda);
            _condense(r);

            r_deg = r.size() - 1;
        }
        _condense(q);
    }

}    // namespace libfqfft

#endif    // CRYPTO3_FFT_BASIC_OPERATIONS_HPP
