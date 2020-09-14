//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_BASIC_OPERATIONS_HPP
#define ALGEBRA_FFT_BASIC_OPERATIONS_HPP

#include <algorithm>
#include <vector>

#include <nil/algebra/fft/detail/field_utils.hpp>

#include <nil/algebra/fft/domains/basic_radix2_domain_aux.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace nil {
    namespace algebra {
        namespace fft {

            /**
             * Returns true if polynomial A is a zero polynomial.
             */
            template<typename FieldValueType>
            bool _is_zero(const std::vector<FieldValueType> &a) {
                return std::all_of(a.begin(), a.end(), [](FieldValueType i) { return i == FieldValueType::zero(); });
            }

            /**
             * Removes extraneous zero entries from in vector representation of polynomial.
             * Example - Degree-4 Polynomial: [0, 1, 2, 3, 4, 0, 0, 0, 0] -> [0, 1, 2, 3, 4]
             * Note: Simplest condensed form is a zero polynomial of vector form: [0]
             */
            template<typename FieldValueType>
            void _condense(std::vector<FieldValueType> &a) {
                while (a.begin() != a.end() && a.back() == FieldValueType::zero())
                    a.pop_back();
            }

            /**
             * Compute the reverse polynomial up to vector size n (degree n-1).
             * Below we make use of the reversal endomorphism definition from
             * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 38].
             */
            template<typename FieldValueType>
            void _reverse(std::vector<FieldValueType> &a, const size_t n) {
                std::reverse(a.begin(), a.end());
                a.resize(n);
            }

            /**
             * Computes the standard polynomial addition, polynomial A + polynomial B, and stores result in polynomial
             * C.
             */
            template<typename FieldValueType>
            void _polynomial_addition(std::vector<FieldValueType> &c, const std::vector<FieldValueType> &a,
                                      const std::vector<FieldValueType> &b) {
                if (_is_zero(a)) {
                    c = b;
                } else if (_is_zero(b)) {
                    c = a;
                } else {
                    size_t a_size = a.size();
                    size_t b_size = b.size();

                    if (a_size > b_size) {
                        c.resize(a_size);
                        std::transform(b.begin(), b.end(), a.begin(), c.begin(), std::plus<FieldValueType>());
                        std::copy(a.begin() + b_size, a.end(), c.begin() + b_size);
                    } else {
                        c.resize(b_size);
                        std::transform(a.begin(), a.end(), b.begin(), c.begin(), std::plus<FieldValueType>());
                        std::copy(b.begin() + a_size, b.end(), c.begin() + a_size);
                    }
                }

                _condense(c);
            }

            /**
             * Computes the standard polynomial subtraction, polynomial A - polynomial B, and stores result in
             * polynomial C.
             */
            template<typename FieldValueType>
            void _polynomial_subtraction(std::vector<FieldValueType> &c, const std::vector<FieldValueType> &a,
                                         const std::vector<FieldValueType> &b) {
                if (_is_zero(b)) {
                    c = a;
                } else if (_is_zero(a)) {
                    c.resize(b.size());
                    std::transform(b.begin(), b.end(), c.begin(), std::negate<FieldValueType>());
                } else {
                    size_t a_size = a.size();
                    size_t b_size = b.size();

                    if (a_size > b_size) {
                        c.resize(a_size);
                        std::transform(a.begin(), a.begin() + b_size, b.begin(), c.begin(), std::minus<FieldValueType>());
                        std::copy(a.begin() + b_size, a.end(), c.begin() + b_size);
                    } else {
                        c.resize(b_size);
                        std::transform(a.begin(), a.end(), b.begin(), c.begin(), std::minus<FieldValueType>());
                        std::transform(b.begin() + a_size, b.end(), c.begin() + a_size, std::negate<FieldValueType>());
                    }
                }

                _condense(c);
            }

            /**
             * Perform the multiplication of two polynomials, polynomial A * polynomial B, using FFT, and stores result
             * in polynomial C.
             */
            template<typename FieldValueType>
            void _polynomial_multiplication_on_fft(std::vector<FieldValueType> &c, const std::vector<FieldValueType> &a,
                                                   const std::vector<FieldValueType> &b) {
                const size_t n = algebra::get_power_of_two(a.size() + b.size() - 1);
                FieldValueType omega = unity_root<FieldValueType>(n);

                std::vector<FieldValueType> u(a);
                std::vector<FieldValueType> v(b);
                u.resize(n, FieldValueType::zero());
                v.resize(n, FieldValueType::zero());
                c.resize(n, FieldValueType::zero());

#ifdef MULTICORE
                detail::basic_parallel_radix2_FFT(u, omega);
                detail::basic_parallel_radix2_FFT(v, omega);
#else
                detail::basic_serial_radix2_FFT(u, omega);
                detail::basic_serial_radix2_FFT(v, omega);
#endif

                std::transform(u.begin(), u.end(), v.begin(), c.begin(), std::multiplies<FieldValueType>());

#ifdef MULTICORE
                detail::basic_parallel_radix2_FFT(c, omega.inversed());
#else
                detail::basic_serial_radix2_FFT(c, omega.inversed());
#endif

                const FieldValueType sconst = FieldValueType(n).inversed();
                std::transform(c.begin(), c.end(), c.begin(), std::bind1st(std::multiplies<FieldValueType>(), sconst));
                _condense(c);
            }

            /**
             * Perform the multiplication of two polynomials, polynomial A * polynomial B, and stores result in
             * polynomial C.
             */
            template<typename FieldValueType>
            void _polynomial_multiplication(std::vector<FieldValueType> &c, const std::vector<FieldValueType> &a,
                                            const std::vector<FieldValueType> &b) {
                _polynomial_multiplication_on_fft(c, a, b);
            }

            /**
             * Compute the transposed, polynomial multiplication of vector a and vector b.
             * Below we make use of the transposed multiplication definition from
             * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 39].
             */
            template<typename FieldValueType>
            std::vector<FieldValueType> _polynomial_multiplication_transpose(const size_t &n,
                                                                        const std::vector<FieldValueType> &a,
                                                                        const std::vector<FieldValueType> &c) {
                const size_t m = a.size();
                // if (c.size() - 1 > m + n)
                // throw InvalidSizeException("expected c.size() - 1 <= m + n");

                std::vector<FieldValueType> r(a);
                _reverse(r, m);
                _polynomial_multiplication(r, r, c);

                /* Determine Middle Product */
                std::vector<FieldValueType> result;
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
            template<typename FieldValueType>
            void _polynomial_division(std::vector<FieldValueType> &q, std::vector<FieldValueType> &r,
                                      const std::vector<FieldValueType> &a, const std::vector<FieldValueType> &b) {
                size_t d = b.size() - 1;          /* Degree of B */
                FieldValueType c = b.back().inversed(); /* Inverse of Leading Coefficient of B */

                r = std::vector<FieldValueType>(a);
                q = std::vector<FieldValueType>(r.size(), FieldValueType::zero());

                size_t r_deg = r.size() - 1;
                size_t shift;

                while (r_deg >= d && !_is_zero(r)) {
                    if (r_deg >= d)
                        shift = r_deg - d;
                    else
                        shift = 0;

                    FieldValueType lead_coeff = r.back() * c;

                    q[shift] += lead_coeff;

                    if (b.size() + shift + 1 > r.size())
                        r.resize(b.size() + shift + 1);
                    auto glambda = [=](FieldValueType x, FieldValueType y) { return y - (x * lead_coeff); };
                    std::transform(b.begin(), b.end(), r.begin() + shift, r.begin() + shift, glambda);
                    _condense(r);

                    r_deg = r.size() - 1;
                }
                _condense(q);
            }

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_OPERATIONS_HPP
