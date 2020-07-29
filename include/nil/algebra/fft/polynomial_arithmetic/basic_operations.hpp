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

#include <nil/algebra/fft/evaluation_domain/domains/basic_radix2_domain_aux.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace nil {
    namespace algebra {
        namespace fft {

            /**
             * Returns true if polynomial A is a zero polynomial.
             */
            template<typename FieldType>
            bool _is_zero(const std::vector<FieldType> &a) {
                return std::all_of(a.begin(), a.end(), [](FieldType i) { return i == FieldType::zero(); });
            }

            /**
             * Removes extraneous zero entries from in vector representation of polynomial.
             * Example - Degree-4 Polynomial: [0, 1, 2, 3, 4, 0, 0, 0, 0] -> [0, 1, 2, 3, 4]
             * Note: Simplest condensed form is a zero polynomial of vector form: [0]
             */
            template<typename FieldType>
            void _condense(std::vector<FieldType> &a) {
                while (a.begin() != a.end() && a.back() == FieldType::zero())
                    a.pop_back();
            }

            /**
             * Compute the reverse polynomial up to vector size n (degree n-1).
             * Below we make use of the reversal endomorphism definition from
             * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 38].
             */
            template<typename FieldType>
            void _reverse(std::vector<FieldType> &a, const size_t n) {
                std::reverse(a.begin(), a.end());
                a.resize(n);
            }

            /**
             * Computes the standard polynomial addition, polynomial A + polynomial B, and stores result in polynomial
             * C.
             */
            template<typename FieldType>
            void _polynomial_addition(std::vector<FieldType> &c, const std::vector<FieldType> &a,
                                      const std::vector<FieldType> &b) {
                if (_is_zero(a)) {
                    c = b;
                } else if (_is_zero(b)) {
                    c = a;
                } else {
                    size_t a_size = a.size();
                    size_t b_size = b.size();

                    if (a_size > b_size) {
                        c.resize(a_size);
                        std::transform(b.begin(), b.end(), a.begin(), c.begin(), std::plus<FieldType>());
                        std::copy(a.begin() + b_size, a.end(), c.begin() + b_size);
                    } else {
                        c.resize(b_size);
                        std::transform(a.begin(), a.end(), b.begin(), c.begin(), std::plus<FieldType>());
                        std::copy(b.begin() + a_size, b.end(), c.begin() + a_size);
                    }
                }

                _condense(c);
            }

            /**
             * Computes the standard polynomial subtraction, polynomial A - polynomial B, and stores result in
             * polynomial C.
             */
            template<typename FieldType>
            void _polynomial_subtraction(std::vector<FieldType> &c, const std::vector<FieldType> &a,
                                         const std::vector<FieldType> &b) {
                if (_is_zero(b)) {
                    c = a;
                } else if (_is_zero(a)) {
                    c.resize(b.size());
                    std::transform(b.begin(), b.end(), c.begin(), std::negate<FieldType>());
                } else {
                    size_t a_size = a.size();
                    size_t b_size = b.size();

                    if (a_size > b_size) {
                        c.resize(a_size);
                        std::transform(a.begin(), a.begin() + b_size, b.begin(), c.begin(), std::minus<FieldType>());
                        std::copy(a.begin() + b_size, a.end(), c.begin() + b_size);
                    } else {
                        c.resize(b_size);
                        std::transform(a.begin(), a.end(), b.begin(), c.begin(), std::minus<FieldType>());
                        std::transform(b.begin() + a_size, b.end(), c.begin() + a_size, std::negate<FieldType>());
                    }
                }

                _condense(c);
            }

            /**
             * Perform the multiplication of two polynomials, polynomial A * polynomial B, using FFT, and stores result
             * in polynomial C.
             */
            template<typename FieldType>
            void _polynomial_multiplication_on_fft(std::vector<FieldType> &c, const std::vector<FieldType> &a,
                                                   const std::vector<FieldType> &b) {
                const size_t n = algebra::get_power_of_two(a.size() + b.size() - 1);
                FieldType omega = detail::unity_root<FieldType>(n);

                std::vector<FieldType> u(a);
                std::vector<FieldType> v(b);
                u.resize(n, FieldType::zero());
                v.resize(n, FieldType::zero());
                c.resize(n, FieldType::zero());

#ifdef MULTICORE
                detail::basic_parallel_radix2_FFT(u, omega);
                detail::basic_parallel_radix2_FFT(v, omega);
#else
                detail::basic_serial_radix2_FFT(u, omega);
                detail::basic_serial_radix2_FFT(v, omega);
#endif

                std::transform(u.begin(), u.end(), v.begin(), c.begin(), std::multiplies<FieldType>());

#ifdef MULTICORE
                detail::basic_parallel_radix2_FFT(c, omega.inverse());
#else
                detail::basic_serial_radix2_FFT(c, omega.inverse());
#endif

                const FieldType sconst = FieldType(n).inverse();
                std::transform(c.begin(), c.end(), c.begin(), std::bind1st(std::multiplies<FieldType>(), sconst));
                _condense(c);
            }

            /**
             * Perform the multiplication of two polynomials, polynomial A * polynomial B, and stores result in
             * polynomial C.
             */
            template<typename FieldType>
            void _polynomial_multiplication(std::vector<FieldType> &c, const std::vector<FieldType> &a,
                                            const std::vector<FieldType> &b) {
                _polynomial_multiplication_on_fft(c, a, b);
            }

            /**
             * Compute the transposed, polynomial multiplication of vector a and vector b.
             * Below we make use of the transposed multiplication definition from
             * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 39].
             */
            template<typename FieldType>
            std::vector<FieldType> _polynomial_multiplication_transpose(const size_t &n,
                                                                        const std::vector<FieldType> &a,
                                                                        const std::vector<FieldType> &c) {
                const size_t m = a.size();
                // if (c.size() - 1 > m + n)
                // throw InvalidSizeException("expected c.size() - 1 <= m + n");

                std::vector<FieldType> r(a);
                _reverse(r, m);
                _polynomial_multiplication(r, r, c);

                /* Determine Middle Product */
                std::vector<FieldType> result;
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
            template<typename FieldType>
            void _polynomial_division(std::vector<FieldType> &q, std::vector<FieldType> &r,
                                      const std::vector<FieldType> &a, const std::vector<FieldType> &b) {
                size_t d = b.size() - 1;          /* Degree of B */
                FieldType c = b.back().inverse(); /* Inverse of Leading Coefficient of B */

                r = std::vector<FieldType>(a);
                q = std::vector<FieldType>(r.size(), FieldType::zero());

                size_t r_deg = r.size() - 1;
                size_t shift;

                while (r_deg >= d && !_is_zero(r)) {
                    if (r_deg >= d)
                        shift = r_deg - d;
                    else
                        shift = 0;

                    FieldType lead_coeff = r.back() * c;

                    q[shift] += lead_coeff;

                    if (b.size() + shift + 1 > r.size())
                        r.resize(b.size() + shift + 1);
                    auto glambda = [=](FieldType x, FieldType y) { return y - (x * lead_coeff); };
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
