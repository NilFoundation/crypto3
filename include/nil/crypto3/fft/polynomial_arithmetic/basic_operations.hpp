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

#ifndef CRYPTO3_ALGEBRA_FFT_BASIC_OPERATIONS_HPP
#define CRYPTO3_ALGEBRA_FFT_BASIC_OPERATIONS_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/fft/detail/field_utils.hpp>

#include <nil/crypto3/fft/domains/detail/basic_radix2_domain_aux.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace nil {
    namespace crypto3 {
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
            void _reverse(std::vector<FieldValueType> &a, const std::size_t n) {
                std::reverse(a.begin(), a.end());
                a.resize(n);
            }

            /**
             * Computes the standard polynomial addition, polynomial A + polynomial B, and stores result in
             * polynomial C.
             */
            template<typename FieldType>
            void _polynomial_addition(std::vector<typename FieldType::value_type> &c,
                                      const std::vector<typename FieldType::value_type> &a,
                                      const std::vector<typename FieldType::value_type> &b) {

                typedef typename FieldType::value_type value_type;

                if (_is_zero(a)) {
                    c = b;
                } else if (_is_zero(b)) {
                    c = a;
                } else {
                    std::size_t a_size = a.size();
                    std::size_t b_size = b.size();

                    if (a_size > b_size) {
                        c.resize(a_size);
                        std::transform(b.begin(), b.end(), a.begin(), c.begin(), std::plus<value_type>());
                        std::copy(a.begin() + b_size, a.end(), c.begin() + b_size);
                    } else {
                        c.resize(b_size);
                        std::transform(a.begin(), a.end(), b.begin(), c.begin(), std::plus<value_type>());
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
            void _polynomial_subtraction(std::vector<typename FieldType::value_type> &c,
                                         const std::vector<typename FieldType::value_type> &a,
                                         const std::vector<typename FieldType::value_type> &b) {

                typedef typename FieldType::value_type value_type;

                if (_is_zero(b)) {
                    c = a;
                } else if (_is_zero(a)) {
                    c.resize(b.size());
                    std::transform(b.begin(), b.end(), c.begin(), std::negate<value_type>());
                } else {
                    std::size_t a_size = a.size();
                    std::size_t b_size = b.size();

                    if (a_size > b_size) {
                        c.resize(a_size);
                        std::transform(a.begin(), a.begin() + b_size, b.begin(), c.begin(), std::minus<value_type>());
                        std::copy(a.begin() + b_size, a.end(), c.begin() + b_size);
                    } else {
                        c.resize(b_size);
                        std::transform(a.begin(), a.end(), b.begin(), c.begin(), std::minus<value_type>());
                        std::transform(b.begin() + a_size, b.end(), c.begin() + a_size, std::negate<value_type>());
                    }
                }

                _condense(c);
            }

            /**
             * Perform the multiplication of two polynomials, polynomial A * polynomial B, using FFT, and stores
             * result in polynomial C.
             */
            template<typename FieldType>
            void _polynomial_multiplication_on_fft(std::vector<typename FieldType::value_type> &c,
                                                   const std::vector<typename FieldType::value_type> &a,
                                                   const std::vector<typename FieldType::value_type> &b) {

                typedef typename FieldType::value_type value_type;

                const std::size_t n = detail::get_power_of_two(a.size() + b.size() - 1);
                value_type omega = detail::unity_root<FieldType>(n);

                std::vector<value_type> u(a);
                std::vector<value_type> v(b);
                u.resize(n, value_type::zero());
                v.resize(n, value_type::zero());
                c.resize(n, value_type::zero());

#ifdef MULTICORE
                detail::basic_parallel_radix2_FFT<FieldType>(u, omega);
                detail::basic_parallel_radix2_FFT<FieldType>(v, omega);
#else
                detail::basic_serial_radix2_FFT<FieldType>(u, omega);
                detail::basic_serial_radix2_FFT<FieldType>(v, omega);
#endif

                std::transform(u.begin(), u.end(), v.begin(), c.begin(), std::multiplies<value_type>());

#ifdef MULTICORE
                detail::basic_parallel_radix2_FFT<FieldType>(c, omega.inversed());
#else
                detail::basic_serial_radix2_FFT<FieldType>(c, omega.inversed());
#endif

                const value_type sconst = value_type(n).inversed();
                std::transform(c.begin(),
                               c.end(),
                               c.begin(),
                               std::bind(std::multiplies<value_type>(), sconst, std::placeholders::_1));
                _condense(c);
            }

            /**
             * Perform the multiplication of two polynomials, polynomial A * polynomial B, and stores result in
             * polynomial C.
             */
            template<typename FieldType>
            void _polynomial_multiplication(std::vector<typename FieldType::value_type> &c,
                                            const std::vector<typename FieldType::value_type> &a,
                                            const std::vector<typename FieldType::value_type> &b) {
                _polynomial_multiplication_on_fft<FieldType>(c, a, b);
            }

            /**
             * Compute the transposed, polynomial multiplication of vector a and vector b.
             * Below we make use of the transposed multiplication definition from
             * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 39].
             */
            template<typename FieldType>
            std::vector<typename FieldType::value_type>
                _polynomial_multiplication_transpose(const std::size_t &n,
                                                     const std::vector<typename FieldType::value_type> &a,
                                                     const std::vector<typename FieldType::value_type> &c) {

                typedef typename FieldType::value_type value_type;

                const std::size_t m = a.size();
                // if (c.size() - 1 > m + n)
                // throw InvalidSizeException("expected c.size() - 1 <= m + n");

                std::vector<value_type> r(a);
                _reverse(r, m);
                _polynomial_multiplication<FieldType>(r, r, c);

                /* Determine Middle Product */
                std::vector<value_type> result;
                for (std::size_t i = m - 1; i < n + m; i++) {
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
            void _polynomial_division(std::vector<typename FieldType::value_type> &q,
                                      std::vector<typename FieldType::value_type> &r,
                                      const std::vector<typename FieldType::value_type> &a,
                                      const std::vector<typename FieldType::value_type> &b) {

                typedef typename FieldType::value_type value_type;

                std::size_t d = b.size() - 1;       /* Degree of B */
                value_type c = b.back().inversed(); /* Inverse of Leading Coefficient of B */

                r = std::vector<value_type>(a);
                q = std::vector<value_type>(r.size(), value_type::zero());

                std::size_t r_deg = r.size() - 1;
                std::size_t shift;

                while (r_deg >= d && !_is_zero(r)) {
                    if (r_deg >= d)
                        shift = r_deg - d;
                    else
                        shift = 0;

                    value_type lead_coeff = r.back() * c;

                    q[shift] += lead_coeff;

                    if (b.size() + shift + 1 > r.size())
                        r.resize(b.size() + shift + 1);
                    auto glambda = [=](value_type x, value_type y) { return y - (x * lead_coeff); };
                    std::transform(b.begin(), b.end(), r.begin() + shift, r.begin() + shift, glambda);
                    _condense(r);

                    r_deg = r.size() - 1;
                }
                _condense(q);
            }

        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_OPERATIONS_HPP
