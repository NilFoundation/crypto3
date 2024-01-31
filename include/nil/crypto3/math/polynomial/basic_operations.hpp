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

#ifndef CRYPTO3_MATH_POLYNOMIAL_BASIC_OPERATIONS_HPP
#define CRYPTO3_MATH_POLYNOMIAL_BASIC_OPERATIONS_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/domains/detail/basic_radix2_domain_aux.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            /**
             * Returns true if polynomial A is a zero polynomial.
             */
            template<typename Iter>
            bool is_zero(const Iter &begin, const Iter &end) {
                typename Iter::value_type zero = typename std::iterator_traits<Iter>::value_type();
                return !std::any_of(begin, end, [zero](typename Iter::value_type i) { return i != zero; });
            }
            /**
             * Returns true if polynomial A is a zero polynomial.
             */
            template<typename Range>
            bool is_zero(const Range &a) {
                typename Range::value_type zero =
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type();
                return !std::any_of(
                    std::begin(a),
                    std::end(a),
                    [zero](typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type i) {
                        return i != zero;
                    });
            }

            template<typename Range>
            void reverse(Range &a, std::size_t n) {
                std::reverse(std::begin(a), std::end(a));
                a.resize(n);
            }

            /**
             * Removes extraneous zero entries from in vector representation of polynomial.
             * Example - Degree-4 Polynomial: [0, 1, 2, 3, 4, 0, 0, 0, 0] -> [0, 1, 2, 3, 4]
             * Note: Simplest condensed form is a zero polynomial of vector form: [0]
             */
            template<typename Range>
            void condense(Range &a) {
                std::size_t i = std::distance(std::cbegin(a), std::cend(a));
                typename Range::value_type zero =
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type();
                while (i > 1 && a[i - 1] == zero) {
                    --i;
                }
                a.resize(i);
            }

            /**
             * Computes the standard polynomial addition, polynomial A + polynomial B, and stores result in
             * polynomial C.
             */
            template<typename Range>
            void addition(Range &c, const Range &a, const Range &b) {

                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type value_type;

                if (is_zero(a)) {
                    c = b;
                } else if (is_zero(b)) {
                    c = a;
                } else {
                    std::size_t a_size = std::distance(std::begin(a), std::end(a));
                    std::size_t b_size = std::distance(std::begin(b), std::end(b));

                    if (a_size > b_size) {
                        c.resize(a_size);
                        std::transform(
                            std::begin(b), std::end(b), std::begin(a), std::begin(c), std::plus<value_type>());
                        std::copy(std::begin(a) + b_size, std::end(a), std::begin(c) + b_size);
                    } else {
                        c.resize(b_size);
                        std::transform(
                            std::begin(a), std::end(a), std::begin(b), std::begin(c), std::plus<value_type>());
                        std::copy(std::begin(b) + a_size, std::end(b), std::begin(c) + a_size);
                    }
                }

                condense(c);
            }

            /**
             * Computes the standard polynomial subtraction, polynomial A - polynomial B, and stores result in
             * polynomial C.
             */
            template<typename Range>
            void subtraction(Range &c, const Range &a, const Range &b) {

                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type value_type;

                if (is_zero(b)) {
                    c = a;
                } else if (is_zero(a)) {
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

                condense(c);
            }

            /**
             * Perform the multiplication of two polynomials, polynomial A * polynomial B, using FFT, and stores
             * result in polynomial C.
             * FieldRange is a range of field elements
             * AlgebraicRange is a range of either field elements or curve elements
             */
            template<typename AlgebraicRange, typename FieldRange>
            void multiplication(AlgebraicRange &c, const AlgebraicRange &a, const FieldRange &b) {

                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<AlgebraicRange>()))>::value_type algebraic_value_type;
                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<FieldRange>()))>::value_type field_value_type;

                typedef typename field_value_type::field_type FieldType;
                BOOST_STATIC_ASSERT(algebra::is_field<FieldType>::value);
                BOOST_STATIC_ASSERT(std::is_same<typename FieldType::value_type, field_value_type>::value);
                BOOST_ASSERT_MSG(a.size() !=0, "Uninitialized polynomial");
                BOOST_ASSERT_MSG(b.size() !=0, "Uninitialized polynomial");

                const std::size_t n = detail::power_of_two(a.size() + b.size() - 1);
                field_value_type omega = unity_root<FieldType>(n);

                AlgebraicRange u(a);
                FieldRange v(b);
                u.resize(n, algebraic_value_type::zero());
                v.resize(n, field_value_type::zero());
                c.resize(n, algebraic_value_type::zero());

                detail::basic_radix2_fft<FieldType>(u, omega);
                detail::basic_radix2_fft<FieldType>(v, omega);

                for(std::size_t i = 0; i < n; ++i) {
                    c[i] = u[i] * v[i];
                }

                detail::basic_radix2_fft<FieldType>(c, omega.inversed());

                const field_value_type sconst = field_value_type(n).inversed();

                for(std::size_t i = 0; i < n; ++i) {
                    c[i] = c[i] * sconst;
                }

                condense(c);
            }

            /**
             * Compute the transposed, polynomial multiplication of vector a and vector b.
             * Below we make use of the transposed multiplication definition from
             * [Bostan, Lecerf, & Schost, 2003. Tellegen's Principle in Practice, on page 39].
             */
            template<typename AlgebraicRange, typename FieldRange>
            AlgebraicRange transpose_multiplication(const std::size_t &n, const AlgebraicRange &a, const FieldRange &c) {

                const std::size_t m = a.size();
                // if (c.size() - 1 > m + n)
                // throw InvalidSizeException("expected c.size() - 1 <= m + n");

                AlgebraicRange r(a);
                reverse(r, m);
                multiplication(r, r, c);

                /* Determine Middle Product */
                AlgebraicRange result;
                for (std::size_t i = m - 1; i < n + m; i++) {
                    result.emplace_back(r[i]);
                }
                return result;
            }

            /**
             * Perform the standard Euclidean Division algorithm. We can not assume that q or r are empty.
             * Input: Polynomial A, Polynomial B, where A / B
             * Output: Polynomial Q, Polynomial R, such that A = (Q * B) + R.
             */
            template<typename Range>
            void division(Range &q, Range &r, const Range &a, const Range &b) {

                typedef
                    typename std::iterator_traits<decltype(std::begin(std::declval<Range>()))>::value_type value_type;

                std::size_t d = b.size() - 1; /* Degree of B */

                // Special case when B has degree 0.
                if (d == 0) {
                    value_type c = b[0].inversed();
                    q.resize(a.size());
                    std::transform(
                            std::begin(a), std::end(a), std::begin(q), [&c](const value_type& value) {return value * c;});
                    // We will always have no reminder here.
                    r.resize(1);
                    r[0] = 0;
                }
                // Special case when B = X^N + C.
                else if (b.back() == value_type::one() && is_zero(b.begin() + 1, b.end() - 1) && a.size() >= b.size()) {
                    q = Range(a.size() - b.size() + 1, value_type::zero());
                    r = Range(a.begin(), a.end() - (a.size() - b.size() + 1));

                    value_type c = -b[0];
                    auto end = --a.end();
                    for (std::size_t t = q.size(); t != 0; --t, --end) {
                        q[t - 1] += *end;
                        if (t - 1 >= d) {
                            q[t - 1 - d] = q[t - 1] * c;
                        } else {
                            r[t - 1] += q[t - 1] * c;
                        }
                    }
                    condense(r);
                } else {
                    value_type c = b.back().inversed(); /* Inverse of Leading Coefficient of B */
                    r = Range(a);
                    q = Range(r.size(), value_type::zero());

                    std::size_t r_deg = r.size() - 1;
                    std::size_t shift;

                    while (r_deg >= d && !is_zero(r)) {
                        shift = r_deg - d;

                        value_type lead_coeff = r.back() * c;

                        q[shift] = lead_coeff;

                        if (b.size() + shift + 1 > r.size())
                            r.resize(b.size() + shift + 1);
                        auto glambda = [=](value_type x, value_type y) { return y - (x * lead_coeff); };
                        std::transform(b.begin(), b.end(), r.begin() + shift, r.begin() + shift, glambda);

                        condense(r);
                        r_deg = r.size() - 1;
                    }
                }
                condense(q);
            }
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_POLYNOMIAL_BASIC_OPERATIONS_HPP
