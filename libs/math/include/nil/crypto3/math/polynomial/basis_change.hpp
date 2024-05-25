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

#ifndef CRYPTO3_MATH_BASIS_CHANGE_HPP
#define CRYPTO3_MATH_BASIS_CHANGE_HPP

#include <algorithm>
#include <vector>

#include <nil/crypto3/math/polynomial/basic_operations.hpp>
#include <nil/crypto3/math/polynomial/xgcd.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            /**
             * Compute the Subproduct Tree of degree 2^M and store it in Tree T.
             * Below we make use of the Subproduct Tree description from
             * [Bostan and Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points], on
             * page 7.
             */
            template<typename FieldType>
            void compute_subproduct_tree(std::vector<std::vector<std::vector<typename FieldType::value_type>>> &T,
                                         std::size_t m) {

                typedef typename FieldType::value_type value_type;

                if (T.size() != m + 1)
                    T.resize(m + 1);

                /*
                 * Subproduct tree T is represented as a 2-dimensional array T_{i, j}.
                 * T_{i, j} = product_{l = [2^i * j] to [2^i * (j+1) - 1]} (x - x_l)
                 * Note: n = 2^m.
                 */

                /* Precompute the first row. */
                T[0] = std::vector<std::vector<value_type>>(1u << m);
                for (std::size_t j = 0; j < (1u << m); j++) {
                    T[0][j] = std::vector<value_type>(2, value_type::one());
                    T[0][j][0] = value_type(-j);
                }

                std::vector<value_type> a;
                std::vector<value_type> b;

                std::size_t index = 0;
                for (std::size_t i = 1; i <= m; i++) {
                    T[i] = std::vector<std::vector<value_type>>(1u << (m - i));
                    for (std::size_t j = 0; j < (1u << (m - i)); j++) {
                        a = T[i - 1][index];
                        index++;

                        b = T[i - 1][index];
                        index++;

                        multiplication(T[i][j], a, b);
                    }
                    index = 0;
                }
            }

            /**
             * Perform the general change of basis from Monomial to Newton Basis with Subproduct Tree T.
             * Below we make use of the MonomialToNewton and TNewtonToMonomial pseudocode from
             * [Bostan and Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points], on page
             * 12 and 14.
             */
            template<typename FieldType, typename Range>
            void
                monomial_to_newton_basis(Range &a,
                                         const std::vector<std::vector<std::vector<typename FieldType::value_type>>> &T,
                                         size_t n) {

                typedef typename Range::value_type value_type;
                typedef typename FieldType::value_type field_value_type;

                std::size_t m = log2(n);
                // if (T.size() != m + 1u)
                // throw DomainSizeException("expected T.size() == m + 1");

                /* MonomialToNewton */
                std::vector<field_value_type> I(T[m][0]);
                reverse(I, n);

                std::vector<field_value_type> mod(n + 1, field_value_type::zero());
                mod[n] = field_value_type::one();

                extended_euclidean(mod, I, mod, mod, I);

                I.resize(n);

                std::vector<value_type> Q(transpose_multiplication(n - 1, a, I));
                reverse(Q, n);

                /* TNewtonToMonomial */
                std::vector<std::vector<value_type>> c(n);
                c[0] = Q;

                std::size_t row_length;
                std::size_t c_vec;
                /* NB: unsigned reverse iteration: cannot do i >= 0, but can do i < m
                   because unsigned integers are guaranteed to wrap around */
                for (std::size_t i = m - 1; i < m; i--) {
                    row_length = T[i].size() - 1;
                    c_vec = 1u << i;

                    /* NB: unsigned reverse iteration */
                    for (std::size_t j = (1u << (m - i - 1)) - 1; j < (1u << (m - i - 1)); j--) {
                        c[2 * j + 1] = transpose_multiplication((1u << i) - 1, c[j], T[i][row_length - 2 * j]);
                        c[2 * j] = c[j];
                        c[2 * j].resize(c_vec);
                    }
                }

                /* Store Computed Newton Basis Coefficients */
                std::size_t j = 0;
                /* NB: unsigned reverse iteration */
                for (std::size_t i = c.size() - 1; i < c.size(); i--) {
                    a[j++] = c[i][0];
                }
            }

            /**
             * Perform the general change of basis from Newton to Monomial Basis with Subproduct Tree T.
             * Below we make use of the NewtonToMonomial pseudocode from
             * [Bostan and Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points], on
             * page 11.
             */
            template<typename FieldType, typename Range>
            void
                newton_to_monomial_basis(Range &a,
                                         const std::vector<std::vector<std::vector<typename FieldType::value_type>>> &T,
                                         size_t n) {

                typedef typename Range::value_type value_type;

                std::size_t m = log2(n);
                // if (T.size() != m + 1u)
                // throw DomainSizeException("expected T.size() == m + 1");

                std::vector<std::vector<value_type>> f(n);
                for (std::size_t i = 0; i < n; i++) {
                    f[i] = std::vector<value_type>(1, a[i]);
                }

                /* NewtonToMonomial */
                std::vector<value_type> temp(1, value_type::zero());
                for (std::size_t i = 0; i < m; i++) {
                    for (std::size_t j = 0; j < (1u << (m - i - 1)); j++) {
                        multiplication(temp, f[2 * j + 1], T[i][2 * j]);
                        addition(f[j], f[2 * j], temp);
                    }
                }

                a = f[0];
            }

            /**
             * Perform the change of basis from Monomial to Newton Basis for geometric sequence.
             * Below we make use of the psuedocode from
             * [Bostan & Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points] on page 26.
             */
            template<typename FieldType, typename Range1, typename Range2, typename Range3>
            void monomial_to_newton_basis_geometric(Range1 &a,
                                                    const Range2 &geometric_sequence,
                                                    const Range3 &geometric_triangular_sequence,
                                                    const std::size_t &n) {

                typedef typename FieldType::value_type field_value_type;
                typedef typename Range1::value_type value_type;

                std::vector<field_value_type> u(n, field_value_type::zero());
                std::vector<value_type> w(n, value_type::zero());
                std::vector<field_value_type> z(n, field_value_type::zero());
                std::vector<value_type> f(n, value_type::zero());
                u[0] = field_value_type::one();
                w[0] = a[0];
                z[0] = field_value_type::one();
                f[0] = a[0];

                for (std::size_t i = 1; i < n; i++) {
                    u[i] = u[i - 1] * geometric_sequence[i] * (field_value_type::one() - geometric_sequence[i]).inversed();
                    w[i] = a[i] * (u[i].inversed());
                    z[i] = u[i] * geometric_triangular_sequence[i].inversed();
                    f[i] = w[i] * geometric_triangular_sequence[i];

                    if (i % 2 == 1) {
                        z[i] = -z[i];
                        f[i] = -f[i];
                    }
                }

                w = transpose_multiplication(n - 1, f, z);

                for (std::size_t i = 0; i < n; i++) {
                    a[i] = w[i] * z[i];
                }
            }

            /**
             * Perform the change of basis from Newton to Monomial Basis for geometric sequence
             * Below we make use of the psuedocode from
             * [Bostan & Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points] on page 26.
             */
            template<typename FieldType, typename Range1, typename Range2, typename Range3>
            void newton_to_monomial_basis_geometric(Range1 &a,
                                                    const Range2 &geometric_sequence,
                                                    const Range3 &geometric_triangular_sequence,
                                                    std::size_t n) {

                typedef typename Range1::value_type value_type;
                typedef typename FieldType::value_type field_value_type;

                std::vector<value_type> v(n, value_type::zero());
                std::vector<field_value_type> u(n, field_value_type::zero());
                std::vector<value_type> w(n, value_type::zero());
                std::vector<field_value_type> z(n, field_value_type::zero());
                v[0] = a[0];
                u[0] = field_value_type::one();
                w[0] = a[0];
                z[0] = field_value_type::one();

                for (std::size_t i = 1; i < n; i++) {
                    v[i] = a[i] * geometric_triangular_sequence[i];
                    if (i % 2 == 1)
                        v[i] = -v[i];

                    u[i] = u[i - 1] * geometric_sequence[i] * (field_value_type::one() - geometric_sequence[i]).inversed();
                    w[i] = v[i] * u[i].inversed();

                    z[i] = u[i] * geometric_triangular_sequence[i].inversed();
                    if (i % 2 == 1)
                        z[i] = -z[i];
                }

                w = transpose_multiplication(n - 1, w, u);

                for (std::size_t i = 0; i < n; i++) {
                    a[i] = w[i] * z[i];
                }
            }
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIS_CHANGE_HPP
