//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_BASIS_CHANGE_HPP
#define ALGEBRA_FFT_BASIS_CHANGE_HPP

#include <algorithm>
#include <vector>

#include <boost/math/tools/polynomial.hpp>

#include <nil/algebra/fft/domains/basic_radix2_domain_aux.hpp>
#include <nil/algebra/fft/polynomial_arithmetic/basic_operations.hpp>
#include <nil/algebra/fft/polynomial_arithmetic/xgcd.hpp>

namespace nil {
    namespace algebra {
        namespace fft {

            /**
             * Compute the Subproduct Tree of degree 2^M and store it in Tree T.
             * Below we make use of the Subproduct Tree description from
             * [Bostan and Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points], on page 7.
             */
            template<typename FieldValueType>
            void compute_subproduct_tree(const size_t &m, std::vector<std::vector<std::vector<FieldValueType>>> &T) {
                if (T.size() != m + 1)
                    T.resize(m + 1);

                /*
                 * Subproduct tree T is represented as a 2-dimensional array T_{i, j}.
                 * T_{i, j} = product_{l = [2^i * j] to [2^i * (j+1) - 1]} (x - x_l)
                 * Note: n = 2^m.
                 */

                /* Precompute the first row. */
                T[0] = std::vector<std::vector<FieldValueType>>(1u << m);
                for (size_t j = 0; j < (1u << m); j++) {
                    T[0][j] = std::vector<FieldValueType>(2, FieldValueType::one());
                    T[0][j][0] = FieldValueType(-j);
                }

                std::vector<FieldValueType> a;
                std::vector<FieldValueType> b;

                size_t index = 0;
                for (size_t i = 1; i <= m; i++) {
                    T[i] = std::vector<std::vector<FieldValueType>>(1u << (m - i));
                    for (size_t j = 0; j < (1u << (m - i)); j++) {
                        a = T[i - 1][index];
                        index++;

                        b = T[i - 1][index];
                        index++;

                        _polynomial_multiplication<FieldType>(T[i][j], a, b);
                    }
                    index = 0;
                }
            }

            /**
             * Perform the general change of basis from Monomial to Newton Basis with Subproduct Tree T.
             * Below we make use of the MonomialToNewton and TNewtonToMonomial pseudocode from
             * [Bostan and Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points], on page 12
             * and 14.
             */
            template<typename FieldValueType>
            void monomial_to_newton_basis(std::vector<FieldValueType> &a,
                                          const std::vector<std::vector<std::vector<FieldValueType>>> &T,
                                          const size_t &n) {
                size_t m = log2(n);
                // if (T.size() != m + 1u)
                // throw DomainSizeException("expected T.size() == m + 1");

                /* MonomialToNewton */
                std::vector<FieldValueType> I(T[m][0]);
                _reverse(I, n);

                std::vector<FieldValueType> mod(n + 1, FieldValueType::zero());
                mod[n] = FieldValueType::one();

                _polynomial_xgcd(mod, I, mod, mod, I);

                I.resize(n);

                std::vector<FieldValueType> Q(_polynomial_multiplication_transpose(n - 1, I, a));
                _reverse(Q, n);

                /* TNewtonToMonomial */
                std::vector<std::vector<FieldValueType>> c(n);
                c[0] = Q;

                size_t row_length;
                size_t c_vec;
                /* NB: unsigned reverse iteration: cannot do i >= 0, but can do i < m
                   because unsigned integers are guaranteed to wrap around */
                for (size_t i = m - 1; i < m; i--) {
                    row_length = T[i].size() - 1;
                    c_vec = 1u << i;

                    /* NB: unsigned reverse iteration */
                    for (size_t j = (1u << (m - i - 1)) - 1; j < (1u << (m - i - 1)); j--) {
                        c[2 * j + 1] =
                            _polynomial_multiplication_transpose((1u << i) - 1, T[i][row_length - 2 * j], c[j]);
                        c[2 * j] = c[j];
                        c[2 * j].resize(c_vec);
                    }
                }

                /* Store Computed Newton Basis Coefficients */
                size_t j = 0;
                /* NB: unsigned reverse iteration */
                for (size_t i = c.size() - 1; i < c.size(); i--) {
                    a[j++] = c[i][0];
                }
            }

            /**
             * Perform the general change of basis from Newton to Monomial Basis with Subproduct Tree T.
             * Below we make use of the NewtonToMonomial pseudocode from
             * [Bostan and Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points], on page 11.
             */
            template<typename FieldValueType>
            void newton_to_monomial_basis(std::vector<FieldValueType> &a,
                                          const std::vector<std::vector<std::vector<FieldValueType>>> &T,
                                          const size_t &n) {
                size_t m = log2(n);
                // if (T.size() != m + 1u)
                // throw DomainSizeException("expected T.size() == m + 1");

                std::vector<std::vector<FieldValueType>> f(n);
                for (size_t i = 0; i < n; i++) {
                    f[i] = std::vector<FieldValueType>(1, a[i]);
                }

                /* NewtonToMonomial */
                std::vector<FieldValueType> temp(1, FieldValueType::zero());
                for (size_t i = 0; i < m; i++) {
                    for (size_t j = 0; j < (1u << (m - i - 1)); j++) {
                        _polynomial_multiplication<FieldType>(temp, T[i][2 * j], f[2 * j + 1]);
                        _polynomial_addition<FieldType>(f[j], f[2 * j], temp);
                    }
                }

                a = f[0];
            }

            /**
             * Perform the change of basis from Monomial to Newton Basis for geometric sequence.
             * Below we make use of the psuedocode from
             * [Bostan & Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points] on page 26.
             */
            template<typename FieldValueType>
            void monomial_to_newton_basis_geometric(std::vector<FieldValueType> &a,
                                                    const std::vector<FieldValueType> &geometric_sequence,
                                                    const std::vector<FieldValueType> &geometric_triangular_sequence,
                                                    const size_t &n) {
                std::vector<FieldValueType> u(n, FieldValueType::zero());
                std::vector<FieldValueType> w(n, FieldValueType::zero());
                std::vector<FieldValueType> z(n, FieldValueType::zero());
                std::vector<FieldValueType> f(n, FieldValueType::zero());
                u[0] = FieldValueType::one();
                w[0] = a[0];
                z[0] = FieldValueType::one();
                f[0] = a[0];

                for (size_t i = 1; i < n; i++) {
                    u[i] = u[i - 1] * geometric_sequence[i] * (FieldValueType::one() - geometric_sequence[i]).inversed();
                    w[i] = a[i] * (u[i].inversed());
                    z[i] = u[i] * geometric_triangular_sequence[i].inversed();
                    f[i] = w[i] * geometric_triangular_sequence[i];

                    if (i % 2 == 1) {
                        z[i] = -z[i];
                        f[i] = -f[i];
                    }
                }

                w = _polynomial_multiplication_transpose(n - 1, z, f);

#ifdef MULTICORE
#pragma omp parallel for
#endif
                for (size_t i = 0; i < n; i++) {
                    a[i] = w[i] * z[i];
                }
            }

            /**
             * Perform the change of basis from Newton to Monomial Basis for geometric sequence
             * Below we make use of the psuedocode from
             * [Bostan & Schost 2005. Polynomial Evaluation and Interpolation on Special Sets of Points] on page 26.
             */
            template<typename FieldValueType>
            void newton_to_monomial_basis_geometric(std::vector<FieldValueType> &a,
                                                    const std::vector<FieldValueType> &geometric_sequence,
                                                    const std::vector<FieldValueType> &geometric_triangular_sequence,
                                                    const size_t &n) {
                std::vector<FieldValueType> v(n, FieldValueType::zero());
                std::vector<FieldValueType> u(n, FieldValueType::zero());
                std::vector<FieldValueType> w(n, FieldValueType::zero());
                std::vector<FieldValueType> z(n, FieldValueType::zero());
                v[0] = a[0];
                u[0] = FieldValueType::one();
                w[0] = a[0];
                z[0] = FieldValueType::one();

                for (size_t i = 1; i < n; i++) {
                    v[i] = a[i] * geometric_triangular_sequence[i];
                    if (i % 2 == 1)
                        v[i] = -v[i];

                    u[i] = u[i - 1] * geometric_sequence[i] * (FieldValueType::one() - geometric_sequence[i]).inversed();
                    w[i] = v[i] * u[i].inversed();

                    z[i] = u[i] * geometric_triangular_sequence[i].inversed();
                    if (i % 2 == 1)
                        z[i] = -z[i];
                }

                w = _polynomial_multiplication_transpose(n - 1, u, w);

#ifdef MULTICORE
#pragma omp parallel for
#endif
                for (size_t i = 0; i < n; i++) {
                    a[i] = w[i] * z[i];
                }
            }

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIS_CHANGE_HPP
