//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_GEOMETRIC_SEQUENCE_DOMAIN_HPP
#define ALGEBRA_FFT_GEOMETRIC_SEQUENCE_DOMAIN_HPP

#include <vector>

#include <nil/algebra/fft/evaluation_domain/evaluation_domain.hpp>
#include <nil/algebra/fft/evaluation_domain/domains/basic_radix2_domain_aux.hpp>

#include <nil/algebra/fft/polynomial_arithmetic/basis_change.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace nil {
    namespace algebra {
        namespace fft {

            template<typename FieldType>
            struct geometric_sequence_domain : public evaluation_domain<FieldType> {

                geometric_sequence_domain(const size_t m) : evaluation_domain<FieldType>(m) {
                    if (m <= 1)
                        throw InvalidSizeException("geometric(): expected m > 1");
                    if (FieldType::geometric_generator() == FieldType::zero())
                        throw InvalidSizeException(
                            "geometric(): expected FieldType::geometric_generator() != FieldType::zero()");

                    precomputation_sentinel = 0;
                }

                void FFT(std::vector<FieldType> &a) {
                    if (a.size() != this->m)
                        throw DomainSizeException("geometric: expected a.size() == this->m");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    monomial_to_newton_basis_geometric(a, geometric_sequence, geometric_triangular_sequence, this->m);

                    /* Newton to Evaluation */
                    std::vector<FieldType> T(this->m);
                    T[0] = FieldType::one();

                    std::vector<FieldType> g(this->m);
                    g[0] = a[0];

                    for (size_t i = 1; i < this->m; i++) {
                        T[i] = T[i - 1] * (geometric_sequence[i] - FieldType::one()).inverse();
                        g[i] = geometric_triangular_sequence[i] * a[i];
                    }

                    _polynomial_multiplication(a, g, T);
                    a.resize(this->m);

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (size_t i = 0; i < this->m; i++) {
                        a[i] *= T[i].inverse();
                    }
                }

                void iFFT(std::vector<FieldType> &a) {
                    if (a.size() != this->m)
                        throw DomainSizeException("geometric: expected a.size() == this->m");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Interpolation to Newton */
                    std::vector<FieldType> T(this->m);
                    T[0] = FieldType::one();

                    std::vector<FieldType> W(this->m);
                    W[0] = a[0] * T[0];

                    FieldType prev_T = T[0];
                    for (size_t i = 1; i < this->m; i++) {
                        prev_T *= (geometric_sequence[i] - FieldType::one()).inverse();

                        W[i] = a[i] * prev_T;
                        T[i] = geometric_triangular_sequence[i] * prev_T;
                        if (i % 2 == 1)
                            T[i] = -T[i];
                    }

                    _polynomial_multiplication(a, W, T);
                    a.resize(this->m);

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (size_t i = 0; i < this->m; i++) {
                        a[i] *= geometric_triangular_sequence[i].inverse();
                    }

                    newton_to_monomial_basis_geometric(a, geometric_sequence, geometric_triangular_sequence, this->m);
                }

                void cosetFFT(std::vector<FieldType> &a, const FieldType &g) {
                    detail::multiply_by_coset(a, g);
                    FFT(a);
                }

                void icosetFFT(std::vector<FieldType> &a, const FieldType &g) {
                    iFFT(a);
                    detail::multiply_by_coset(a, g.inverse());
                }

                std::vector<FieldType> evaluate_all_lagrange_polynomials(const FieldType &t) {
                    /* Compute Lagrange polynomial of size m, with m+1 points (x_0, y_0), ... ,(x_m, y_m) */
                    /* Evaluate for x = t */
                    /* Return coeffs for each l_j(x) = (l / l_i[j]) * w[j] */

                    /* for all i: w[i] = (1 / r) * w[i-1] * (1 - a[i]^m-i+1) / (1 - a[i]^-i) */

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /**
                     * If t equals one of the geometric progression values,
                     * then output 1 at the right place, and 0 elsewhere.
                     */
                    for (size_t i = 0; i < this->m; ++i) {
                        if (geometric_sequence[i] == t)    // i.e., t equals a[i]
                        {
                            std::vector<FieldType> res(this->m, FieldType::zero());
                            res[i] = FieldType::one();
                            return res;
                        }
                    }

                    /**
                     * Otherwise, if t does not equal any of the geometric progression values,
                     * then compute each Lagrange coefficient.
                     */
                    std::vector<FieldType> l(this->m);
                    l[0] = t - geometric_sequence[0];

                    std::vector<FieldType> g(this->m);
                    g[0] = FieldType::zero();

                    FieldType l_vanish = l[0];
                    FieldType g_vanish = FieldType::one();
                    for (size_t i = 1; i < this->m; i++) {
                        l[i] = t - geometric_sequence[i];
                        g[i] = FieldType::one() - geometric_sequence[i];

                        l_vanish *= l[i];
                        g_vanish *= g[i];
                    }

                    FieldType r = geometric_sequence[this->m - 1].inverse();
                    FieldType r_i = r;

                    std::vector<FieldType> g_i(this->m);
                    g_i[0] = g_vanish.inverse();

                    l[0] = l_vanish * l[0].inverse() * g_i[0];
                    for (size_t i = 1; i < this->m; i++) {
                        g_i[i] = g_i[i - 1] * g[this->m - i] * -g[i].inverse() * geometric_sequence[i];
                        l[i] = l_vanish * r_i * l[i].inverse() * g_i[i];
                        r_i *= r;
                    }

                    return l;
                }

                FieldType get_domain_element(const size_t idx) {
                    if (!precomputation_sentinel)
                        do_precomputation();

                    return geometric_sequence[idx];
                }

                FieldType compute_vanishing_polynomial(const FieldType &t) {
                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Notes: Z = prod_{i = 0 to m} (t - a[i]) */
                    /* Better approach: Montgomery Trick + Divide&Conquer/FFT */
                    FieldType Z = FieldType::one();
                    for (size_t i = 0; i < this->m; i++) {
                        Z *= (t - geometric_sequence[i]);
                    }
                    return Z;
                }

                void add_poly_Z(const FieldType &coeff, std::vector<FieldType> &H) {
                    if (H.size() != m + 1)
                        throw DomainSizeException("geometric: expected H.size() == m+1");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    std::vector<FieldType> x(2, FieldType::zero());
                    x[0] = -geometric_sequence[0];
                    x[1] = FieldType::one();

                    std::vector<FieldType> t(2, FieldType::zero());

                    for (size_t i = 1; i < this->m + 1; i++) {
                        t[0] = -geometric_sequence[i];
                        t[1] = FieldType::one();

                        _polynomial_multiplication(x, x, t);
                    }

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (size_t i = 0; i < this->m + 1; i++) {
                        H[i] += (x[i] * coeff);
                    }
                }

                void divide_by_Z_on_coset(std::vector<FieldType> &P) {
                    const FieldType coset = FieldType::multiplicative_generator; /* coset in geometric sequence? */
                    const FieldType Z_inverse_at_coset = compute_vanishing_polynomial(coset).inverse();
                    for (size_t i = 0; i < this->m; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }

                void do_precomputation() {
                    geometric_sequence = std::vector<FieldType>(this->m, FieldType::zero());
                    geometric_sequence[0] = FieldType::one();

                    geometric_triangular_sequence = std::vector<FieldType>(this->m, FieldType::zero());
                    geometric_triangular_sequence[0] = FieldType::one();

                    for (size_t i = 1; i < this->m; i++) {
                        geometric_sequence[i] = geometric_sequence[i - 1] * FieldType::geometric_generator();
                        geometric_triangular_sequence[i] =
                            geometric_triangular_sequence[i - 1] * geometric_sequence[i - 1];
                    }

                    precomputation_sentinel = 1;
                }

            private:
                bool precomputation_sentinel;
                std::vector<FieldType> geometric_sequence;
                std::vector<FieldType> geometric_triangular_sequence;
            };

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_GEOMETRIC_SEQUENCE_DOMAIN_HPP
