//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CAS_FFT_GEOMETRIC_SEQUENCE_DOMAIN_HPP
#define CAS_FFT_GEOMETRIC_SEQUENCE_DOMAIN_HPP

#include <vector>

#include <nil/cas/fft/evaluation_domain/evaluation_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/basic_radix2_domain_aux.hpp>

#include <nil/cas/fft/polynomial_arithmetic/basis_change.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace nil {
    namespace cas {
        namespace fft {

            template<typename FieldT>
            struct geometric_sequence_domain : public evaluation_domain<FieldT> {

                geometric_sequence_domain(const size_t m) : evaluation_domain<FieldT>(m) {
                    if (m <= 1)
                        throw InvalidSizeException("geometric(): expected m > 1");
                    if (FieldT::geometric_generator() == FieldT::zero())
                        throw InvalidSizeException("geometric(): expected FieldT::geometric_generator() != FieldT::zero()");

                    precomputation_sentinel = 0;
                }

                void FFT(std::vector<FieldT> &a) {
                    if (a.size() != m)
                        throw DomainSizeException("geometric: expected a.size() == m");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    monomial_to_newton_basis_geometric(a, geometric_sequence, geometric_triangular_sequence, m);

                    /* Newton to Evaluation */
                    std::vector<FieldT> T(m);
                    T[0] = FieldT::one();

                    std::vector<FieldT> g(m);
                    g[0] = a[0];

                    for (size_t i = 1; i < m; i++) {
                        T[i] = T[i - 1] * (geometric_sequence[i] - FieldT::one()).inverse();
                        g[i] = geometric_triangular_sequence[i] * a[i];
                    }

                    _polynomial_multiplication(a, g, T);
                    a.resize(m);

            #ifdef MULTICORE
            #pragma omp parallel for
            #endif
                    for (size_t i = 0; i < m; i++) {
                        a[i] *= T[i].inverse();
                    }
                }

                void iFFT(std::vector<FieldT> &a) {
                    if (a.size() != m)
                        throw DomainSizeException("geometric: expected a.size() == m");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Interpolation to Newton */
                    std::vector<FieldT> T(m);
                    T[0] = FieldT::one();

                    std::vector<FieldT> W(m);
                    W[0] = a[0] * T[0];

                    FieldT prev_T = T[0];
                    for (size_t i = 1; i < m; i++) {
                        prev_T *= (geometric_sequence[i] - FieldT::one()).inverse();

                        W[i] = a[i] * prev_T;
                        T[i] = geometric_triangular_sequence[i] * prev_T;
                        if (i % 2 == 1)
                            T[i] = -T[i];
                    }

                    _polynomial_multiplication(a, W, T);
                    a.resize(m);

            #ifdef MULTICORE
            #pragma omp parallel for
            #endif
                    for (size_t i = 0; i < m; i++) {
                        a[i] *= geometric_triangular_sequence[i].inverse();
                    }

                    newton_to_monomial_basis_geometric(a, geometric_sequence, geometric_triangular_sequence, m);
                }

                void cosetFFT(std::vector<FieldT> &a, const FieldT &g) {
                    _multiply_by_coset(a, g);
                    FFT(a);
                }

                void icosetFFT(std::vector<FieldT> &a, const FieldT &g) {
                    iFFT(a);
                    _multiply_by_coset(a, g.inverse());
                }

                std::vector<FieldT> evaluate_all_lagrange_polynomials(const FieldT &t) {
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
                    for (size_t i = 0; i < m; ++i) {
                        if (geometric_sequence[i] == t)    // i.e., t equals a[i]
                        {
                            std::vector<FieldT> res(m, FieldT::zero());
                            res[i] = FieldT::one();
                            return res;
                        }
                    }

                    /**
                     * Otherwise, if t does not equal any of the geometric progression values,
                     * then compute each Lagrange coefficient.
                     */
                    std::vector<FieldT> l(m);
                    l[0] = t - geometric_sequence[0];

                    std::vector<FieldT> g(m);
                    g[0] = FieldT::zero();

                    FieldT l_vanish = l[0];
                    FieldT g_vanish = FieldT::one();
                    for (size_t i = 1; i < m; i++) {
                        l[i] = t - geometric_sequence[i];
                        g[i] = FieldT::one() - geometric_sequence[i];

                        l_vanish *= l[i];
                        g_vanish *= g[i];
                    }

                    FieldT r = geometric_sequence[m - 1].inverse();
                    FieldT r_i = r;

                    std::vector<FieldT> g_i(m);
                    g_i[0] = g_vanish.inverse();

                    l[0] = l_vanish * l[0].inverse() * g_i[0];
                    for (size_t i = 1; i < m; i++) {
                        g_i[i] = g_i[i - 1] * g[m - i] * -g[i].inverse() * geometric_sequence[i];
                        l[i] = l_vanish * r_i * l[i].inverse() * g_i[i];
                        r_i *= r;
                    }

                    return l;
                }

                FieldT get_domain_element(const size_t idx) {
                    if (!precomputation_sentinel)
                        do_precomputation();

                    return geometric_sequence[idx];
                }

                FieldT compute_vanishing_polynomial(const FieldT &t) {
                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Notes: Z = prod_{i = 0 to m} (t - a[i]) */
                    /* Better approach: Montgomery Trick + Divide&Conquer/FFT */
                    FieldT Z = FieldT::one();
                    for (size_t i = 0; i < m; i++) {
                        Z *= (t - geometric_sequence[i]);
                    }
                    return Z;
                }

                void add_poly_Z(const FieldT &coeff, std::vector<FieldT> &H) {
                    if (H.size() != m + 1)
                        throw DomainSizeException("geometric: expected H.size() == m+1");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    std::vector<FieldT> x(2, FieldT::zero());
                    x[0] = -geometric_sequence[0];
                    x[1] = FieldT::one();

                    std::vector<FieldT> t(2, FieldT::zero());

                    for (size_t i = 1; i < m + 1; i++) {
                        t[0] = -geometric_sequence[i];
                        t[1] = FieldT::one();

                        _polynomial_multiplication(x, x, t);
                    }

            #ifdef MULTICORE
            #pragma omp parallel for
            #endif
                    for (size_t i = 0; i < m + 1; i++) {
                        H[i] += (x[i] * coeff);
                    }
                }

                void divide_by_Z_on_coset(std::vector<FieldT> &P) {
                    const FieldT coset = FieldT::multiplicative_generator; /* coset in geometric sequence? */
                    const FieldT Z_inverse_at_coset = compute_vanishing_polynomial(coset).inverse();
                    for (size_t i = 0; i < m; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }

                void do_precomputation() {
                    geometric_sequence = std::vector<FieldT>(m, FieldT::zero());
                    geometric_sequence[0] = FieldT::one();

                    geometric_triangular_sequence = std::vector<FieldT>(m, FieldT::zero());
                    geometric_triangular_sequence[0] = FieldT::one();

                    for (size_t i = 1; i < m; i++) {
                        geometric_sequence[i] = geometric_sequence[i - 1] * FieldT::geometric_generator();
                        geometric_triangular_sequence[i] =
                            geometric_triangular_sequence[i - 1] * geometric_sequence[i - 1];
                    }

                    precomputation_sentinel = 1;
                }
            private:
                bool precomputation_sentinel;
                std::vector<FieldT> geometric_sequence;
                std::vector<FieldT> geometric_triangular_sequence;
            };

        }    // namespace fft
    }        // namespace cas
}    // namespace nil

#endif    // CAS_FFT_GEOMETRIC_SEQUENCE_DOMAIN_HPP
