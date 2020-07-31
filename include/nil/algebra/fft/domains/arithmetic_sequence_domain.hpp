//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_ARITHMETIC_SEQUENCE_DOMAIN_HPP
#define ALGEBRA_FFT_ARITHMETIC_SEQUENCE_DOMAIN_HPP

#include <vector>

#include <nil/algebra/fft/evaluation_domain.hpp>
#include <nil/algebra/fft/domains/basic_radix2_domain_aux.hpp>
#include <nil/algebra/fft/polynomial_arithmetic/basis_change.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace nil {
    namespace algebra {
        namespace fft {

            template<typename FieldType, std::size_t MinSize>
            struct arithmetic_sequence_domain : public evaluation_domain<FieldType, MinSize> {
                static_assert(MinSize > 1, "arithmetic(): expected MinSize > 1");
                //                if (FieldType::arithmetic_generator() == FieldType::zero())
                //                throw InvalidSizeException(
                //                "arithmetic(): expected FieldType::arithmetic_generator() != "
                //                "FieldType::zero()");

                void FFT(std::vector<FieldType> &a) {
                    if (a.size() != MinSize)
                        throw DomainSizeException("arithmetic: expected a.size() == MinSize");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Monomial to Newton */
                    monomial_to_newton_basis(a, subproduct_tree, MinSize);

                    /* Newton to Evaluation */
                    std::vector<FieldType> S(MinSize); /* i! * arithmetic_generator */
                    S[0] = FieldType::one();

                    FieldType factorial = FieldType::one();
                    for (size_t i = 1; i < MinSize; i++) {
                        factorial *= FieldType(i);
                        S[i] = (factorial * arithmetic_generator).inverse();
                    }

                    _polynomial_multiplication(a, a, S);
                    a.resize(MinSize);

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (size_t i = 0; i < MinSize; i++) {
                        a[i] *= S[i].inverse();
                    }
                }

                void iFFT(std::vector<FieldType> &a) {
                    if (a.size() != MinSize)
                        throw DomainSizeException("arithmetic: expected a.size() == MinSize");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Interpolation to Newton */
                    std::vector<FieldType> S(MinSize); /* i! * arithmetic_generator */
                    S[0] = FieldType::one();

                    std::vector<FieldType> W(MinSize);
                    W[0] = a[0] * S[0];

                    FieldType factorial = FieldType::one();
                    for (size_t i = 1; i < MinSize; i++) {
                        factorial *= FieldType(i);
                        S[i] = (factorial * arithmetic_generator).inverse();
                        W[i] = a[i] * S[i];
                        if (i % 2 == 1)
                            S[i] = -S[i];
                    }

                    _polynomial_multiplication(a, W, S);
                    a.resize(MinSize);

                    /* Newton to Monomial */
                    newton_to_monomial_basis(a, subproduct_tree, MinSize);
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

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /**
                     * If t equals one of the arithmetic progression values,
                     * then output 1 at the right place, and 0 elsewhere.
                     */
                    for (size_t i = 0; i < MinSize; ++i) {
                        if (arithmetic_sequence[i] == t)    // i.e., t equals arithmetic_sequence[i]
                        {
                            std::vector<FieldType> res(MinSize, FieldType::zero());
                            res[i] = FieldType::one();
                            return res;
                        }
                    }

                    /**
                     * Otherwise, if t does not equal any of the arithmetic progression values,
                     * then compute each Lagrange coefficient.
                     */
                    std::vector<FieldType> l(MinSize);
                    l[0] = t - arithmetic_sequence[0];

                    FieldType l_vanish = l[0];
                    FieldType g_vanish = FieldType::one();

                    for (size_t i = 1; i < MinSize; i++) {
                        l[i] = t - arithmetic_sequence[i];
                        l_vanish *= l[i];
                        g_vanish *= -arithmetic_sequence[i];
                    }

                    std::vector<FieldType> w(MinSize);
                    w[0] = g_vanish.inverse() * (arithmetic_generator ^ (MinSize - 1));

                    l[0] = l_vanish * l[0].inverse() * w[0];
                    for (size_t i = 1; i < MinSize; i++) {
                        FieldType num = arithmetic_sequence[i - 1] - arithmetic_sequence[MinSize - 1];
                        w[i] = w[i - 1] * num * arithmetic_sequence[i].inverse();
                        l[i] = l_vanish * l[i].inverse() * w[i];
                    }

                    return l;
                }

                FieldType get_domain_element(const size_t idx) {
                    if (!precomputation_sentinel)
                        do_precomputation();

                    return arithmetic_sequence[idx];
                }

                FieldType compute_vanishing_polynomial(const FieldType &t) {
                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Notes: Z = prod_{i = 0 to m} (t - a[i]) */
                    FieldType Z = FieldType::one();
                    for (size_t i = 0; i < MinSize; i++) {
                        Z *= (t - arithmetic_sequence[i]);
                    }
                    return Z;
                }

                void add_poly_Z(const FieldType &coeff, std::vector<FieldType> &H) {
                    if (H.size() != MinSize + 1)
                        throw DomainSizeException("arithmetic: expected H.size() == MinSize+1");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    std::vector<FieldType> x(2, FieldType::zero());
                    x[0] = -arithmetic_sequence[0];
                    x[1] = FieldType::one();

                    std::vector<FieldType> t(2, FieldType::zero());

                    for (size_t i = 1; i < MinSize + 1; i++) {
                        t[0] = -arithmetic_sequence[i];
                        t[1] = FieldType::one();

                        _polynomial_multiplication(x, x, t);
                    }

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (size_t i = 0; i < MinSize + 1; i++) {
                        H[i] += (x[i] * coeff);
                    }
                }

                void divide_by_Z_on_coset(std::vector<FieldType> &P) {
                    const FieldType coset = arithmetic_generator; /* coset in arithmetic sequence? */
                    const FieldType Z_inverse_at_coset = compute_vanishing_polynomial(coset).inverse();
                    for (size_t i = 0; i < MinSize; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }

                void do_precomputation() {
                    compute_subproduct_tree(log2(MinSize), subproduct_tree);

                    arithmetic_generator = FieldType::arithmetic_generator();

                    arithmetic_sequence = std::vector<FieldType>(MinSize);
                    for (size_t i = 0; i < MinSize; i++) {
                        arithmetic_sequence[i] = arithmetic_generator * FieldType(i);
                    }

                    precomputation_sentinel = 1;
                }

            private:
                bool precomputation_sentinel = false;
                std::vector<std::vector<std::vector<FieldType>>> subproduct_tree;
                std::vector<FieldType> arithmetic_sequence;
                FieldType arithmetic_generator;
            };

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_ARITHMETIC_SEQUENCE_DOMAIN_HPP
