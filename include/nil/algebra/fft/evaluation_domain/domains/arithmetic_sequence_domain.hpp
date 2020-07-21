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

#include <nil/algebra/fft/evaluation_domain/evaluation_domain.hpp>
#include <nil/algebra/fft/evaluation_domain/domains/basic_radix2_domain_aux.hpp>
#include <nil/algebra/fft/polynomial_arithmetic/basis_change.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace nil {
    namespace algebra {
        namespace fft {

            template<typename FieldT>
            struct arithmetic_sequence_domain : public evaluation_domain<FieldT> {

                arithmetic_sequence_domain(const size_t m) : evaluation_domain<FieldT>(m) {
                    //if (m <= 1)
                        //throw InvalidSizeException("arithmetic(): expected this->m > 1");
                    //if (FieldT::arithmetic_generator() == FieldT::zero())
                        //throw InvalidSizeException("arithmetic(): expected FieldT::arithmetic_generator() != FieldT::zero()");

                    precomputation_sentinel = 0;
                }

                void FFT(std::vector<FieldT> &a) {
                    //if (a.size() != this->m)
                        //throw DomainSizeException("arithmetic: expected a.size() == this->m");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Monomial to Newton */
                    monomial_to_newton_basis(a, subproduct_tree, this->m);

                    /* Newton to Evaluation */
                    std::vector<FieldT> S(this->m); /* i! * arithmetic_generator */
                    S[0] = FieldT::one();

                    FieldT factorial = FieldT::one();
                    for (size_t i = 1; i < this->m; i++) {
                        factorial *= FieldT(i);
                        S[i] = (factorial * arithmetic_generator).inverse();
                    }

                    _polynomial_multiplication(a, a, S);
                    a.resize(this->m);

            #ifdef MULTICORE
            #pragma omp parallel for
            #endif
                    for (size_t i = 0; i < this->m; i++) {
                        a[i] *= S[i].inverse();
                    }
                }

                void iFFT(std::vector<FieldT> &a) {
                    //if (a.size() != this->m)
                        //throw DomainSizeException("arithmetic: expected a.size() == this->m");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Interpolation to Newton */
                    std::vector<FieldT> S(this->m); /* i! * arithmetic_generator */
                    S[0] = FieldT::one();

                    std::vector<FieldT> W(this->m);
                    W[0] = a[0] * S[0];

                    FieldT factorial = FieldT::one();
                    for (size_t i = 1; i < this->m; i++) {
                        factorial *= FieldT(i);
                        S[i] = (factorial * arithmetic_generator).inverse();
                        W[i] = a[i] * S[i];
                        if (i % 2 == 1)
                            S[i] = -S[i];
                    }

                    _polynomial_multiplication(a, W, S);
                    a.resize(this->m);

                    /* Newton to Monomial */
                    newton_to_monomial_basis(a, subproduct_tree, this->m);
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

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /**
                     * If t equals one of the arithmetic progression values,
                     * then output 1 at the right place, and 0 elsewhere.
                     */
                    for (size_t i = 0; i < this->m; ++i) {
                        if (arithmetic_sequence[i] == t)    // i.e., t equals arithmetic_sequence[i]
                        {
                            std::vector<FieldT> res(this->m, FieldT::zero());
                            res[i] = FieldT::one();
                            return res;
                        }
                    }

                    /**
                     * Otherwise, if t does not equal any of the arithmetic progression values,
                     * then compute each Lagrange coefficient.
                     */
                    std::vector<FieldT> l(this->m);
                    l[0] = t - arithmetic_sequence[0];

                    FieldT l_vanish = l[0];
                    FieldT g_vanish = FieldT::one();

                    for (size_t i = 1; i < this->m; i++) {
                        l[i] = t - arithmetic_sequence[i];
                        l_vanish *= l[i];
                        g_vanish *= -arithmetic_sequence[i];
                    }

                    std::vector<FieldT> w(this->m);
                    w[0] = g_vanish.inverse() * (arithmetic_generator ^ (this->m - 1));

                    l[0] = l_vanish * l[0].inverse() * w[0];
                    for (size_t i = 1; i < this->m; i++) {
                        FieldT num = arithmetic_sequence[i - 1] - arithmetic_sequence[this->m - 1];
                        w[i] = w[i - 1] * num * arithmetic_sequence[i].inverse();
                        l[i] = l_vanish * l[i].inverse() * w[i];
                    }

                    return l;
                }

                FieldT get_domain_element(const size_t idx) {
                    if (!precomputation_sentinel)
                        do_precomputation();

                    return arithmetic_sequence[idx];
                }

                FieldT compute_vanishing_polynomial(const FieldT &t) {
                    if (!precomputation_sentinel)
                        do_precomputation();

                    /* Notes: Z = prod_{i = 0 to m} (t - a[i]) */
                    FieldT Z = FieldT::one();
                    for (size_t i = 0; i < this->m; i++) {
                        Z *= (t - arithmetic_sequence[i]);
                    }
                    return Z;
                }

                void add_poly_Z(const FieldT &coeff, std::vector<FieldT> &H) {
                    //if (H.size() != this->m + 1)
                        //throw DomainSizeException("arithmetic: expected H.size() == this->m+1");

                    if (!precomputation_sentinel)
                        do_precomputation();

                    std::vector<FieldT> x(2, FieldT::zero());
                    x[0] = -arithmetic_sequence[0];
                    x[1] = FieldT::one();

                    std::vector<FieldT> t(2, FieldT::zero());

                    for (size_t i = 1; i < this->m + 1; i++) {
                        t[0] = -arithmetic_sequence[i];
                        t[1] = FieldT::one();

                        _polynomial_multiplication(x, x, t);
                    }

            #ifdef MULTICORE
            #pragma omp parallel for
            #endif
                    for (size_t i = 0; i < this->m + 1; i++) {
                        H[i] += (x[i] * coeff);
                    }
                }

                void divide_by_Z_on_coset(std::vector<FieldT> &P) {
                    const FieldT coset = arithmetic_generator; /* coset in arithmetic sequence? */
                    const FieldT Z_inverse_at_coset = compute_vanishing_polynomial(coset).inverse();
                    for (size_t i = 0; i < this->m; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }

                void do_precomputation() {
                    compute_subproduct_tree(log2(this->m), subproduct_tree);

                    arithmetic_generator = FieldT::arithmetic_generator();

                    arithmetic_sequence = std::vector<FieldT>(this->m);
                    for (size_t i = 0; i < this->m; i++) {
                        arithmetic_sequence[i] = arithmetic_generator * FieldT(i);
                    }

                    precomputation_sentinel = 1;
                }


            private:

                bool precomputation_sentinel;
                std::vector<std::vector<std::vector<FieldT>>> subproduct_tree;
                std::vector<FieldT> arithmetic_sequence;
                FieldT arithmetic_generator;
            };

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_ARITHMETIC_SEQUENCE_DOMAIN_HPP
