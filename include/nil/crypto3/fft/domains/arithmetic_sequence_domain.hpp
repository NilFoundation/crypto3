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

#ifndef CRYPTO3_ALGEBRA_FFT_ARITHMETIC_SEQUENCE_DOMAIN_HPP
#define CRYPTO3_ALGEBRA_FFT_ARITHMETIC_SEQUENCE_DOMAIN_HPP

#include <vector>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
//#include <nil/crypto3/fft/domains/basic_radix2_domain_aux.hpp>
#include <nil/crypto3/fft/polynomial_arithmetic/basis_change.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace nil {
    namespace crypto3 {
        namespace fft {

            using namespace nil::crypto3::algebra;

            template<typename FieldType>
            class evaluation_domain;

            template<typename FieldType>
            class arithmetic_sequence_domain : public evaluation_domain<FieldType> {
                typedef typename FieldType::value_type value_type;

            public:
                bool precomputation_sentinel;
                std::vector<std::vector<std::vector<value_type>>> subproduct_tree;
                std::vector<value_type> arithmetic_sequence;
                value_type arithmetic_generator;

                void do_precomputation() {
                    compute_subproduct_tree<FieldType>(log2(this->m), this->subproduct_tree);

                    this->arithmetic_generator = value_type(fields::arithmetic_params<FieldType>::arithmetic_generator);

                    this->arithmetic_sequence = std::vector<value_type>(this->m);
                    for (std::size_t i = 0; i < this->m; i++) {
                        this->arithmetic_sequence[i] = this->arithmetic_generator * value_type(i);
                    }

                    this->precomputation_sentinel = 1;
                }

                arithmetic_sequence_domain(const std::size_t m) : evaluation_domain<FieldType>(m) {
                    // if (m <= 1) {
                    //    throw std::invalid_argument("arithmetic(): expected m > 1");
                    //}

                    // if (!(value_type(fields::arithmetic_params<FieldType>::arithmetic_generator).is_zero())) {
                    //    throw std::invalid_argument(
                    //        "arithmetic(): expected arithmetic_params<FieldType>::arithmetic_generator.is_zero() "
                    //        "!= true");
                    //}

                    precomputation_sentinel = 0;
                }

                void FFT(std::vector<value_type> &a) {
                    // if (a.size() != this->m) {
                    //    throw std::invalid_argument("arithmetic: expected a.size() == this->m");
                    //}

                    if (!this->precomputation_sentinel) {
                        do_precomputation();
                    }

                    /* Monomial to Newton */
                    monomial_to_newton_basis<FieldType>(a, this->subproduct_tree, this->m);

                    /* Newton to Evaluation */
                    std::vector<value_type> S(this->m); /* i! * arithmetic_generator */
                    S[0] = value_type::one();

                    value_type factorial = value_type::one();
                    for (std::size_t i = 1; i < this->m; i++) {
                        factorial *= value_type(i);
                        S[i] = (factorial * this->arithmetic_generator).inversed();
                    }

                    _polynomial_multiplication<FieldType>(a, a, S);
                    a.resize(this->m);

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (std::size_t i = 0; i < this->m; i++) {
                        a[i] *= S[i].inversed();
                    }
                }
                void iFFT(std::vector<value_type> &a) {
                    // if (a.size() != this->m)
                    //    throw std::invalid_argument("arithmetic: expected a.size() == this->m");

                    if (!this->precomputation_sentinel)
                        do_precomputation();

                    /* Interpolation to Newton */
                    std::vector<value_type> S(this->m); /* i! * arithmetic_generator */
                    S[0] = value_type::one();

                    std::vector<value_type> W(this->m);
                    W[0] = a[0] * S[0];

                    value_type factorial = value_type::one();
                    for (std::size_t i = 1; i < this->m; i++) {
                        factorial *= value_type(i);
                        S[i] = (factorial * this->arithmetic_generator).inversed();
                        W[i] = a[i] * S[i];
                        if (i % 2 == 1)
                            S[i] = -S[i];
                    }

                    _polynomial_multiplication<FieldType>(a, W, S);
                    a.resize(this->m);

                    /* Newton to Monomial */
                    newton_to_monomial_basis<FieldType>(a, this->subproduct_tree, this->m);
                }

                std::vector<value_type> evaluate_all_lagrange_polynomials(const value_type &t) {
                    /* Compute Lagrange polynomial of size m, with m+1 points (x_0, y_0), ... ,(x_m, y_m) */
                    /* Evaluate for x = t */
                    /* Return coeffs for each l_j(x) = (l / l_i[j]) * w[j] */

                    if (!this->precomputation_sentinel)
                        do_precomputation();

                    /**
                     * If t equals one of the arithmetic progression values,
                     * then output 1 at the right place, and 0 elsewhere.
                     */
                    for (std::size_t i = 0; i < this->m; ++i) {
                        if (this->arithmetic_sequence[i] == t)    // i.e., t equals this->arithmetic_sequence[i]
                        {
                            std::vector<value_type> res(this->m, value_type::zero());
                            res[i] = value_type::one();
                            return res;
                        }
                    }

                    /**
                     * Otherwise, if t does not equal any of the arithmetic progression values,
                     * then compute each Lagrange coefficient.
                     */
                    std::vector<value_type> l(this->m);
                    l[0] = t - this->arithmetic_sequence[0];

                    value_type l_vanish = l[0];
                    value_type g_vanish = value_type::one();

                    for (std::size_t i = 1; i < this->m; i++) {
                        l[i] = t - this->arithmetic_sequence[i];
                        l_vanish *= l[i];
                        g_vanish *= -this->arithmetic_sequence[i];
                    }

                    std::vector<value_type> w(this->m);
                    w[0] = g_vanish.inversed() * (this->arithmetic_generator.pow(this->m - 1));

                    l[0] = l_vanish * l[0].inversed() * w[0];
                    for (std::size_t i = 1; i < this->m; i++) {
                        value_type num = this->arithmetic_sequence[i - 1] - this->arithmetic_sequence[this->m - 1];
                        w[i] = w[i - 1] * num * this->arithmetic_sequence[i].inversed();
                        l[i] = l_vanish * l[i].inversed() * w[i];
                    }

                    return l;
                }
                value_type get_domain_element(const std::size_t idx) {
                    if (!this->precomputation_sentinel)
                        do_precomputation();

                    return this->arithmetic_sequence[idx];
                }
                value_type compute_vanishing_polynomial(const value_type &t) {
                    if (!this->precomputation_sentinel)
                        do_precomputation();

                    /* Notes: Z = prod_{i = 0 to m} (t - a[i]) */
                    value_type Z = value_type::one();
                    for (std::size_t i = 0; i < this->m; i++) {
                        Z *= (t - this->arithmetic_sequence[i]);
                    }
                    return Z;
                }
                void add_poly_Z(const value_type &coeff, std::vector<value_type> &H) {
                    if (H.size() != this->m + 1)
                        throw std::invalid_argument("arithmetic: expected H.size() == this->m+1");

                    if (!this->precomputation_sentinel)
                        do_precomputation();

                    std::vector<value_type> x(2, value_type::zero());
                    x[0] = -this->arithmetic_sequence[0];
                    x[1] = value_type::one();

                    std::vector<value_type> t(2, value_type::zero());

                    for (std::size_t i = 1; i < this->m + 1; i++) {
                        t[0] = -this->arithmetic_sequence[i];
                        t[1] = value_type::one();

                        _polynomial_multiplication<FieldType>(x, x, t);
                    }

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (std::size_t i = 0; i < this->m + 1; i++) {
                        H[i] += (x[i] * coeff);
                    }
                }
                void divide_by_Z_on_coset(std::vector<value_type> &P) {
                    const value_type coset = this->arithmetic_generator; /* coset in arithmetic sequence? */
                    const value_type Z_inverse_at_coset = this->compute_vanishing_polynomial(coset).inversed();
                    for (std::size_t i = 0; i < this->m; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }
            };
        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_ARITHMETIC_SEQUENCE_DOMAIN_HPP
