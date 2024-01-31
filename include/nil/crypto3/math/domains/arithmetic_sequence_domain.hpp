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

#ifndef CRYPTO3_MATH_ARITHMETIC_SEQUENCE_DOMAIN_HPP
#define CRYPTO3_MATH_ARITHMETIC_SEQUENCE_DOMAIN_HPP

#include <vector>

#include <nil/crypto3/math/domains/evaluation_domain.hpp>

#include <nil/crypto3/math/polynomial/basis_change.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            using namespace nil::crypto3::algebra;

            template<typename FieldType, typename ValueType>
            class evaluation_domain;

            template<typename FieldType, typename ValueType = typename FieldType::value_type>
            class arithmetic_sequence_domain : public evaluation_domain<FieldType, ValueType> {
                typedef typename FieldType::value_type field_value_type;
                typedef ValueType value_type;

            public:
                typedef FieldType field_type;

                bool precomputation_sentinel;
                std::vector<std::vector<std::vector<field_value_type>>> subproduct_tree;
                std::vector<field_value_type> arithmetic_sequence;
                field_value_type arithmetic_generator;

                void do_precomputation() {
                    compute_subproduct_tree<FieldType>(this->subproduct_tree, log2(this->m));

                    arithmetic_generator = field_value_type(fields::arithmetic_params<FieldType>::arithmetic_generator);

                    arithmetic_sequence = std::vector<field_value_type>(this->m);
                    for (std::size_t i = 0; i < this->m; i++) {
                        arithmetic_sequence[i] = arithmetic_generator * field_value_type(i);
                    }

                    precomputation_sentinel = true;
                }

                arithmetic_sequence_domain(const std::size_t m) : evaluation_domain<FieldType, ValueType>(m) {
                    if (m <= 1) {
                        throw std::invalid_argument("arithmetic(): expected m > 1");
                    }

                    if (field_value_type(fields::arithmetic_params<FieldType>::arithmetic_generator).is_zero()) {
                        throw std::invalid_argument(
                            "arithmetic(): expected arithmetic_params<FieldType>::arithmetic_generator.is_zero() "
                            "!= true");
                    }

                    precomputation_sentinel = false;
                }

                void fft(std::vector<value_type> &a) override {
                    if (a.size() != this->m) {
                        if (a.size() < this->m) {
                            a.resize(this->m, value_type::zero());
                        } else {
                            throw std::invalid_argument("arithmetic: expected a.size() == this->m");
                        }
                    }

                    if (!this->precomputation_sentinel) {
                        do_precomputation();
                    }

                    /* Monomial to Newton */
                    monomial_to_newton_basis<FieldType>(a, subproduct_tree, this->m);

                    /* Newton to Evaluation */
                    std::vector<field_value_type> S(this->m); /* i! * arithmetic_generator */
                    S[0] = field_value_type::one();

                    field_value_type factorial = field_value_type::one();
                    for (std::size_t i = 1; i < this->m; i++) {
                        factorial *= field_value_type(i);
                        S[i] = (factorial * arithmetic_generator).inversed();
                    }

                    multiplication(a, a, S);
                    a.resize(this->m);

                    for (std::size_t i = 0; i < this->m; i++) {
                        a[i] = a[i] * S[i].inversed();
                    }
                }

                void inverse_fft(std::vector<value_type> &a) override {
                    if (a.size() != this->m) {
                        if (a.size() < this->m) {
                            a.resize(this->m, value_type::zero());
                        } else {
                            throw std::invalid_argument("arithmetic: expected a.size() == this->m");
                        }
                    }

                    if (!this->precomputation_sentinel)
                        do_precomputation();

                    /* Interpolation to Newton */
                    std::vector<field_value_type> S(this->m); /* i! * arithmetic_generator */
                    S[0] = field_value_type::one();

                    std::vector<value_type> W(this->m);
                    W[0] = a[0] * S[0];

                    field_value_type factorial = field_value_type::one();
                    for (std::size_t i = 1; i < this->m; i++) {
                        factorial *= field_value_type(i);
                        S[i] = (factorial * arithmetic_generator).inversed();
                        W[i] = a[i] * S[i];
                        if (i % 2 == 1)
                            S[i] = -S[i];
                    }

                    multiplication(a, W, S);
                    a.resize(this->m);

                    /* Newton to Monomial */
                    newton_to_monomial_basis<FieldType>(a, subproduct_tree, this->m);
                }

                std::vector<field_value_type> evaluate_all_lagrange_polynomials(const field_value_type &t) override {
                    /* Compute Lagrange polynomial of size m, with m+1 points (x_0, y_0), ... ,(x_m, y_m) */
                    /* Evaluate for x = t */
                    /* Return coeffs for each l_j(x) = (l / l_i[j]) * w[j] */

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /**
                     * If t equals one of the arithmetic progression values,
                     * then output 1 at the right place, and 0 elsewhere.
                     */
                    for (std::size_t i = 0; i < this->m; ++i) {
                        if (arithmetic_sequence[i] == t)    // i.e., t equals this->arithmetic_sequence[i]
                        {
                            std::vector<field_value_type> res(this->m, field_value_type::zero());
                            res[i] = field_value_type::one();
                            return res;
                        }
                    }

                    /**
                     * Otherwise, if t does not equal any of the arithmetic progression values,
                     * then compute each Lagrange coefficient.
                     */
                    std::vector<field_value_type> l(this->m);
                    l[0] = t - this->arithmetic_sequence[0];

                    field_value_type l_vanish = l[0];
                    field_value_type g_vanish = field_value_type::one();

                    for (std::size_t i = 1; i < this->m; i++) {
                        l[i] = t - this->arithmetic_sequence[i];
                        l_vanish *= l[i];
                        g_vanish *= -this->arithmetic_sequence[i];
                    }

                    std::vector<field_value_type> w(this->m);
                    w[0] = g_vanish.inversed() * (this->arithmetic_generator.pow(this->m - 1));

                    l[0] = l_vanish * l[0].inversed() * w[0];
                    for (std::size_t i = 1; i < this->m; i++) {
                        field_value_type num = this->arithmetic_sequence[i - 1] - this->arithmetic_sequence[this->m - 1];
                        w[i] = w[i - 1] * num * this->arithmetic_sequence[i].inversed();
                        l[i] = l_vanish * l[i].inversed() * w[i];
                    }

                    return l;
                }

                std::vector<value_type> evaluate_all_lagrange_polynomials(const typename std::vector<value_type>::const_iterator &t_powers_begin,
                                                                          const typename std::vector<value_type>::const_iterator &t_powers_end) override {
                    if(std::distance(t_powers_begin, t_powers_end) < this->m) {
                        throw std::invalid_argument("arithmetic_sequence_radix2: expected std::distance(t_powers_begin, t_powers_end) >= this->m");
                    }

                    /* Compute Lagrange polynomial of size m, with m+1 points (x_0, y_0), ... ,(x_m, y_m) */
                    /* Evaluate for x = t */
                    /* Return coeffs for each l_j(x) = (l / l_i[j]) * w[j] */

                    if (!precomputation_sentinel)
                        do_precomputation();

                    /**
                     * If t equals one of the arithmetic progression values,
                     * then output 1 at the right place, and 0 elsewhere.
                     */
                    for (std::size_t i = 0; i < this->m; ++i) {
                        if (arithmetic_sequence[i] * t_powers_begin[0] == t_powers_begin[1])    // i.e., t equals a[i]
                        {
                            std::vector<value_type> res(this->m, value_type::zero());
                            res[i] = t_powers_begin[0];
                            return res;
                        }
                    }

                    /**
                     * Otherwise, if t does not equal any of the arithmetic progression values,
                     * then compute each Lagrange coefficient.
                     */
                    std::vector<polynomial<field_value_type>> l(this->m);
                    l[0] = polynomial<field_value_type>({-arithmetic_sequence[0], field_value_type::one()});;

                    polynomial<field_value_type> l_vanish = l[0];
                    field_value_type g_vanish = field_value_type::one();

                    for (std::size_t i = 1; i < this->m; i++) {
                        l[i] = polynomial<field_value_type>({-arithmetic_sequence[i], field_value_type::one()});
                        l_vanish = l_vanish * l[i];
                        g_vanish *= -this->arithmetic_sequence[i];
                    }

                    std::vector<field_value_type> w(this->m);
                    w[0] = g_vanish.inversed() * (this->arithmetic_generator.pow(this->m - 1));

                    for (std::size_t i = 0; i < this->m; i++) {
                        l[i] = l_vanish / l[i];
                    }

                    std::vector<value_type> result(this->m, value_type::zero());

                    for(std::size_t j = 0; j < l[0].size(); ++j) {
                        result[0] = result[0] + t_powers_begin[j] * l[0][j];
                    }
                    result[0] = result[0] * w[0];

                    for (std::size_t i = 1; i < this->m; i++) {
                        field_value_type num = this->arithmetic_sequence[i - 1] - this->arithmetic_sequence[this->m - 1];
                        w[i] = w[i - 1] * num * this->arithmetic_sequence[i].inversed();

                        for(std::size_t j = 0; j < l[i].size(); ++j) {
                            result[i] = result[i] + t_powers_begin[j] * l[i][j];
                        }
                        result[i] = result[i] * w[i];
                    }

                    return result;
                }

                // This one is not the unity root actually, but it's ok for our purposes.
                const field_value_type& get_unity_root() override {
                    return arithmetic_generator;
                }

                field_value_type get_domain_element(const std::size_t idx) override {
                    if (!this->precomputation_sentinel)
                        do_precomputation();

                    return this->arithmetic_sequence[idx];
                }

                field_value_type compute_vanishing_polynomial(const field_value_type &t) override {
                    if (!this->precomputation_sentinel)
                        do_precomputation();

                    /* Notes: Z = prod_{i = 0 to m} (t - a[i]) */
                    field_value_type Z = field_value_type::one();
                    for (std::size_t i = 0; i < this->m; i++) {
                        Z *= (t - this->arithmetic_sequence[i]);
                    }
                    return Z;
                }

                polynomial<field_value_type> get_vanishing_polynomial() override {
                    if (!precomputation_sentinel)
                        do_precomputation();

                    polynomial<field_value_type> z({field_value_type::one()});
                    for (std::size_t i = 0; i < this->m; i++) {
                        z = z * polynomial<field_value_type>({-arithmetic_sequence[i], field_value_type::one()});
                    }
                    return z;
                }

                void add_poly_z(const field_value_type &coeff, std::vector<field_value_type> &H) override {
                    if (H.size() != this->m + 1)
                        throw std::invalid_argument("arithmetic: expected H.size() == this->m+1");

                    if (!this->precomputation_sentinel)
                        do_precomputation();

                    std::vector<field_value_type> x(2, field_value_type::zero());
                    x[0] = -this->arithmetic_sequence[0];
                    x[1] = field_value_type::one();

                    std::vector<field_value_type> t(2, field_value_type::zero());

                    for (std::size_t i = 1; i < this->m + 1; i++) {
                        t[0] = -this->arithmetic_sequence[i];
                        t[1] = field_value_type::one();

                        multiplication(x, x, t);
                    }

                    for (std::size_t i = 0; i < this->m + 1; i++) {
                        H[i] += (x[i] * coeff);
                    }
                }

                void divide_by_z_on_coset(std::vector<field_value_type> &P) override {
                    const field_value_type coset = this->arithmetic_generator; /* coset in arithmetic sequence? */
                    const field_value_type Z_inverse_at_coset = this->compute_vanishing_polynomial(coset).inversed();
                    for (std::size_t i = 0; i < this->m; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }
            };
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_ARITHMETIC_SEQUENCE_DOMAIN_HPP
