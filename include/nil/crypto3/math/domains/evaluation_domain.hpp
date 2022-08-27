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

#ifndef CRYPTO3_MATH_EVALUATION_DOMAIN_HPP
#define CRYPTO3_MATH_EVALUATION_DOMAIN_HPP

#include <vector>

#include <nil/crypto3/multiprecision/integer.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            /**
             * An evaluation domain.
             */
            template<typename FieldType, typename ValueType = typename FieldType::value_type>
            class evaluation_domain {

                typedef typename FieldType::value_type field_value_type;
                typedef ValueType value_type;

            public:
                typedef FieldType field_type;

                field_value_type root;
                field_value_type root_inverse;
                field_value_type domain;
                field_value_type domain_inverse;
                field_value_type generator;
                field_value_type generator_inverse;

                std::size_t m;
                std::size_t log2_size;
                std::size_t generator_size;

                /**
                 * Construct an evaluation domain S of size m, if possible.
                 *
                 * (See the function get_evaluation_domain below.)
                 */
                evaluation_domain(const std::size_t m) : m(m), log2_size(multiprecision::msb(m)) {};

                inline std::size_t size() const {
                    return m;
                }

                /**
                 * Get the idx-th element in S.
                 */
                virtual field_value_type get_domain_element(const std::size_t idx) = 0;

                /**
                 * Compute the FFT, over the domain S, of the vector a.
                 */
                virtual void fft(std::vector<value_type> &a) = 0;

                /**
                 * Compute the inverse FFT, over the domain S, of the vector a.
                 */
                virtual void inverse_fft(std::vector<value_type> &a) = 0;

                /**
                 * Evaluate all Lagrange polynomials.
                 *
                 * The inputs are:
                 * - an integer m
                 * - an element t
                 * The output is a vector (b_{0},...,b_{m-1})
                 * where b_{i} is the evaluation of L_{i,S}(z) at z = t.
                 */
                virtual std::vector<field_value_type> evaluate_all_lagrange_polynomials(const field_value_type &t) = 0;

                /**
                 * Evaluate all Lagrange polynomials.
                 *
                 * The inputs are:
                 * - an integer m
                 * - a vector (t**0,...,t**(m-1)) t_powers for some element t
                 * The output is a vector (b_{0},...,b_{m-1})
                 * where b_{i} is the evaluation of L_{i,S}(z) at z = t.
                 */
                virtual std::vector<value_type> evaluate_all_lagrange_polynomials(const typename std::vector<value_type>::const_iterator &t_powers_begin,
                                                                                  const typename std::vector<value_type>::const_iterator &t_powers_end) = 0;

                /**
                 * Evaluate the vanishing polynomial of S at the field element t.
                 */
                virtual field_value_type compute_vanishing_polynomial(const field_value_type &t) = 0;

                /**
                 * Build the vanishing polynomial of S.
                 */
                virtual polynomial<field_value_type> get_vanishing_polynomial() = 0;

                /**
                 * Add the coefficients of the vanishing polynomial of S to the coefficients of the polynomial H.
                 */
                virtual void add_poly_z(const field_value_type &coeff, std::vector<field_value_type> &H) = 0;

                /**
                 * Multiply by the evaluation, on a coset of S, of the inverse of the vanishing polynomial of S.
                 */
                virtual void divide_by_z_on_coset(std::vector<field_value_type> &P) = 0;

                bool operator==(const evaluation_domain &rhs) const {
                    return root == rhs.root && root_inverse == rhs.root_inverse && domain == rhs.domain &&
                           domain_inverse == rhs.domain_inverse && generator == rhs.generator &&
                           generator_inverse == rhs.generator_inverse && m == rhs.m && log2_size == rhs.log2_size &&
                           generator_size == rhs.generator_size;
                }
            };
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_EVALUATION_DOMAIN_HPP
