//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FFT_EVALUATION_DOMAIN_HPP
#define CRYPTO3_ALGEBRA_FFT_EVALUATION_DOMAIN_HPP

#include <vector>

//#include <boost/math/tools/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace fft {

            /**
             * An evaluation domain.
             */
            template<typename FieldType>
            class evaluation_domain {

                using value_type = typename FieldType::value_type;

            public:

                const size_t m;

                /**
                 * Construct an evaluation domain S of size m, if possible.
                 *
                 * (See the function get_evaluation_domain below.)
                 */
                evaluation_domain(const size_t m) : m(m) {};

                /**
                 * Get the idx-th element in S.
                 */
                virtual value_type get_domain_element(const size_t idx) = 0;

                /**
                 * Compute the FFT, over the domain S, of the vector a.
                 */
                virtual void FFT(std::vector<value_type> &a) = 0;

                /**
                 * Compute the inverse FFT, over the domain S, of the vector a.
                 */
                virtual void iFFT(std::vector<value_type> &a) = 0;

                /**
                 * Evaluate all Lagrange polynomials.
                 *
                 * The inputs are:
                 * - an integer m
                 * - an element t
                 * The output is a vector (b_{0},...,b_{m-1})
                 * where b_{i} is the evaluation of L_{i,S}(z) at z = t.
                 */
                virtual std::vector<value_type> evaluate_all_lagrange_polynomials(const value_type &t) = 0;

                /**
                 * Evaluate the vanishing polynomial of S at the field element t.
                 */
                virtual value_type compute_vanishing_polynomial(const value_type &t) = 0;

                /**
                 * Add the coefficients of the vanishing polynomial of S to the coefficients of the polynomial H.
                 */
                virtual void add_poly_Z(const value_type &coeff, std::vector<value_type> &H) = 0;

                /**
                 * Multiply by the evaluation, on a coset of S, of the inverse of the vanishing polynomial of S.
                 */
                virtual void divide_by_Z_on_coset(std::vector<value_type> &P) = 0;
            };
        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_EVALUATION_DOMAIN_HPP
