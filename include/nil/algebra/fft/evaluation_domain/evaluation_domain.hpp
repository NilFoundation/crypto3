//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_EVALUATION_DOMAIN_HPP
#define ALGEBRA_FFT_EVALUATION_DOMAIN_HPP

#include <vector>

namespace nil {
    namespace algebra {
        namespace fft {

            /**
             * An evaluation domain.
             */
            template<typename FieldT>
            struct evaluation_domain {
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
                virtual FieldT get_domain_element(const size_t idx) = 0;

                /**
                 * Compute the FFT, over the domain S, of the vector a.
                 */
                virtual void FFT(std::vector<FieldT> &a) = 0;

                /**
                 * Compute the inverse FFT, over the domain S, of the vector a.
                 */
                virtual void iFFT(std::vector<FieldT> &a) = 0;

                /**
                 * Compute the FFT, over the domain g*S, of the vector a.
                 */
                virtual void cosetFFT(std::vector<FieldT> &a, const FieldT &g) = 0;

                /**
                 * Compute the inverse FFT, over the domain g*S, of the vector a.
                 */
                virtual void icosetFFT(std::vector<FieldT> &a, const FieldT &g) = 0;

                /**
                 * Evaluate all Lagrange polynomials.
                 *
                 * The inputs are:
                 * - an integer m
                 * - an element t
                 * The output is a vector (b_{0},...,b_{m-1})
                 * where b_{i} is the evaluation of L_{i,S}(z) at z = t.
                 */
                virtual std::vector<FieldT> evaluate_all_lagrange_polynomials(const FieldT &t) = 0;

                /**
                 * Evaluate the vanishing polynomial of S at the field element t.
                 */
                virtual FieldT compute_vanishing_polynomial(const FieldT &t) = 0;

                /**
                 * Add the coefficients of the vanishing polynomial of S to the coefficients of the polynomial H.
                 */
                virtual void add_poly_Z(const FieldT &coeff, std::vector<FieldT> &H) = 0;

                /**
                 * Multiply by the evaluation, on a coset of S, of the inverse of the vanishing polynomial of S.
                 */
                virtual void divide_by_Z_on_coset(std::vector<FieldT> &P) = 0;
            };

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_EVALUATION_DOMAIN_HPP
