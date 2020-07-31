//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_XGCD_HPP
#define ALGEBRA_FFT_XGCD_HPP

#include <algorithm>
#include <vector>

#include <nil/algebra/fft/domains/basic_radix2_domain_aux.hpp>
#include <nil/algebra/fft/polynomial_arithmetic/basic_operations.hpp>

namespace nil {
    namespace algebra {
        namespace fft {

            /*!
             * @brief Perform the standard Extended Euclidean Division algorithm.
             * Input: Polynomial A, Polynomial B.
             * Output: Polynomial G, Polynomial U, Polynomial V, such that G = (A * U) + (B * V).
             */

            template<typename FieldType>
            void _polynomial_xgcd(const std::vector<FieldType> &a, const std::vector<FieldType> &b, std::vector<FieldType> &g,
                                  std::vector<FieldType> &u, std::vector<FieldType> &v) {
                if (_is_zero(b)) {
                    g = a;
                    u = std::vector<FieldType>(1, FieldType::one());
                    v = std::vector<FieldType>(1, FieldType::zero());
                    return;
                }

                std::vector<FieldType> U(1, FieldType::one());
                std::vector<FieldType> V1(1, FieldType::zero());
                std::vector<FieldType> G(a);
                std::vector<FieldType> V3(b);

                std::vector<FieldType> Q(1, FieldType::zero());
                std::vector<FieldType> R(1, FieldType::zero());
                std::vector<FieldType> T(1, FieldType::zero());

                while (!_is_zero(V3)) {
                    _polynomial_division(Q, R, G, V3);
                    _polynomial_multiplication(G, V1, Q);
                    _polynomial_subtraction(T, U, G);

                    U = V1;
                    G = V3;
                    V1 = T;
                    V3 = R;
                }

                _polynomial_multiplication(V3, a, U);
                _polynomial_subtraction(V3, G, V3);
                _polynomial_division(V1, R, V3, b);

                FieldType lead_coeff = G.back().inverse();
                std::transform(G.begin(), G.end(), G.begin(), std::bind1st(std::multiplies<FieldType>(), lead_coeff));
                std::transform(U.begin(), U.end(), U.begin(), std::bind1st(std::multiplies<FieldType>(), lead_coeff));
                std::transform(V1.begin(), V1.end(), V1.begin(), std::bind1st(std::multiplies<FieldType>(), lead_coeff));

                g = G;
                u = U;
                v = V1;
            }

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_XGCD_HPP
