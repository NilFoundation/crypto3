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
            void _polynomial_xgcd(const std::vector<typename FieldType::value_type> &a, const std::vector<typename FieldType::value_type> &b, std::vector<typename FieldType::value_type> &g,
                                  std::vector<typename FieldType::value_type> &u, std::vector<typename FieldType::value_type> &v) {

                using value_type = typename FieldType::value_type;

                if (_is_zero(b)) {
                    g = a;
                    u = std::vector<value_type>(1, value_type::one());
                    v = std::vector<value_type>(1, value_type::zero());
                    return;
                }

                std::vector<value_type> U(1, value_type::one());
                std::vector<value_type> V1(1, value_type::zero());
                std::vector<value_type> G(a);
                std::vector<value_type> V3(b);

                std::vector<value_type> Q(1, value_type::zero());
                std::vector<value_type> R(1, value_type::zero());
                std::vector<value_type> T(1, value_type::zero());

                while (!_is_zero(V3)) {
                    _polynomial_division<FieldType>(Q, R, G, V3);
                    _polynomial_multiplication<FieldType>(G, V1, Q);
                    _polynomial_subtraction<FieldType>(T, U, G);

                    U = V1;
                    G = V3;
                    V1 = T;
                    V3 = R;
                }

                _polynomial_multiplication<FieldType>(V3, a, U);
                _polynomial_subtraction<FieldType>(V3, G, V3);
                _polynomial_division<FieldType>(V1, R, V3, b);

                value_type lead_coeff = G.back().inversed();
                std::transform(G.begin(), G.end(), G.begin(), std::bind1st(std::multiplies<value_type>(), lead_coeff));
                std::transform(U.begin(), U.end(), U.begin(), std::bind1st(std::multiplies<value_type>(), lead_coeff));
                std::transform(V1.begin(), V1.end(), V1.begin(), std::bind1st(std::multiplies<value_type>(), lead_coeff));

                g = G;
                u = U;
                v = V1;
            }

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_XGCD_HPP
