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

#ifndef CRYPTO3_ALGEBRA_FFT_XGCD_HPP
#define CRYPTO3_ALGEBRA_FFT_XGCD_HPP

#include <algorithm>
#include <vector>

//#include <nil/crypto3/fft/domains/basic_radix2_domain_aux.hpp>
#include <nil/crypto3/fft/polynomial_arithmetic/basic_operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace fft {

            /*!
             * @brief Perform the standard Extended Euclidean Division algorithm.
             * Input: Polynomial A, Polynomial B.
             * Output: Polynomial G, Polynomial U, Polynomial V, such that G = (A * U) + (B * V).
             */

            template<typename FieldType>
            void _polynomial_xgcd(const std::vector<typename FieldType::value_type> &a,
                                  const std::vector<typename FieldType::value_type> &b,
                                  std::vector<typename FieldType::value_type> &g,
                                  std::vector<typename FieldType::value_type> &u,
                                  std::vector<typename FieldType::value_type> &v) {

                typedef typename FieldType::value_type value_type;

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
                std::transform(G.begin(), G.end(), G.begin(),
                               std::bind(std::multiplies<value_type>(), lead_coeff, std::placeholders::_1));
                std::transform(U.begin(), U.end(), U.begin(),
                               std::bind(std::multiplies<value_type>(), lead_coeff, std::placeholders::_1));
                std::transform(V1.begin(), V1.end(), V1.begin(),
                               std::bind(std::multiplies<value_type>(), lead_coeff, std::placeholders::_1));

                g = G;
                u = U;
                v = V1;
            }

        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_XGCD_HPP
