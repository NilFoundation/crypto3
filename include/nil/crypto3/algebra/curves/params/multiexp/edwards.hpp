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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_MULTIEXP_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_MULTIEXP_PARAMS_HPP

#include <nil/crypto3/algebra/curves/params.hpp>

#include <nil/crypto3/algebra/curves/edwards.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<typename GroupType>
                struct multiexp_params;

                /************************* EDWARDS-183 ***********************************/

                template<>
                struct multiexp_params<typename edwards<183>::g1_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 4.10]
                        1,
                        // window 2 is unbeaten in [4.10, 9.69]
                        4,
                        // window 3 is unbeaten in [9.69, 25.21]
                        10,
                        // window 4 is unbeaten in [25.21, 60.00]
                        25,
                        // window 5 is unbeaten in [60.00, 149.33]
                        60,
                        // window 6 is unbeaten in [149.33, 369.61]
                        149,
                        // window 7 is unbeaten in [369.61, 849.07]
                        370,
                        // window 8 is unbeaten in [849.07, 1764.94]
                        849,
                        // window 9 is unbeaten in [1764.94, 4429.59]
                        1765,
                        // window 10 is unbeaten in [4429.59, 13388.78]
                        4430,
                        // window 11 is unbeaten in [13388.78, 15368.00]
                        13389,
                        // window 12 is unbeaten in [15368.00, 74912.07]
                        15368,
                        // window 13 is unbeaten in [74912.07, 438107.20]
                        74912,
                        // window 14 is never the best
                        0,
                        // window 15 is unbeaten in [438107.20, 1045626.18]
                        438107,
                        // window 16 is never the best
                        0,
                        // window 17 is unbeaten in [1045626.18, 1577434.48]
                        1045626,
                        // window 18 is unbeaten in [1577434.48, 17350594.23]
                        1577434,
                        // window 19 is never the best
                        0,
                        // window 20 is never the best
                        0,
                        // window 21 is unbeaten in [17350594.23, inf]
                        17350594,
                        // window 22 is never the best
                        0};
                };

                template<>
                struct multiexp_params<typename edwards<183>::g2_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 4.74]
                        1,
                        // window 2 is unbeaten in [4.74, 10.67]
                        5,
                        // window 3 is unbeaten in [10.67, 25.53]
                        11,
                        // window 4 is unbeaten in [25.53, 60.67]
                        26,
                        // window 5 is unbeaten in [60.67, 145.77]
                        61,
                        // window 6 is unbeaten in [145.77, 356.76]
                        146,
                        // window 7 is unbeaten in [356.76, 823.08]
                        357,
                        // window 8 is unbeaten in [823.08, 1589.45]
                        823,
                        // window 9 is unbeaten in [1589.45, 4135.70]
                        1589,
                        // window 10 is unbeaten in [4135.70, 14297.74]
                        4136,
                        // window 11 is unbeaten in [14297.74, 16744.85]
                        14298,
                        // window 12 is unbeaten in [16744.85, 51768.98]
                        16745,
                        // window 13 is unbeaten in [51768.98, 99811.01]
                        51769,
                        // window 14 is unbeaten in [99811.01, 193306.72]
                        99811,
                        // window 15 is unbeaten in [193306.72, 907184.68]
                        193307,
                        // window 16 is never the best
                        0,
                        // window 17 is unbeaten in [907184.68, 1389682.59]
                        907185,
                        // window 18 is unbeaten in [1389682.59, 6752695.74]
                        1389683,
                        // window 19 is never the best
                        0,
                        // window 20 is unbeaten in [6752695.74, 193642894.51]
                        6752696,
                        // window 21 is unbeaten in [193642894.51, 226760202.29]
                        193642895,
                        // window 22 is unbeaten in [226760202.29, inf]
                        226760202};
                };

                /************************* EDWARDS-183 definitions ***********************************/

                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename edwards<183>::g1_type>::fixed_base_exp_window_table;
                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename edwards<183>::g2_type>::fixed_base_exp_window_table;

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_MULTIEXP_PARAMS_HPP
