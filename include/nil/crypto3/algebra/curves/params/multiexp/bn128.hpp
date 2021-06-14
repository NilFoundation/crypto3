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

#ifndef CRYPTO3_ALGEBRA_CURVES_BN128_MULTIEXP_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_BN128_MULTIEXP_PARAMS_HPP

#include <nil/crypto3/algebra/curves/params.hpp>

#include <nil/crypto3/algebra/curves/bn128.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<typename GroupType>
                struct multiexp_params;

                /************************* BN128-254 ***********************************/

                template<>
                struct multiexp_params<typename bn128<254>::g1_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 4.24]
                        1,
                        // window 2 is unbeaten in [4.24, 10.43]
                        4,
                        // window 3 is unbeaten in [10.43, 24.88]
                        10,
                        // window 4 is unbeaten in [24.88, 62.10]
                        25,
                        // window 5 is unbeaten in [62.10, 157.80]
                        62,
                        // window 6 is unbeaten in [157.80, 362.05]
                        158,
                        // window 7 is unbeaten in [362.05, 806.67]
                        362,
                        // window 8 is unbeaten in [806.67, 2090.34]
                        807,
                        // window 9 is unbeaten in [2090.34, 4459.58]
                        2090,
                        // window 10 is unbeaten in [4459.58, 9280.12]
                        4460,
                        // window 11 is unbeaten in [9280.12, 43302.64]
                        9280,
                        // window 12 is unbeaten in [43302.64, 210998.73]
                        43303,
                        // window 13 is never the best
                        0,
                        // window 14 is never the best
                        0,
                        // window 15 is unbeaten in [210998.73, 506869.47]
                        210999,
                        // window 16 is unbeaten in [506869.47, 930023.36]
                        506869,
                        // window 17 is unbeaten in [930023.36, 8350812.20]
                        930023,
                        // window 18 is never the best
                        0,
                        // window 19 is never the best
                        0,
                        // window 20 is unbeaten in [8350812.20, 21708138.87]
                        8350812,
                        // window 21 is unbeaten in [21708138.87, 29482995.52]
                        21708139,
                        // window 22 is unbeaten in [29482995.52, inf]
                        29482996};
                };

                template<>
                struct multiexp_params<typename bn128<254>::g2_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 4.13]
                        1,
                        // window 2 is unbeaten in [4.13, 10.72]
                        4,
                        // window 3 is unbeaten in [10.72, 25.60]
                        11,
                        // window 4 is unbeaten in [25.60, 60.99]
                        26,
                        // window 5 is unbeaten in [60.99, 153.66]
                        61,
                        // window 6 is unbeaten in [153.66, 353.13]
                        154,
                        // window 7 is unbeaten in [353.13, 771.87]
                        353,
                        // window 8 is unbeaten in [771.87, 2025.85]
                        772,
                        // window 9 is unbeaten in [2025.85, 4398.65]
                        2026,
                        // window 10 is unbeaten in [4398.65, 10493.42]
                        4399,
                        // window 11 is unbeaten in [10493.42, 37054.73]
                        10493,
                        // window 12 is unbeaten in [37054.73, 49928.78]
                        37055,
                        // window 13 is unbeaten in [49928.78, 114502.82]
                        49929,
                        // window 14 is unbeaten in [114502.82, 161445.26]
                        114503,
                        // window 15 is unbeaten in [161445.26, 470648.01]
                        161445,
                        // window 16 is unbeaten in [470648.01, 1059821.87]
                        470648,
                        // window 17 is unbeaten in [1059821.87, 5450848.25]
                        1059822,
                        // window 18 is never the best
                        0,
                        // window 19 is unbeaten in [5450848.25, 5566795.57]
                        5450848,
                        // window 20 is unbeaten in [5566795.57, 33055217.52]
                        5566796,
                        // window 21 is never the best
                        0,
                        // window 22 is unbeaten in [33055217.52, inf]
                        33055218};
                };

                /************************* BN128-254 definitions ***********************************/

                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename bn128<254>::g1_type>::fixed_base_exp_window_table;
                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename bn128<254>::g2_type>::fixed_base_exp_window_table;

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BN128_MULTIEXP_PARAMS_HPP
