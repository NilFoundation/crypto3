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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT6_MULTIEXP_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT6_MULTIEXP_PARAMS_HPP

#include <nil/crypto3/algebra/curves/params.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<typename GroupType>
                struct multiexp_params;

                /************************* MNT6-298 ***********************************/

                template<>
                struct multiexp_params<typename mnt6<298>::g1_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 3.96]
                        1,
                        // window 2 is unbeaten in [3.96, 9.67]
                        4,
                        // window 3 is unbeaten in [9.67, 25.13]
                        10,
                        // window 4 is unbeaten in [25.13, 60.31]
                        25,
                        // window 5 is unbeaten in [60.31, 146.07]
                        60,
                        // window 6 is unbeaten in [146.07, 350.09]
                        146,
                        // window 7 is unbeaten in [350.09, 844.54]
                        350,
                        // window 8 is unbeaten in [844.54, 1839.64]
                        845,
                        // window 9 is unbeaten in [1839.64, 3904.26]
                        1840,
                        // window 10 is unbeaten in [3904.26, 11309.42]
                        3904,
                        // window 11 is unbeaten in [11309.42, 24015.57]
                        11309,
                        // window 12 is unbeaten in [24015.57, 72288.57]
                        24016,
                        // window 13 is unbeaten in [72288.57, 138413.22]
                        72289,
                        // window 14 is unbeaten in [138413.22, 156390.30]
                        138413,
                        // window 15 is unbeaten in [156390.30, 562560.50]
                        156390,
                        // window 16 is unbeaten in [562560.50, 1036742.02]
                        562560,
                        // window 17 is unbeaten in [1036742.02, 2053818.86]
                        1036742,
                        // window 18 is unbeaten in [2053818.86, 4370223.95]
                        2053819,
                        // window 19 is unbeaten in [4370223.95, 8215703.81]
                        4370224,
                        // window 20 is unbeaten in [8215703.81, 42682375.43]
                        8215704,
                        // window 21 is never the best
                        0,
                        // window 22 is unbeaten in [42682375.43, inf]
                        42682375};
                };

                template<>
                struct multiexp_params<typename mnt6<298>::g2_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 4.25]
                        1,
                        // window 2 is unbeaten in [4.25, 10.22]
                        4,
                        // window 3 is unbeaten in [10.22, 24.85]
                        10,
                        // window 4 is unbeaten in [24.85, 60.06]
                        25,
                        // window 5 is unbeaten in [60.06, 143.61]
                        60,
                        // window 6 is unbeaten in [143.61, 345.66]
                        144,
                        // window 7 is unbeaten in [345.66, 818.56]
                        346,
                        // window 8 is unbeaten in [818.56, 1782.06]
                        819,
                        // window 9 is unbeaten in [1782.06, 4002.45]
                        1782,
                        // window 10 is unbeaten in [4002.45, 10870.18]
                        4002,
                        // window 11 is unbeaten in [10870.18, 18022.51]
                        10870,
                        // window 12 is unbeaten in [18022.51, 43160.74]
                        18023,
                        // window 13 is unbeaten in [43160.74, 149743.32]
                        43161,
                        // window 14 is never the best
                        0,
                        // window 15 is unbeaten in [149743.32, 551844.13]
                        149743,
                        // window 16 is unbeaten in [551844.13, 1041827.91]
                        551844,
                        // window 17 is unbeaten in [1041827.91, 1977371.53]
                        1041828,
                        // window 18 is unbeaten in [1977371.53, 3703619.51]
                        1977372,
                        // window 19 is unbeaten in [3703619.51, 7057236.87]
                        3703620,
                        // window 20 is unbeaten in [7057236.87, 38554491.67]
                        7057237,
                        // window 21 is never the best
                        0,
                        // window 22 is unbeaten in [38554491.67, inf]
                        38554492};
                };

                /************************* MNT6-298 definitions ***********************************/

                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename mnt6<298>::g1_type>::fixed_base_exp_window_table;
                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename mnt6<298>::g2_type>::fixed_base_exp_window_table;

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_MNT6_MULTIEXP_PARAMS_HPP
