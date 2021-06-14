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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT4_MULTIEXP_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT4_MULTIEXP_PARAMS_HPP

#include <nil/crypto3/algebra/curves/params.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<typename GroupType>
                struct multiexp_params;

                /************************* MNT4-298 ***********************************/

                template<>
                struct multiexp_params<typename mnt4<298>::g1_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 5.09]
                        1,
                        // window 2 is unbeaten in [5.09, 9.64]
                        5,
                        // window 3 is unbeaten in [9.64, 24.79]
                        10,
                        // window 4 is unbeaten in [24.79, 60.29]
                        25,
                        // window 5 is unbeaten in [60.29, 144.37]
                        60,
                        // window 6 is unbeaten in [144.37, 344.90]
                        144,
                        // window 7 is unbeaten in [344.90, 855.00]
                        345,
                        // window 8 is unbeaten in [855.00, 1804.62]
                        855,
                        // window 9 is unbeaten in [1804.62, 3912.30]
                        1805,
                        // window 10 is unbeaten in [3912.30, 11264.50]
                        3912,
                        // window 11 is unbeaten in [11264.50, 27897.51]
                        11265,
                        // window 12 is unbeaten in [27897.51, 57596.79]
                        27898,
                        // window 13 is unbeaten in [57596.79, 145298.71]
                        57597,
                        // window 14 is unbeaten in [145298.71, 157204.59]
                        145299,
                        // window 15 is unbeaten in [157204.59, 601600.62]
                        157205,
                        // window 16 is unbeaten in [601600.62, 1107377.25]
                        601601,
                        // window 17 is unbeaten in [1107377.25, 1789646.95]
                        1107377,
                        // window 18 is unbeaten in [1789646.95, 4392626.92]
                        1789647,
                        // window 19 is unbeaten in [4392626.92, 8221210.60]
                        4392627,
                        // window 20 is unbeaten in [8221210.60, 42363731.19]
                        8221211,
                        // window 21 is never the best
                        0,
                        // window 22 is unbeaten in [42363731.19, inf]
                        42363731};
                };

                template<>
                struct multiexp_params<typename mnt4<298>::g2_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 4.17]
                        1,
                        // window 2 is unbeaten in [4.17, 10.12]
                        4,
                        // window 3 is unbeaten in [10.12, 24.65]
                        10,
                        // window 4 is unbeaten in [24.65, 60.03]
                        25,
                        // window 5 is unbeaten in [60.03, 143.16]
                        60,
                        // window 6 is unbeaten in [143.16, 344.73]
                        143,
                        // window 7 is unbeaten in [344.73, 821.24]
                        345,
                        // window 8 is unbeaten in [821.24, 1793.92]
                        821,
                        // window 9 is unbeaten in [1793.92, 3919.59]
                        1794,
                        // window 10 is unbeaten in [3919.59, 11301.46]
                        3920,
                        // window 11 is unbeaten in [11301.46, 18960.09]
                        11301,
                        // window 12 is unbeaten in [18960.09, 44198.62]
                        18960,
                        // window 13 is unbeaten in [44198.62, 150799.57]
                        44199,
                        // window 14 is never the best
                        0,
                        // window 15 is unbeaten in [150799.57, 548694.81]
                        150800,
                        // window 16 is unbeaten in [548694.81, 1051769.08]
                        548695,
                        // window 17 is unbeaten in [1051769.08, 2023925.59]
                        1051769,
                        // window 18 is unbeaten in [2023925.59, 3787108.68]
                        2023926,
                        // window 19 is unbeaten in [3787108.68, 7107480.30]
                        3787109,
                        // window 20 is unbeaten in [7107480.30, 38760027.14]
                        7107480,
                        // window 21 is never the best
                        0,
                        // window 22 is unbeaten in [38760027.14, inf]
                        38760027};
                };

                /************************* MNT4-298 definitions ***********************************/

                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename mnt4<298>::g1_type>::fixed_base_exp_window_table;
                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename mnt4<298>::g2_type>::fixed_base_exp_window_table;

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_MNT4_MULTIEXP_PARAMS_HPP
