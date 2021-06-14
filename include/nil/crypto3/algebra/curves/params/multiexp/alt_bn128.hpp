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

#ifndef CRYPTO3_ALGEBRA_CURVES_ALT_BN128_MULTIEXP_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_ALT_BN128_MULTIEXP_PARAMS_HPP

#include <nil/crypto3/algebra/curves/params.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<typename GroupType>
                struct multiexp_params;

                /************************* ALT_BN128-254 ***********************************/

                template<>
                struct multiexp_params<typename alt_bn128<254>::g1_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 4.99]
                        1,
                        // window 2 is unbeaten in [4.99, 10.99]
                        5,
                        // window 3 is unbeaten in [10.99, 32.29]
                        11,
                        // window 4 is unbeaten in [32.29, 55.23]
                        32,
                        // window 5 is unbeaten in [55.23, 162.03]
                        55,
                        // window 6 is unbeaten in [162.03, 360.15]
                        162,
                        // window 7 is unbeaten in [360.15, 815.44]
                        360,
                        // window 8 is unbeaten in [815.44, 2373.07]
                        815,
                        // window 9 is unbeaten in [2373.07, 6977.75]
                        2373,
                        // window 10 is unbeaten in [6977.75, 7122.23]
                        6978,
                        // window 11 is unbeaten in [7122.23, 57818.46]
                        7122,
                        // window 12 is never the best
                        0,
                        // window 13 is unbeaten in [57818.46, 169679.14]
                        57818,
                        // window 14 is never the best
                        0,
                        // window 15 is unbeaten in [169679.14, 439758.91]
                        169679,
                        // window 16 is unbeaten in [439758.91, 936073.41]
                        439759,
                        // window 17 is unbeaten in [936073.41, 4666554.74]
                        936073,
                        // window 18 is never the best
                        0,
                        // window 19 is unbeaten in [4666554.74, 7580404.42]
                        4666555,
                        // window 20 is unbeaten in [7580404.42, 34552892.20]
                        7580404,
                        // window 21 is never the best
                        0,
                        // window 22 is unbeaten in [34552892.20, inf]
                        34552892};
                };

                template<>
                struct multiexp_params<typename alt_bn128<254>::g2_type> {

                    constexpr static const std::array<std::size_t, 22> fixed_base_exp_window_table = {
                        // window 1 is unbeaten in [-inf, 5.10]
                        1,
                        // window 2 is unbeaten in [5.10, 10.43]
                        5,
                        // window 3 is unbeaten in [10.43, 25.28]
                        10,
                        // window 4 is unbeaten in [25.28, 59.00]
                        25,
                        // window 5 is unbeaten in [59.00, 154.03]
                        59,
                        // window 6 is unbeaten in [154.03, 334.25]
                        154,
                        // window 7 is unbeaten in [334.25, 742.58]
                        334,
                        // window 8 is unbeaten in [742.58, 2034.40]
                        743,
                        // window 9 is unbeaten in [2034.40, 4987.56]
                        2034,
                        // window 10 is unbeaten in [4987.56, 8888.27]
                        4988,
                        // window 11 is unbeaten in [8888.27, 26271.13]
                        8888,
                        // window 12 is unbeaten in [26271.13, 39768.20]
                        26271,
                        // window 13 is unbeaten in [39768.20, 106275.75]
                        39768,
                        // window 14 is unbeaten in [106275.75, 141703.40]
                        106276,
                        // window 15 is unbeaten in [141703.40, 462422.97]
                        141703,
                        // window 16 is unbeaten in [462422.97, 926871.84]
                        462423,
                        // window 17 is unbeaten in [926871.84, 4873049.17]
                        926872,
                        // window 18 is never the best
                        0,
                        // window 19 is unbeaten in [4873049.17, 5706707.88]
                        4873049,
                        // window 20 is unbeaten in [5706707.88, 31673814.95]
                        5706708,
                        // window 21 is never the best
                        0,
                        // window 22 is unbeaten in [31673814.95, inf]
                        31673815};
                };

                /************************* ALT_BN128-254 definitions ***********************************/

                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename alt_bn128<254>::g1_type>::fixed_base_exp_window_table;
                constexpr std::array<std::size_t, 22> const
                    multiexp_params<typename alt_bn128<254>::g2_type>::fixed_base_exp_window_table;

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_ALT_BN128_MULTIEXP_PARAMS_HPP
