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

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_WNAF_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_WNAF_PARAMS_HPP

#include <nil/crypto3/algebra/curves/params.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<typename GroupType>
                struct wnaf_params;

                /************************* BLS12-381 ***********************************/

                template<>
                struct wnaf_params<typename bls12<381>::g1_type> {

                    constexpr static const std::array<std::size_t, 4> wnaf_window_table = {11, 24, 60, 127};
                };

                template<>
                struct wnaf_params<typename bls12<381>::g2_type> {

                    constexpr static const std::array<std::size_t, 4> wnaf_window_table = {5, 15, 39, 109};
                };

                /************************* BLS12-377 ***********************************/

                template<>
                struct wnaf_params<typename bls12<377>::g1_type> {

                    constexpr static const std::array<std::size_t, 4> wnaf_window_table = {11, 24, 60, 127};
                };

                template<>
                struct wnaf_params<typename bls12<377>::g2_type> {

                    constexpr static const std::array<std::size_t, 4> wnaf_window_table = {5, 15, 39, 109};
                };

                /************************* BLS12-381 definitions ***********************************/

                constexpr std::array<std::size_t, 4> const wnaf_params<typename bls12<381>::g1_type>::wnaf_window_table;
                constexpr std::array<std::size_t, 4> const wnaf_params<typename bls12<381>::g2_type>::wnaf_window_table;

                /************************* BLS12-377 definitions ***********************************/

                constexpr std::array<std::size_t, 4> const wnaf_params<typename bls12<377>::g1_type>::wnaf_window_table;
                constexpr std::array<std::size_t, 4> const wnaf_params<typename bls12<377>::g2_type>::wnaf_window_table;

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BLS12_WNAF_PARAMS_HPP
