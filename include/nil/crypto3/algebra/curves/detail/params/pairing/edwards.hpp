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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_PAIRING_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_PAIRING_PARAMS_HPP

#include <nil/crypto3/algebra/curves/edwards.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<std::size_t Version>
                struct edwards;

                namespace detail {

                    template<typename CurveType>
                    struct pairing_params;

                    /************************* EDWARDS-183 ***********************************/

                    template<>
                    struct pairing_params<edwards<183>> {

                        using policy_type = edwards_basic_policy<183>;

                        using g1_field_type_value = typename policy_type::g1_field_type::value_type;
                        using g2_field_type_value = typename policy_type::g2_field_type::value_type;

                        constexpr static const g2_field_type_value twist = g2_field_type_value(
                            {g2_field_type_value::underlying_type::zero(), g2_field_type_value::underlying_type::one(),
                             g2_field_type_value::underlying_type::zero()});

                        constexpr static const g2_field_type_value twist_coeff_a = a * twist;
                        constexpr static const g2_field_type_value twist_coeff_d = d * twist;

                        constexpr static const g1_field_type_value twist_mul_by_a_c0;
                        constexpr static const g1_field_type_value twist_mul_by_a_c1 = a;
                        constexpr static const g1_field_type_value twist_mul_by_a_c2 = a;
                        constexpr static const g1_field_type_value twist_mul_by_d_c0;
                        constexpr static const g1_field_type_value twist_mul_by_d_c1 = d;
                        constexpr static const g1_field_type_value twist_mul_by_d_c2 = d;
                        constexpr static const g1_field_type_value twist_mul_by_q_Y =
                            g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);
                        constexpr static const g1_field_type_value twist_mul_by_q_Z =
                            g1_field_type_value(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180);
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_PAIRING_PARAMS_HPP
