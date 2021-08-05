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

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT4_298_PAIRING_PARAMS_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT4_298_PAIRING_PARAMS_HPP

#include <nil/crypto3/algebra/curves/mnt4.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class pairing_params;

                    template<>
                    class pairing_params<curves::mnt4<298>> {
                        using curve_type = curves::mnt4<298>;

                    public:
                        using integral_type = typename curve_type::base_field_type::integral_type;
                        using extended_integral_type = typename curve_type::base_field_type::extended_integral_type;

                        constexpr static const std::size_t integral_type_max_bits =
                            curve_type::base_field_type::modulus_bits;

                        constexpr static const integral_type ate_loop_count =
                            0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149;
                        constexpr static const bool ate_is_loop_count_neg = false;
                        constexpr static const extended_integral_type final_exponent = extended_integral_type(
                            0x343C7AC3174C87A1EFE216B37AFB6D3035ACCA5A07B2394F42E0029264C0324A95E87DCB6C97234CBA7385B8D20FEA4E85074066818687634E61F58B68EA590B11CEE431BE8348DEB351384D8485E987A57004BB9A1E7A6036C7A5801F55AC8E065E41B012422619E7E69541C5980000_cppui894);

                        constexpr static const integral_type final_exponent_last_chunk_abs_of_w0 =
                            0x1EEF5546609756BEC2A33F0DC9A1B671660001_cppui149;
                        constexpr static const bool final_exponent_last_chunk_is_w0_neg = false;
                        constexpr static const integral_type final_exponent_last_chunk_w1 = integral_type(0x1);

                        using g2_field_type_value = typename curve_type::template g2_type<>::field_type::value_type;

                        constexpr static const g2_field_type_value twist =
                            g2_field_type_value(g2_field_type_value::underlying_type::zero(),
                                                g2_field_type_value::underlying_type::one());

                        constexpr static const g2_field_type_value twist_coeff_a =
                            curve_type::template g2_type<>::params_type::a;
                        constexpr static const g2_field_type_value twist_coeff_b =
                            curve_type::template g2_type<>::params_type::b;
                    };

                    constexpr typename pairing_params<curves::mnt4<298>>::integral_type const
                        pairing_params<curves::mnt4<298>>::ate_loop_count;
                    constexpr typename pairing_params<curves::mnt4<298>>::integral_type const
                        pairing_params<curves::mnt4<298>>::final_exponent_last_chunk_abs_of_w0;
                    constexpr typename pairing_params<curves::mnt4<298>>::integral_type const
                        pairing_params<curves::mnt4<298>>::final_exponent_last_chunk_w1;
                    constexpr typename pairing_params<curves::mnt4<298>>::extended_integral_type const
                        pairing_params<curves::mnt4<298>>::final_exponent;

                    constexpr typename pairing_params<curves::mnt4<298>>::g2_field_type_value const
                        pairing_params<curves::mnt4<298>>::twist;
                    constexpr typename pairing_params<curves::mnt4<298>>::g2_field_type_value const
                        pairing_params<curves::mnt4<298>>::twist_coeff_a;
                    constexpr typename pairing_params<curves::mnt4<298>>::g2_field_type_value const
                        pairing_params<curves::mnt4<298>>::twist_coeff_b;

                    constexpr bool const pairing_params<curves::mnt4<298>>::ate_is_loop_count_neg;
                    constexpr bool const pairing_params<curves::mnt4<298>>::final_exponent_last_chunk_is_w0_neg;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_MNT4_298_PAIRING_PARAMS_HPP
