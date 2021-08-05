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

#ifndef CRYPTO3_ALGEBRA_PAIRING_MNT6_298_PAIRING_PARAMS_HPP
#define CRYPTO3_ALGEBRA_PAIRING_MNT6_298_PAIRING_PARAMS_HPP

#include <nil/crypto3/algebra/curves/mnt6.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class pairing_params;

                    template<>
                    class pairing_params<curves::mnt6<298>> {
                        using curve_type = curves::mnt6<298>;

                    public:
                        using integral_type = typename curve_type::base_field_type::integral_type;
                        using extended_integral_type = typename curve_type::base_field_type::extended_integral_type;

                        constexpr static const std::size_t integral_type_max_bits =
                            curve_type::base_field_type::modulus_bits;

                        constexpr static const integral_type ate_loop_count =
                            0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149;
                        constexpr static const bool ate_is_loop_count_neg = true;
                        constexpr static const extended_integral_type final_exponent = extended_integral_type(
                            0x2D9F068E10293574745C62CB0EE7CF1D27F98BA7E8F16BB1CB498038B1B0B4D7EA28C42575093726D5E360818F2DD5B39038CFF6405359561DD2F2F0627F9264724E069A7198C17873F7F54D8C7CE3D5DAED1AC5E87C26C03B1F481813BB668B6FEDC7C2AAA83936D8BC842F74C66E7A13921F7D91474B3981D3A3B3B40537720C84FE27E3E90BB29DB12DFFE17A286C150EF5071B3087765F9454046ECBDD3B014FF91A1C18D55DB868E841DBF82BCCEFB4233833BD800000000_cppui1490);

                        constexpr static const integral_type final_exponent_last_chunk_abs_of_w0 =
                            0x1EEF5546609756BEC2A33F0DC9A1B671660000_cppui149;    // same as ate_loop_count?
                        constexpr static const bool final_exponent_last_chunk_is_w0_neg = true;
                        constexpr static const integral_type final_exponent_last_chunk_w1 = integral_type(0x1);

                        using g2_field_type_value = typename curve_type::template g2_type<>::field_type::value_type;

                        constexpr static const g2_field_type_value twist =
                            g2_field_type_value(g2_field_type_value::underlying_type::zero(),
                                                g2_field_type_value::underlying_type::one(),
                                                g2_field_type_value::underlying_type::zero());

                        constexpr static const g2_field_type_value twist_coeff_a =
                            curve_type::template g2_type<>::params_type::a;
                        constexpr static const g2_field_type_value twist_coeff_b =
                            curve_type::template g2_type<>::params_type::b;
                    };

                    constexpr typename pairing_params<curves::mnt6<298>>::integral_type const
                        pairing_params<curves::mnt6<298>>::ate_loop_count;
                    constexpr typename pairing_params<curves::mnt6<298>>::integral_type const
                        pairing_params<curves::mnt6<298>>::final_exponent_last_chunk_abs_of_w0;
                    constexpr typename pairing_params<curves::mnt6<298>>::integral_type const
                        pairing_params<curves::mnt6<298>>::final_exponent_last_chunk_w1;
                    constexpr typename pairing_params<curves::mnt6<298>>::extended_integral_type const
                        pairing_params<curves::mnt6<298>>::final_exponent;

                    constexpr typename pairing_params<curves::mnt6<298>>::g2_field_type_value const
                        pairing_params<curves::mnt6<298>>::twist;
                    constexpr typename pairing_params<curves::mnt6<298>>::g2_field_type_value const
                        pairing_params<curves::mnt6<298>>::twist_coeff_a;
                    constexpr typename pairing_params<curves::mnt6<298>>::g2_field_type_value const
                        pairing_params<curves::mnt6<298>>::twist_coeff_b;

                    constexpr bool const pairing_params<curves::mnt6<298>>::ate_is_loop_count_neg;
                    constexpr bool const pairing_params<curves::mnt6<298>>::final_exponent_last_chunk_is_w0_neg;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_MNT6_298_PAIRING_PARAMS_HPP
