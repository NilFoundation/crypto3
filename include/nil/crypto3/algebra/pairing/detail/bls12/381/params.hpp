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

#ifndef CRYPTO3_ALGEBRA_PAIRING_BLS12_381_BASIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_PAIRING_BLS12_381_BASIC_PARAMS_HPP

#include <nil/crypto3/algebra/curves/bls12.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class pairing_params;

                    template<>
                    class pairing_params<curves::bls12<381>> {
                        using curve_type = curves::bls12<381>;

                    public:
                        using integral_type = typename curve_type::base_field_type::integral_type;
                        using extended_integral_type = typename curve_type::base_field_type::extended_integral_type;

                        constexpr static const std::size_t integral_type_max_bits =
                            curve_type::base_field_type::modulus_bits;

                        constexpr static const integral_type ate_loop_count = 0xD201000000010000_cppui64;
                        constexpr static const bool ate_is_loop_count_neg = true;
                        // constexpr static const extended_integral_type final_exponent = extended_integral_type(
                        //    0x2EE1DB5DCC825B7E1BDA9C0496A1C0A89EE0193D4977B3F7D4507D07363BAA13F8D14A917848517BADC3A43D1073776AB353F2C30698E8CC7DEADA9C0AADFF5E9CFEE9A074E43B9A660835CC872EE83FF3A0F0F1C0AD0D6106FEAF4E347AA68AD49466FA927E7BB9375331807A0DCE2630D9AA4B113F414386B0E8819328148978E2B0DD39099B86E1AB656D2670D93E4D7ACDD350DA5359BC73AB61A0C5BF24C374693C49F570BCD2B01F3077FFB10BF24DDE41064837F27611212596BC293C8D4C01F25118790F4684D0B9C40A68EB74BB22A40EE7169CDC1041296532FEF459F12438DFC8E2886EF965E61A474C5C85B0129127A1B5AD0463434724538411D1676A53B5A62EB34C05739334F46C02C3F0BD0C55D3109CD15948D0A1FAD20044CE6AD4C6BEC3EC03EF19592004CEDD556952C6D8823B19DADD7C2498345C6E5308F1C511291097DB60B1749BF9B71A9F9E0100418A3EF0BC627751BBD81367066BCA6A4C1B6DCFC5CCEB73FC56947A403577DFA9E13C24EA820B09C1D9F7C31759C3635DE3F7A3639991708E88ADCE88177456C49637FD7961BE1A4C7E79FB02FAA732E2F3EC2BEA83D196283313492CAA9D4AFF1C910E9622D2A73F62537F2701AAEF6539314043F7BBCE5B78C7869AEB2181A67E49EEED2161DAF3F881BD88592D767F67C4717489119226C2F011D4CAB803E9D71650A6F80698E2F8491D12191A04406FBC8FBD5F48925F98630E68BFB24C0BCB9B55DF57510_cppui4314);

                        constexpr static const integral_type final_exponent_z = 0xD201000000010000_cppui64;
                        constexpr static const bool final_exponent_is_z_neg = true;

                        using g2_field_type_value = typename curve_type::template g2_type<>::field_type::value_type;

                        constexpr static const g2_field_type_value twist =
                            curve_type::template g2_type<>::params_type::twist;

                        constexpr static const g2_field_type_value twist_coeff_b =
                            curve_type::template g2_type<>::params_type::b;
                    };

                    constexpr typename pairing_params<curves::bls12<381>>::integral_type const
                        pairing_params<curves::bls12<381>>::ate_loop_count;

                    constexpr typename pairing_params<curves::bls12<381>>::integral_type const
                        pairing_params<curves::bls12<381>>::final_exponent_z;
                    constexpr typename pairing_params<curves::bls12<381>>::g2_field_type_value const
                        pairing_params<curves::bls12<381>>::twist;
                    constexpr typename pairing_params<curves::bls12<381>>::g2_field_type_value const
                        pairing_params<curves::bls12<381>>::twist_coeff_b;

                    constexpr bool const pairing_params<curves::bls12<381>>::final_exponent_is_z_neg;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_BLS12_381_BASIC_PARAMS_HPP
