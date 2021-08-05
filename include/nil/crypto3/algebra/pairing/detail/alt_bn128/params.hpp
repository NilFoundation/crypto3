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

#ifndef CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_PAIRING_PARAMS_HPP
#define CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_PAIRING_PARAMS_HPP

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    template<typename CurveType>
                    class pairing_params;

                    template<>
                    class pairing_params<curves::alt_bn128<254>> {
                        using curve_type = curves::alt_bn128<254>;

                    public:
                        using integral_type = typename curve_type::base_field_type::integral_type;
                        using extended_integral_type = typename curve_type::base_field_type::extended_integral_type;

                        constexpr static const std::size_t integral_type_max_bits =
                            curve_type::base_field_type::modulus_bits;

                        constexpr static const integral_type ate_loop_count = 0x19D797039BE763BA8_cppui254;
                        constexpr static const bool ate_is_loop_count_neg = false;
                        constexpr static const extended_integral_type final_exponent = extended_integral_type(
                            0x2F4B6DC97020FDDADF107D20BC842D43BF6369B1FF6A1C71015F3F7BE2E1E30A73BB94FEC0DAF15466B2383A5D3EC3D15AD524D8F70C54EFEE1BD8C3B21377E563A09A1B705887E72ECEADDEA3790364A61F676BAAF977870E88D5C6C8FEF0781361E443AE77F5B63A2A2264487F2940A8B1DDB3D15062CD0FB2015DFC6668449AED3CC48A82D0D602D268C7DAAB6A41294C0CC4EBE5664568DFC50E1648A45A4A1E3A5195846A3ED011A337A02088EC80E0EBAE8755CFE107ACF3AAFB40494E406F804216BB10CF430B0F37856B42DB8DC5514724EE93DFB10826F0DD4A0364B9580291D2CD65664814FDE37CA80BB4EA44EACC5E641BBADF423F9A2CBF813B8D145DA90029BAEE7DDADDA71C7F3811C4105262945BBA1668C3BE69A3C230974D83561841D766F9C9D570BB7FBE04C7E8A6C3C760C0DE81DEF35692DA361102B6B9B2B918837FA97896E84ABB40A4EFB7E54523A486964B64CA86F120_cppui2790);

                        constexpr static const integral_type final_exponent_z = integral_type(0x44E992B44A6909F1);
                        constexpr static const integral_type final_exponent_is_z_neg = false;

                        using g2_field_type_value = typename curve_type::g2_type::field_type::value_type;

                        constexpr static const g2_field_type_value twist = g2_type::params_type::twist;
                    };

                    constexpr typename pairing_params<curves::alt_bn128<254>>::integral_type const
                        pairing_params<curves::alt_bn128<254>>::ate_loop_count;

                    constexpr typename pairing_params<curves::alt_bn128<254>>::integral_type const
                        pairing_params<curves::alt_bn128<254>>::final_exponent_z;

                    constexpr typename pairing_params<curves::alt_bn128<254>>::extended_integral_type const
                        pairing_params<curves::alt_bn128<254>>::final_exponent;

                    constexpr bool const pairing_params<curves::alt_bn128<254>>::ate_is_loop_count_neg;
                    constexpr bool const pairing_params<curves::alt_bn128<254>>::final_exponent_is_z_neg;

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_PAIRING_PARAMS_HPP
