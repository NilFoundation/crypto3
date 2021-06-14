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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BLS12_FP12_2OVER2OVER2_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BLS12_FP12_2OVER2OVER2_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<typename BaseField>
                    struct fp12_2over3over2_extension_params;

                    /************************* BLS12-381 ***********************************/

                    template<>
                    class fp12_2over3over2_extension_params<fields::bls12<381>> : public params<fields::bls12<381>> {

                        typedef fields::bls12<381> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef fields::fp2<base_field_type> non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef fields::fp6_3over2<base_field_type> underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;
                        // typedef element_fp6_3over2<fp6_3over2_extension_params<field_type>> underlying_type;

                        /*constexpr static const std::array<non_residue_type, 12> Frobenius_coeffs_c1 =
                           {non_residue_type(0x01, 0x00),
                            non_residue_type(0x1904D3BF02BB0667C231BEB4202C0D1F0FD603FD3CBD5F4F7B2443D784BAB9C4F67EA53D63E7813D8D0775ED92235FB8_cppui381,
                           0xFC3E2B36C4E03288E9E902231F9FB854A14787B6C7B36FEC0C8EC971F63C5F282D5AC14D6C7EC22CF78A126DDC4AF3_cppui376),
                            non_residue_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFF_cppui319,
                           0x00),
                            non_residue_type(0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2_cppui381,
                           0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09_cppui379),
                            non_residue_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319,
                           0x00),
                            non_residue_type(0x144E4211384586C16BD3AD4AFA99CC9170DF3560E77982D0DB45F3536814F0BD5871C1908BD478CD1EE605167FF82995_cppui381,
                           0x5B2CFD9013A5FD8DF47FA6B48B1E045F39816240C0B8FEE8BEADF4D8E9C0566C63A3E6E257F87329B18FAE980078116_cppui379),

                            non_residue_type(0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381,
                           0x00),
                            non_residue_type(0xFC3E2B36C4E03288E9E902231F9FB854A14787B6C7B36FEC0C8EC971F63C5F282D5AC14D6C7EC22CF78A126DDC4AF3_cppui376,
                           0x1904D3BF02BB0667C231BEB4202C0D1F0FD603FD3CBD5F4F7B2443D784BAB9C4F67EA53D63E7813D8D0775ED92235FB8_cppui381),
                            non_residue_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381,
                           0x00),
                            non_residue_type(0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09_cppui379,
                           0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2_cppui381),
                            non_residue_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAD_cppui381,
                           0x00),
                            non_residue_type(0x5B2CFD9013A5FD8DF47FA6B48B1E045F39816240C0B8FEE8BEADF4D8E9C0566C63A3E6E257F87329B18FAE980078116_cppui379,
                           0x144E4211384586C16BD3AD4AFA99CC9170DF3560E77982D0DB45F3536814F0BD5871C1908BD478CD1EE605167FF82995_cppui381)};*/

                        constexpr static const std::array<modulus_type, 12 * 2> Frobenius_coeffs_c1 = {
                            0x01,
                            0x00,
                            0x1904D3BF02BB0667C231BEB4202C0D1F0FD603FD3CBD5F4F7B2443D784BAB9C4F67EA53D63E7813D8D0775ED92235FB8_cppui381,
                            0xFC3E2B36C4E03288E9E902231F9FB854A14787B6C7B36FEC0C8EC971F63C5F282D5AC14D6C7EC22CF78A126DDC4AF3_cppui376,
                            0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFF_cppui319,
                            0x00,
                            0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2_cppui381,
                            0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09_cppui379,
                            0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319,
                            0x00,
                            0x144E4211384586C16BD3AD4AFA99CC9170DF3560E77982D0DB45F3536814F0BD5871C1908BD478CD1EE605167FF82995_cppui381,
                            0x5B2CFD9013A5FD8DF47FA6B48B1E045F39816240C0B8FEE8BEADF4D8E9C0566C63A3E6E257F87329B18FAE980078116_cppui379,

                            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381,
                            0x00,
                            0xFC3E2B36C4E03288E9E902231F9FB854A14787B6C7B36FEC0C8EC971F63C5F282D5AC14D6C7EC22CF78A126DDC4AF3_cppui376,
                            0x1904D3BF02BB0667C231BEB4202C0D1F0FD603FD3CBD5F4F7B2443D784BAB9C4F67EA53D63E7813D8D0775ED92235FB8_cppui381,
                            0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381,
                            0x00,
                            0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09_cppui379,
                            0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2_cppui381,
                            0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAD_cppui381,
                            0x00,
                            0x5B2CFD9013A5FD8DF47FA6B48B1E045F39816240C0B8FEE8BEADF4D8E9C0566C63A3E6E257F87329B18FAE980078116_cppui379,
                            0x144E4211384586C16BD3AD4AFA99CC9170DF3560E77982D0DB45F3536814F0BD5871C1908BD478CD1EE605167FF82995_cppui381};

                        constexpr static const non_residue_type non_residue = non_residue_type(0x01, 0x01);
                    };

                    /************************* BLS12-377 ***********************************/

                    template<>
                    class fp12_2over3over2_extension_params<fields::bls12<377>> : public params<fields::bls12<377>> {

                        typedef fields::bls12<377> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef fields::fp2<base_field_type> non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef fields::fp6_3over2<base_field_type> underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;

                        /*constexpr static const std::array<non_residue_type, 12> Frobenius_coeffs_c1 =
                           {non_residue_type(0x01, 0x00),
                            non_residue_type(0x9A9975399C019633C1E30682567F915C8A45E0F94EBC8EC681BF34A3AA559DB57668E558EB0188E938A9D1104F2031_cppui376,
                           0x00),
                            non_residue_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000002_cppui316,
                           0x00),
                            non_residue_type(0x1680A40796537CAC0C534DB1A79BEB1400398F50AD1DEC1BCE649CF436B0F6299588459BFF27D8E6E76D5ECF1391C63_cppui377,
                           0x00),
                            non_residue_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316,
                           0x00),
                            non_residue_type(0xCD70CB3FC936348D0351D498233F1FE379531411832232F6648A9A9FC0B9C4E3E21B7467077C05853E2C1BE0E9FC32_cppui376,
                           0x00),

                            non_residue_type(0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000000_cppui377,
                           0x00),
                            non_residue_type(0x113A0D0DE290F54927922B9EA4AC9A9BD98941207A657005871A2FB165EF2626194F45ED714FE779BD0162EEFB0DFD0_cppui377,
                           0x00),
                            non_residue_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377,
                           0x00),
                            non_residue_type(0x4630059E5FD9200575D0E552278A89DA1F40FDF62334CD620D1860769E389D7DB2D8EA700D82721691EA130EC6E39E_cppui375,
                           0x00),
                            non_residue_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E94577A00000000000000000000000_cppui377,
                           0x00),
                            non_residue_type(0xE0C97AD7FBDAB63937B3EBD47E0A1B36A986DEEF71F15C288ED7951A488E3B332941CFC8F883FAFFCA93E41F1603CF_cppui376,
                           0x00)};*/

                        constexpr static const std::array<modulus_type, 12 * 2> Frobenius_coeffs_c1 = {
                            0x01,
                            0x00,
                            0x9A9975399C019633C1E30682567F915C8A45E0F94EBC8EC681BF34A3AA559DB57668E558EB0188E938A9D1104F2031_cppui376,
                            0x00,
                            0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000002_cppui316,
                            0x00,
                            0x1680A40796537CAC0C534DB1A79BEB1400398F50AD1DEC1BCE649CF436B0F6299588459BFF27D8E6E76D5ECF1391C63_cppui377,
                            0x00,
                            0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316,
                            0x00,
                            0xCD70CB3FC936348D0351D498233F1FE379531411832232F6648A9A9FC0B9C4E3E21B7467077C05853E2C1BE0E9FC32_cppui376,
                            0x00,

                            0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000000_cppui377,
                            0x00,
                            0x113A0D0DE290F54927922B9EA4AC9A9BD98941207A657005871A2FB165EF2626194F45ED714FE779BD0162EEFB0DFD0_cppui377,
                            0x00,
                            0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377,
                            0x00,
                            0x4630059E5FD9200575D0E552278A89DA1F40FDF62334CD620D1860769E389D7DB2D8EA700D82721691EA130EC6E39E_cppui375,
                            0x00,
                            0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E94577A00000000000000000000000_cppui377,
                            0x00,
                            0xE0C97AD7FBDAB63937B3EBD47E0A1B36A986DEEF71F15C288ED7951A488E3B332941CFC8F883FAFFCA93E41F1603CF_cppui376,
                            0x00};

                        constexpr static const non_residue_type non_residue = non_residue_type(0x00, 0x01);
                    };

                    constexpr 
                        typename fp12_2over3over2_extension_params<bls12_base_field<381>>::non_residue_type const
                        fp12_2over3over2_extension_params<bls12_base_field<381>>::non_residue;
                    constexpr 
                        typename fp12_2over3over2_extension_params<bls12_base_field<377>>::non_residue_type const
                        fp12_2over3over2_extension_params<bls12_base_field<377>>::non_residue;

                    constexpr std::array<
                        typename fp12_2over3over2_extension_params<bls12_base_field<381>>::modulus_type, 12 * 2> const
                        fp12_2over3over2_extension_params<bls12_base_field<381>>::Frobenius_coeffs_c1;
                    constexpr std::array<
                        typename fp12_2over3over2_extension_params<bls12_base_field<377>>::modulus_type, 12 * 2> const
                        fp12_2over3over2_extension_params<bls12_base_field<377>>::Frobenius_coeffs_c1;
                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BLS12_FP12_2OVER2OVER2_EXTENSION_PARAMS_HPP
