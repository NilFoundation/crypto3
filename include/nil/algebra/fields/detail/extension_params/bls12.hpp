//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BLS12_EXTENSION_PARAMS_HPP
#define ALGEBRA_FIELDS_BLS12_EXTENSION_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/element/fp6_3over2.hpp>

#include <nil/algebra/fields/params.hpp>
#include <nil/algebra/fields/bls12/base_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                using namespace nil::algebra;

                template<typename FieldType>
                struct fp2_extension_params;

                template<typename FieldType>
                struct fp6_3over2_extension_params;

                template<typename FieldType>
                struct fp12_2over3over2_extension_params;
                
                /************************* BLS12-381 ***********************************/

                template<>
                class fp2_extension_params<fields::bls12<381, CHAR_BIT>>
                    : public params<fields::bls12<381, CHAR_BIT>> {

                    typedef params<fields::bls12<381, CHAR_BIT>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;
                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp<policy_type> non_residue_type;
                    typedef element_fp<policy_type> underlying_type;

                    constexpr static const std::size_t s = 0x03;
                    constexpr static const extended_modulus_type t =
                        0x5486F497186BF8E97A4F1D5445E4BD3C5B921CA1CE08D68CDCB3C92693D17A0A14C59FA2DBB94DDEA62926612F1DE023AD0C3390C30B8F6525D0B50E1234092CD7F23DA7CE36E862C586706C42279FAF9DAD63AEC705D564D54000038E31C7_cppui759;
                    constexpr static const extended_modulus_type t_minus_1_over_2 =
                        0x2A437A4B8C35FC74BD278EAA22F25E9E2DC90E50E7046B466E59E49349E8BD050A62CFD16DDCA6EF53149330978EF011D68619C86185C7B292E85A87091A04966BF91ED3E71B743162C338362113CFD7CED6B1D76382EAB26AA00001C718E3_cppui758;
                    constexpr static const std::array<modulus_type, 2> nqr = {0x01, 0x01};
                    constexpr static const std::array<modulus_type, 2> nqr_to_t = 
                        {0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09_cppui379,
                         0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2_cppui381};

                    constexpr static const std::array<underlying_type, 2> Frobenius_coeffs_c1 = {underlying_type(0x01),
                        underlying_type(0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381)};

                    constexpr static const modulus_type non_residue = modulus_type(
                        0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381);
                };

                template<>
                class fp6_3over2_extension_params<fields::bls12<381, CHAR_BIT>>
                    : public params<fields::bls12<381, CHAR_BIT>> {

                    typedef fields::bls12<381, CHAR_BIT> field_type;
                    typedef params<field_type> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp2<field_type> non_residue_type;
                    typedef element_fp2<fp2_extension_params<field_type>> underlying_type;

                    constexpr static const std::array<underlying_type, 6> Frobenius_coeffs_c1 = {underlying_type(0x01, 0x00),
                        underlying_type(0x00, 0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381),
                        underlying_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319, 0x00),
                        underlying_type(0x00, 0x01),
                        underlying_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381, 0x00),
                        underlying_type(0x00, 0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319)};

                    constexpr static const std::array<underlying_type, 6> Frobenius_coeffs_c1 = {underlying_type(0x01, 0x00),
                        underlying_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAD_cppui381, 0x00),
                        underlying_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381, 0x00),
                        underlying_type(0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381, 0x00),
                        underlying_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319, 0x00),
                        underlying_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFF_cppui319, 0x00)};

                    constexpr static const std::array<modulus_type, 2> non_residue = {1, 1};
                };

                template<>
                class fp12_2over3over2_extension_params<fields::bls12<381, CHAR_BIT>>
                    : public params<fields::bls12<381, CHAR_BIT>> {

                    typedef fields::bls12<381, CHAR_BIT> field_type;
                    typedef params<field_type> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp2<field_type> non_residue_type;
                    typedef element_fp6_3over2<fp6_3over2_extension_params<field_type>> underlying_type;

                    constexpr static const std::array<underlying_type, 12> Frobenius_coeffs_c1 = {underlying_type(0x01, 0x00),
                        underlying_type(0x1904D3BF02BB0667C231BEB4202C0D1F0FD603FD3CBD5F4F7B2443D784BAB9C4F67EA53D63E7813D8D0775ED92235FB8_cppui381, 0xFC3E2B36C4E03288E9E902231F9FB854A14787B6C7B36FEC0C8EC971F63C5F282D5AC14D6C7EC22CF78A126DDC4AF3_cppui376),
                        underlying_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFF_cppui319, 0x00),
                        underlying_type(0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2_cppui381, 0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09_cppui379),
                        underlying_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319, 0x00),
                        underlying_type(0x144E4211384586C16BD3AD4AFA99CC9170DF3560E77982D0DB45F3536814F0BD5871C1908BD478CD1EE605167FF82995_cppui381, 0x5B2CFD9013A5FD8DF47FA6B48B1E045F39816240C0B8FEE8BEADF4D8E9C0566C63A3E6E257F87329B18FAE980078116_cppui379),

                        underlying_type(0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381, 0x00),
                        underlying_type(0xFC3E2B36C4E03288E9E902231F9FB854A14787B6C7B36FEC0C8EC971F63C5F282D5AC14D6C7EC22CF78A126DDC4AF3_cppui376, 0x1904D3BF02BB0667C231BEB4202C0D1F0FD603FD3CBD5F4F7B2443D784BAB9C4F67EA53D63E7813D8D0775ED92235FB8_cppui381),
                        underlying_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381, 0x00),
                        underlying_type(0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09_cppui379, 0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2_cppui381),
                        underlying_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAD_cppui381, 0x00),
                        underlying_type(0x5B2CFD9013A5FD8DF47FA6B48B1E045F39816240C0B8FEE8BEADF4D8E9C0566C63A3E6E257F87329B18FAE980078116_cppui379, 0x144E4211384586C16BD3AD4AFA99CC9170DF3560E77982D0DB45F3536814F0BD5871C1908BD478CD1EE605167FF82995_cppui381)};

                    constexpr static const std::array<modulus_type, 2> non_residue = {1, 1};
                };

                /************************* BLS12-377 ***********************************/

                template<>
                class fp2_extension_params<fields::bls12<377, CHAR_BIT>>
                    : public params<fields::bls12<377, CHAR_BIT>> {

                    typedef params<fields::bls12<377, CHAR_BIT>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;
                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    constexpr static const std::size_t s = 0x2F;
                constexpr static const extended_modulus_type t =
                    0x5A60FA1775FF644AD227766C24C78977170FB495DD27E3EBCE2827BB49AB813A0315F720CC19B8029CE24A0549AD88C155555176E15C063064972B0C7193AD797F7A46BE3813495B44D1E5C37B000E671A4A9E00000021423_cppui707;
                constexpr static const extended_modulus_type t_minus_1_over_2 =
                    0x2D307D0BBAFFB2256913BB361263C4BB8B87DA4AEE93F1F5E71413DDA4D5C09D018AFB90660CDC014E712502A4D6C460AAAAA8BB70AE0318324B958638C9D6BCBFBD235F1C09A4ADA268F2E1BD8007338D254F00000010A11_cppui706;
                constexpr static const std::array<modulus_type, 2> nqr = {0x00, 0x01};
                constexpr static const std::array<modulus_type, 2> nqr_to_t = 
                    {0x00, 0x1ABEF7237D62007BB9B2EDA5AFCB52F9D179F23DBD49B8D1B24CF7C1BF8066791317689172D0F4CB90CF47182B7D7B2_cppui377};

                    typedef element_fp<policy_type> non_residue_type;
                    typedef element_fp<policy_type> underlying_type;

                    constexpr static const std::array<underlying_type, 2> Frobenius_coeffs_c1 = {underlying_type(0x01),
                        underlying_type(0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000000_cppui377)};

                    constexpr static const modulus_type non_residue = modulus_type(
                        0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508BFFFFFFFFFFC_cppui377);
                };

                template<>
                class fp6_3over2_extension_params<fields::bls12<377, CHAR_BIT>>
                    : public params<fields::bls12<377, CHAR_BIT>> {

                    typedef fields::bls12<377, CHAR_BIT> field_type;
                    typedef params<field_type> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp2<field_type> non_residue_type;
                    typedef element_fp2<fp2_extension_params<field_type>> underlying_type;

                    constexpr static const std::array<underlying_type, 6> Frobenius_coeffs_c1 = {underlying_type(0x01, 0x00),
                        underlying_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000002_cppui316, 0x00),
                        underlying_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316, 0x00),
                        underlying_type(0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000000_cppui377, 0x00),
                        underlying_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377, 0x00),
                        underlying_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E94577A00000000000000000000000_cppui377, 0x00)};

                    constexpr static const std::array<underlying_type, 6> Frobenius_coeffs_c1 = {underlying_type(0x01, 0x00),
                        underlying_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316, 0x00),
                        underlying_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377, 0x00),
                        underlying_type(0x01, 0x00),
                        underlying_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316, 0x00),
                        underlying_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377, 0x00)};

                    constexpr static const std::array<modulus_type, 2> non_residue = {0, 1};
                };

                template<>
                class fp12_2over3over2_extension_params<fields::bls12<377, CHAR_BIT>>
                    : public params<fields::bls12<377, CHAR_BIT>> {

                    typedef fields::bls12<377, CHAR_BIT> field_type;
                    typedef params<field_type> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp2<field_type> non_residue_type;
                    typedef element_fp6_3over2<fp6_3over2_extension_params<field_type>> underlying_type;

                    constexpr static const std::array<underlying_type, 12> Frobenius_coeffs_c1 = {underlying_type(0x01, 0x00),
                        underlying_type(0x9A9975399C019633C1E30682567F915C8A45E0F94EBC8EC681BF34A3AA559DB57668E558EB0188E938A9D1104F2031_cppui376, 0x00),
                        underlying_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000002_cppui316, 0x00),
                        underlying_type(0x1680A40796537CAC0C534DB1A79BEB1400398F50AD1DEC1BCE649CF436B0F6299588459BFF27D8E6E76D5ECF1391C63_cppui377, 0x00),
                        underlying_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316, 0x00),
                        underlying_type(0xCD70CB3FC936348D0351D498233F1FE379531411832232F6648A9A9FC0B9C4E3E21B7467077C05853E2C1BE0E9FC32_cppui376, 0x00),

                        underlying_type(0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000000_cppui377, 0x00),
                        underlying_type(0x165715080792691229252027773188420350858440463845631411558924158284924566418821255823372982649037525009328560463824_cppui377, 0x00),
                        underlying_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377, 0x00),
                        underlying_type(0x4630059E5FD9200575D0E552278A89DA1F40FDF62334CD620D1860769E389D7DB2D8EA700D82721691EA130EC6E39E_cppui375, 0x00),
                        underlying_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E94577A00000000000000000000000_cppui377, 0x00),
                        underlying_type(0xE0C97AD7FBDAB63937B3EBD47E0A1B36A986DEEF71F15C288ED7951A488E3B332941CFC8F883FAFFCA93E41F1603CF_cppui376, 0x00)};

                    constexpr static const std::array<modulus_type, 2> non_residue = {0, 1};
                };

                constexpr typename fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::modulus_type const
                    fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::non_residue;
                constexpr typename fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::modulus_type const
                    fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::non_residue;

                constexpr typename std::size_t const
                    fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::s;
                constexpr typename std::size_t const
                    fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::s;

                constexpr typename fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::extended_modulus_type const
                    fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::t;
                constexpr typename fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::extended_modulus_type const
                    fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::t;

                constexpr typename fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::extended_modulus_type const
                    fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::t_minus_1_over_2;
                constexpr typename fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::extended_modulus_type const
                    fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::t_minus_1_over_2;

                constexpr std::array<typename fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::modulus_type, 2> const
                    fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::nqr;
                constexpr std::array<typename fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::modulus_type, 2> const
                    fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::nqr;

                constexpr std::array<typename fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::modulus_type, 2> const
                    fp2_extension_params<bls12_base_field<381, CHAR_BIT>>::nqr_to_t;
                constexpr std::array<typename fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::modulus_type, 2> const
                    fp2_extension_params<bls12_base_field<377, CHAR_BIT>>::nqr_to_t;

                constexpr std::array<typename fp6_3over2_extension_params<bls12_base_field<381, CHAR_BIT>>::modulus_type, 2> const
                    fp6_3over2_extension_params<bls12_base_field<381, CHAR_BIT>>::non_residue;
                constexpr std::array<typename fp6_3over2_extension_params<bls12_base_field<377, CHAR_BIT>>::modulus_type, 2> const
                    fp6_3over2_extension_params<bls12_base_field<377, CHAR_BIT>>::non_residue;

                constexpr std::array<typename fp12_2over3over2_extension_params<bls12_base_field<381, CHAR_BIT>>::modulus_type, 2> const
                    fp12_2over3over2_extension_params<bls12_base_field<381, CHAR_BIT>>::non_residue;
                constexpr std::array<typename fp12_2over3over2_extension_params<bls12_base_field<377, CHAR_BIT>>::modulus_type, 2> const
                    fp12_2over3over2_extension_params<bls12_base_field<377, CHAR_BIT>>::non_residue;

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BLS12_EXTENSION_PARAMS_HPP
