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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BLS12_FP2_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BLS12_FP2_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<typename BaseField>
                struct fp2;

                namespace detail {

                    template<typename BaseField>
                    struct fp2_extension_params;

                    /************************* BLS12-381 ***********************************/

                    template<>
                    class fp2_extension_params<fields::bls12<381>> : public params<fields::bls12<381>> {

                        typedef fields::bls12<381> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        using field_type = fields::fp2<base_field_type>;

                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;
                        typedef typename policy_type::extended_modulus_type extended_modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef base_field_type non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef base_field_type underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;

                        constexpr static const std::size_t s = 0x03;
                        constexpr static const extended_modulus_type t =
                            0x5486F497186BF8E97A4F1D5445E4BD3C5B921CA1CE08D68CDCB3C92693D17A0A14C59FA2DBB94DDEA62926612F1DE023AD0C3390C30B8F6525D0B50E1234092CD7F23DA7CE36E862C586706C42279FAF9DAD63AEC705D564D54000038E31C7_cppui759;
                        constexpr static const extended_modulus_type t_minus_1_over_2 =
                            0x2A437A4B8C35FC74BD278EAA22F25E9E2DC90E50E7046B466E59E49349E8BD050A62CFD16DDCA6EF53149330978EF011D68619C86185C7B292E85A87091A04966BF91ED3E71B743162C338362113CFD7CED6B1D76382EAB26AA00001C718E3_cppui758;
                        constexpr static const std::array<modulus_type, 2> nqr = {0x01, 0x01};
                        constexpr static const std::array<modulus_type, 2> nqr_to_t = {
                            0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09_cppui379,
                            0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2_cppui381};

                        constexpr static const extended_modulus_type group_order =
                            0x1521BD25C61AFE3A5E93C75511792F4F16E48728738235A3372CF249A4F45E82853167E8B6EE5377A98A49984BC77808EB430CE430C2E3D949742D43848D024B35FC8F69F38DBA18B1619C1B1089E7EBE76B58EBB1C1755935500000E38C71C_cppui761;

                        /*constexpr static const std::array<non_residue_type, 2> Frobenius_coeffs_c1 =
                           {non_residue_type(0x01),
                            non_residue_type(0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381)};*/

                        constexpr static const std::array<modulus_type, 2> Frobenius_coeffs_c1 = {
                            0x01,
                            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381};

                        constexpr static const non_residue_type non_residue = non_residue_type(
                            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381);
                    };

                    /************************* BLS12-377 ***********************************/

                    template<>
                    class fp2_extension_params<fields::bls12<377>> : public params<fields::bls12<377>> {

                        typedef fields::bls12<377> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        using field_type = fields::fp2<base_field_type>;

                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;
                        typedef typename policy_type::extended_modulus_type extended_modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef base_field_type non_residue_field_type;
                        typedef non_residue_field_type::value_type non_residue_type;
                        typedef base_field_type underlying_field_type;
                        typedef underlying_field_type::value_type underlying_type;

                        constexpr static const std::size_t s = 0x2F;
                        constexpr static const extended_modulus_type t =
                            0x5A60FA1775FF644AD227766C24C78977170FB495DD27E3EBCE2827BB49AB813A0315F720CC19B8029CE24A0549AD88C155555176E15C063064972B0C7193AD797F7A46BE3813495B44D1E5C37B000E671A4A9E00000021423_cppui707;
                        constexpr static const extended_modulus_type t_minus_1_over_2 =
                            0x2D307D0BBAFFB2256913BB361263C4BB8B87DA4AEE93F1F5E71413DDA4D5C09D018AFB90660CDC014E712502A4D6C460AAAAA8BB70AE0318324B958638C9D6BCBFBD235F1C09A4ADA268F2E1BD8007338D254F00000010A11_cppui706;
                        constexpr static const std::array<modulus_type, 2> nqr = {0x00, 0x01};
                        constexpr static const std::array<modulus_type, 2> nqr_to_t = {
                            0x00,
                            0x1ABEF7237D62007BB9B2EDA5AFCB52F9D179F23DBD49B8D1B24CF7C1BF8066791317689172D0F4CB90CF47182B7D7B2_cppui377};

                        constexpr static const extended_modulus_type group_order =
                            0x16983E85DD7FD912B489DD9B0931E25DC5C3ED257749F8FAF38A09EED26AE04E80C57DC833066E00A7389281526B62305555545DB857018C1925CAC31C64EB5E5FDE91AF8E04D256D1347970DEC00399C692A780000008508C00000000000_cppui753;

                        /*constexpr static const std::array<non_residue_type, 2> Frobenius_coeffs_c1 =
                           {non_residue_type(0x01),
                            non_residue_type(0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000000_cppui377)};*/

                        constexpr static const std::array<modulus_type, 2> Frobenius_coeffs_c1 = {
                            0x01,
                            0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000000_cppui377};

                        constexpr static const non_residue_type non_residue = non_residue_type(
                            0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508BFFFFFFFFFFC_cppui377);
                    };

                    constexpr typename fp2_extension_params<bls12_base_field<381>>::non_residue_type const
                        fp2_extension_params<bls12_base_field<381>>::non_residue;
                    constexpr typename fp2_extension_params<bls12_base_field<377>>::non_residue_type const
                        fp2_extension_params<bls12_base_field<377>>::non_residue;

                    constexpr typename std::size_t const fp2_extension_params<bls12_base_field<381>>::s;
                    constexpr typename std::size_t const fp2_extension_params<bls12_base_field<377>>::s;

                    constexpr typename fp2_extension_params<bls12_base_field<381>>::extended_modulus_type const
                        fp2_extension_params<bls12_base_field<381>>::t;
                    constexpr typename fp2_extension_params<bls12_base_field<377>>::extended_modulus_type const
                        fp2_extension_params<bls12_base_field<377>>::t;

                    constexpr typename fp2_extension_params<bls12_base_field<381>>::extended_modulus_type const
                        fp2_extension_params<bls12_base_field<381>>::t_minus_1_over_2;
                    constexpr typename fp2_extension_params<bls12_base_field<377>>::extended_modulus_type const
                        fp2_extension_params<bls12_base_field<377>>::t_minus_1_over_2;

                    constexpr std::array<typename fp2_extension_params<bls12_base_field<381>>::modulus_type, 2> const
                        fp2_extension_params<bls12_base_field<381>>::nqr;
                    constexpr std::array<typename fp2_extension_params<bls12_base_field<377>>::modulus_type, 2> const
                        fp2_extension_params<bls12_base_field<377>>::nqr;

                    constexpr std::array<typename fp2_extension_params<bls12_base_field<381>>::modulus_type, 2> const
                        fp2_extension_params<bls12_base_field<381>>::nqr_to_t;
                    constexpr std::array<typename fp2_extension_params<bls12_base_field<377>>::modulus_type, 2> const
                        fp2_extension_params<bls12_base_field<377>>::nqr_to_t;

                    constexpr typename fp2_extension_params<bls12_base_field<381>>::extended_modulus_type const
                        fp2_extension_params<bls12_base_field<381>>::group_order;
                    constexpr typename fp2_extension_params<bls12_base_field<377>>::extended_modulus_type const
                        fp2_extension_params<bls12_base_field<377>>::group_order;

                    constexpr std::array<typename fp2_extension_params<bls12_base_field<381>>::modulus_type, 2> const
                        fp2_extension_params<bls12_base_field<381>>::Frobenius_coeffs_c1;
                    constexpr std::array<typename fp2_extension_params<bls12_base_field<377>>::modulus_type, 2> const
                        fp2_extension_params<bls12_base_field<377>>::Frobenius_coeffs_c1;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BLS12_FP2_EXTENSION_PARAMS_HPP
