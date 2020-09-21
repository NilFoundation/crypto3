//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_3over2.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/base_field.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<typename FieldType>
                    struct fp2_extension_params;

                    template<typename FieldType>
                    struct fp6_3over2_extension_params;

                    template<typename FieldType>
                    struct fp12_2over3over2_extension_params;

                    /************************* ALT_BN128 ***********************************/

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    class fp2_extension_params<fields::alt_bn128<ModulusBits, GeneratorBits>>
                        : public params<fields::alt_bn128<ModulusBits, GeneratorBits>> {

                        typedef params<fields::alt_bn128<ModulusBits, GeneratorBits>> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;
                        typedef typename policy_type::extended_modulus_type extended_modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef element_fp<policy_type> non_residue_type;
                        typedef element_fp<policy_type> underlying_type;

                        constexpr static const std::size_t s = 0x04;
                        constexpr static const extended_modulus_type t =
                            0x925C4B8763CBF9C599A6F7C0348D21CB00B85511637560626EDFA5C34C6B38D04689E957A1242C84A50189C6D96CADCA602072D09EAC1013B5458A2275D69B_cppui504;
                        constexpr static const extended_modulus_type t_minus_1_over_2 =
                            0x492E25C3B1E5FCE2CCD37BE01A4690E5805C2A88B1BAB031376FD2E1A6359C682344F4ABD09216425280C4E36CB656E5301039684F560809DAA2C5113AEB4D_cppui503;
                        constexpr static const std::array<modulus_type, 2> nqr = {0x02, 0x01};
                        constexpr static const std::array<modulus_type, 2> nqr_to_t = {
                            0xB20DCB5704E326A0DD3ECD4F30515275398A41A4E1DC5D347CFBBEDDA71CF82_cppui252,
                            0xB1FFEFD8885BF22252522C29527D19F05CFC50E9715370AB0F3A6CA462390C_cppui248};

                        /*constexpr static const std::array<non_residue_type, 2> Frobenius_coeffs_c1 =
                           {non_residue_type(0x01),
                            non_residue_type(0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254)};*/

                        constexpr static const std::array<modulus_type, 2> Frobenius_coeffs_c1 = {
                            0x01, 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254};

                        constexpr static const modulus_type non_residue =
                            modulus_type(0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254);
                    };

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    class fp6_3over2_extension_params<fields::alt_bn128<ModulusBits, GeneratorBits>>
                        : public params<fields::alt_bn128<ModulusBits, GeneratorBits>> {

                        typedef fields::alt_bn128<ModulusBits, GeneratorBits> field_type;
                        typedef params<field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef element_fp2<fp2_extension_params<field_type>> non_residue_type;
                        typedef element_fp2<fp2_extension_params<field_type>> underlying_type;

                        /*constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c1 =
                        {non_residue_type(0x01, 0x00),
                            non_residue_type(0x2FB347984F7911F74C0BEC3CF559B143B78CC310C2C3330C99E39557176F553D_cppui254,
                        0x16C9E55061EBAE204BA4CC8BD75A079432AE2A1D0B7C9DCE1665D51C640FCBA2_cppui253),
                            non_residue_type(0x30644E72E131A0295E6DD9E7E0ACCCB0C28F069FBB966E3DE4BD44E5607CFD48_cppui254,
                        0x00),
                            non_residue_type(0x856E078B755EF0ABAFF1C77959F25AC805FFD3D5D6942D37B746EE87BDCFB6D_cppui252,
                        0x4F1DE41B3D1766FA9F30E6DEC26094F0FDF31BF98FF2631380CAB2BAAA586DE_cppui251),
                            non_residue_type(0x59E26BCEA0D48BACD4F263F1ACDB5C4F5763473177FFFFFE_cppui191, 0x00),
                            non_residue_type(0x28BE74D4BB943F51699582B87809D9CAF71614D4B0B71F3A62E913EE1DADA9E4_cppui254,
                        0x14A88AE0CB747B99C2B86ABCBE01477A54F40EB4C3F6068DEDAE0BCEC9C7AAC7_cppui253)};

                        constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c2 =
                        {non_residue_type(0x01, 0x00),
                            non_residue_type(0x5B54F5E64EEA80180F3C0B75A181E84D33365F7BE94EC72848A1F55921EA762_cppui251,
                        0x2C145EDBE7FD8AEE9F3A80B03B0B1C923685D2EA1BDEC763C13B4711CD2B8126_cppui254),
                            non_residue_type(0x59E26BCEA0D48BACD4F263F1ACDB5C4F5763473177FFFFFE_cppui191, 0x00),
                            non_residue_type(0xBC58C6611C08DAB19BEE0F7B5B2444EE633094575B06BCB0E1A92BC3CCBF066_cppui252,
                        0x23D5E999E1910A12FEB0F6EF0CD21D04A44A9E08737F96E55FE3ED9D730C239F_cppui254),
                            non_residue_type(0x30644E72E131A0295E6DD9E7E0ACCCB0C28F069FBB966E3DE4BD44E5607CFD48_cppui254,
                        0x00),
                            non_residue_type(0x1EE972AE6A826A7D1D9DA40771B6F589DE1AFB54342C724FA97BDA050992657F_cppui253,
                        0x10DE546FF8D4AB51D2B513CDBB25772454326430418536D15721E37E70C255C9_cppui253)};*/

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c1 = {
                            0x01,
                            0x00,
                            0x2FB347984F7911F74C0BEC3CF559B143B78CC310C2C3330C99E39557176F553D_cppui254,
                            0x16C9E55061EBAE204BA4CC8BD75A079432AE2A1D0B7C9DCE1665D51C640FCBA2_cppui253,
                            0x30644E72E131A0295E6DD9E7E0ACCCB0C28F069FBB966E3DE4BD44E5607CFD48_cppui254,
                            0x00,
                            0x856E078B755EF0ABAFF1C77959F25AC805FFD3D5D6942D37B746EE87BDCFB6D_cppui252,
                            0x4F1DE41B3D1766FA9F30E6DEC26094F0FDF31BF98FF2631380CAB2BAAA586DE_cppui251,
                            0x59E26BCEA0D48BACD4F263F1ACDB5C4F5763473177FFFFFE_cppui191,
                            0x00,
                            0x28BE74D4BB943F51699582B87809D9CAF71614D4B0B71F3A62E913EE1DADA9E4_cppui254,
                            0x14A88AE0CB747B99C2B86ABCBE01477A54F40EB4C3F6068DEDAE0BCEC9C7AAC7_cppui253};

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c2 = {
                            0x01,
                            0x00,
                            0x5B54F5E64EEA80180F3C0B75A181E84D33365F7BE94EC72848A1F55921EA762_cppui251,
                            0x2C145EDBE7FD8AEE9F3A80B03B0B1C923685D2EA1BDEC763C13B4711CD2B8126_cppui254,
                            0x59E26BCEA0D48BACD4F263F1ACDB5C4F5763473177FFFFFE_cppui191,
                            0x00,
                            0xBC58C6611C08DAB19BEE0F7B5B2444EE633094575B06BCB0E1A92BC3CCBF066_cppui252,
                            0x23D5E999E1910A12FEB0F6EF0CD21D04A44A9E08737F96E55FE3ED9D730C239F_cppui254,
                            0x30644E72E131A0295E6DD9E7E0ACCCB0C28F069FBB966E3DE4BD44E5607CFD48_cppui254,
                            0x00,
                            0x1EE972AE6A826A7D1D9DA40771B6F589DE1AFB54342C724FA97BDA050992657F_cppui253,
                            0x10DE546FF8D4AB51D2B513CDBB25772454326430418536D15721E37E70C255C9_cppui253};

                        constexpr static const std::array<modulus_type, 2> non_residue = {9, 1};
                    };

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    class fp12_2over3over2_extension_params<fields::alt_bn128<ModulusBits, GeneratorBits>>
                        : public params<fields::alt_bn128<ModulusBits, GeneratorBits>> {

                        typedef fields::alt_bn128<ModulusBits, GeneratorBits> field_type;
                        typedef params<field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef element_fp2<fp2_extension_params<field_type>> non_residue_type;
                        typedef element_fp6_3over2<fp6_3over2_extension_params<field_type>> underlying_type;

                        /*constexpr static const std::array<non_residue_type, 12> Frobenius_coeffs_c1 =
                           {non_residue_type(0x01, 0x00),
                            non_residue_type(0x1284B71C2865A7DFE8B99FDD76E68B605C521E08292F2176D60B35DADCC9E470_cppui253,
                           0x246996F3B4FAE7E6A6327CFE12150B8E747992778EEEC7E5CA5CF05F80F362AC_cppui254),
                            non_residue_type(0x30644E72E131A0295E6DD9E7E0ACCCB0C28F069FBB966E3DE4BD44E5607CFD49_cppui254,
                           0x00),
                            non_residue_type(0x19DC81CFCC82E4BBEFE9608CD0ACAA90894CB38DBE55D24AE86F7D391ED4A67F_cppui253,
                           0xABF8B60BE77D7306CBEEE33576139D7F03A5E397D439EC7694AA2BF4C0C101_cppui248),
                            non_residue_type(0x30644E72E131A0295E6DD9E7E0ACCCB0C28F069FBB966E3DE4BD44E5607CFD48_cppui254,
                           0x00),
                            non_residue_type(0x757CAB3A41D3CDC072FC0AF59C61F302CFA95859526B0D41264475E420AC20F_cppui251,
                           0xCA6B035381E35B618E9B79BA4E2606CA20B7DFD71573C93E85845E34C4A5B9C_cppui252),
                            non_residue_type(0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254,
                           0x00),
                            non_residue_type(0x1DDF9756B8CBF849CF96A5D90A9ACCFD3B2F4C893F42A9166615563BFBB318D7_cppui253,
                           0xBFAB77F2C36B843121DC8B86F6C4CCF2307D819D98302A771C39BB757899A9B_cppui252),
                            non_residue_type(0x59E26BCEA0D48BACD4F263F1ACDB5C4F5763473177FFFFFE_cppui191, 0x00),
                            non_residue_type(0x1687CCA314AEBB6DC866E529B0D4ADCD0E34B703AA1BF84253B10EDDB9A856C8_cppui253,
                           0x2FB855BCD54A22B6B18456D34C0B44C0187DC4ADD09D90A0C58BE1EAE3BC3C46_cppui254),
                            non_residue_type(0x59E26BCEA0D48BACD4F263F1ACDB5C4F5763473177FFFFFF_cppui191, 0x00),
                            non_residue_type(0x290C83BF3D14634DB120850727BB392D6A86D50BD34B19B929BC44B896723B38_cppui254,
                           0x23BD9E3DA9136A739F668E1ADC9EF7F0F575EC93F71A8DF953C846338C32A1AB_cppui254)};*/

                        constexpr static const std::array<modulus_type, 12 * 2> Frobenius_coeffs_c1 = {
                            0x01,
                            0x00,
                            0x1284B71C2865A7DFE8B99FDD76E68B605C521E08292F2176D60B35DADCC9E470_cppui253,
                            0x246996F3B4FAE7E6A6327CFE12150B8E747992778EEEC7E5CA5CF05F80F362AC_cppui254,
                            0x30644E72E131A0295E6DD9E7E0ACCCB0C28F069FBB966E3DE4BD44E5607CFD49_cppui254,
                            0x00,
                            0x19DC81CFCC82E4BBEFE9608CD0ACAA90894CB38DBE55D24AE86F7D391ED4A67F_cppui253,
                            0xABF8B60BE77D7306CBEEE33576139D7F03A5E397D439EC7694AA2BF4C0C101_cppui248,
                            0x30644E72E131A0295E6DD9E7E0ACCCB0C28F069FBB966E3DE4BD44E5607CFD48_cppui254,
                            0x00,
                            0x757CAB3A41D3CDC072FC0AF59C61F302CFA95859526B0D41264475E420AC20F_cppui251,
                            0xCA6B035381E35B618E9B79BA4E2606CA20B7DFD71573C93E85845E34C4A5B9C_cppui252,
                            0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254,
                            0x00,
                            0x1DDF9756B8CBF849CF96A5D90A9ACCFD3B2F4C893F42A9166615563BFBB318D7_cppui253,
                            0xBFAB77F2C36B843121DC8B86F6C4CCF2307D819D98302A771C39BB757899A9B_cppui252,
                            0x59E26BCEA0D48BACD4F263F1ACDB5C4F5763473177FFFFFE_cppui191,
                            0x00,
                            0x1687CCA314AEBB6DC866E529B0D4ADCD0E34B703AA1BF84253B10EDDB9A856C8_cppui253,
                            0x2FB855BCD54A22B6B18456D34C0B44C0187DC4ADD09D90A0C58BE1EAE3BC3C46_cppui254,
                            0x59E26BCEA0D48BACD4F263F1ACDB5C4F5763473177FFFFFF_cppui191,
                            0x00,
                            0x290C83BF3D14634DB120850727BB392D6A86D50BD34B19B929BC44B896723B38_cppui254,
                            0x23BD9E3DA9136A739F668E1ADC9EF7F0F575EC93F71A8DF953C846338C32A1AB_cppui254};

                        constexpr static const std::array<modulus_type, 2> non_residue = {9, 1};
                    };

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr typename fp2_extension_params<
                        alt_bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                        fp2_extension_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>::non_residue;

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr typename std::size_t const
                        fp2_extension_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>::s;

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr typename fp2_extension_params<
                        alt_bn128_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                        fp2_extension_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>::t;

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr typename fp2_extension_params<
                        alt_bn128_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                        fp2_extension_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>::t_minus_1_over_2;

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr std::array<
                        typename fp2_extension_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type,
                        2> const fp2_extension_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>::nqr;

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr std::array<
                        typename fp2_extension_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type,
                        2> const fp2_extension_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>::nqr_to_t;

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr std::array<typename fp6_3over2_extension_params<
                                             alt_bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type,
                                         2> const
                        fp6_3over2_extension_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>::non_residue;

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr std::array<typename fp12_2over3over2_extension_params<
                                             alt_bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type,
                                         2> const
                        fp12_2over3over2_extension_params<
                            alt_bn128_base_field<ModulusBits, GeneratorBits>>::non_residue;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ALT_BN128_EXTENSION_PARAMS_HPP
