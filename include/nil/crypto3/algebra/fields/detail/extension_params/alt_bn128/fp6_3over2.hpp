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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_FP6_3OVER2_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_FP6_3OVER2_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<typename BaseField>
                    struct fp6_3over2_extension_params;

                    /************************* ALT_BN128 ***********************************/

                    template<std::size_t Version>
                    class fp6_3over2_extension_params<fields::alt_bn128<Version>>
                        : public params<fields::alt_bn128<Version>> {

                        typedef fields::alt_bn128<Version> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef fields::fp2<base_field_type> non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef fields::fp2<base_field_type> underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;

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

                        constexpr static const non_residue_type non_residue = non_residue_type(0x09, 0x01);
                    };

                    template<std::size_t Version>
                    constexpr typename fp6_3over2_extension_params<alt_bn128_base_field<Version>>::non_residue_type const
                        fp6_3over2_extension_params<alt_bn128_base_field<Version>>::non_residue;

                    template<std::size_t Version>
                    constexpr std::array<
                        typename fp6_3over2_extension_params<alt_bn128_base_field<Version>>::modulus_type,
                        6 * 2> const
                        fp6_3over2_extension_params<alt_bn128_base_field<Version>>::Frobenius_coeffs_c1;
                    template<std::size_t Version>
                    constexpr std::array<
                        typename fp6_3over2_extension_params<alt_bn128_base_field<Version>>::modulus_type,
                        6 * 2> const
                        fp6_3over2_extension_params<alt_bn128_base_field<Version>>::Frobenius_coeffs_c2;
                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_ALT_BN128_FP6_3OVER2_EXTENSION_PARAMS_HPP
