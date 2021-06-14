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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BLS12_FP6_3OVER2_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BLS12_FP6_3OVER2_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/fp2.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    template<typename BaseField>
                    struct fp6_3over2_extension_params;

                    /************************* BLS12-381 ***********************************/

                    template<>
                    class fp6_3over2_extension_params<fields::bls12<381>> : public params<fields::bls12<381>> {

                        typedef fields::bls12<381> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef fields::fp2<base_field_type> non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef fields::fp2<base_field_type> underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;
                        // typedef element_fp2<fp2_extension_params<field_type>> underlying_type;

                        /*constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c1 =
                        {non_residue_type(0x01, 0x00), non_residue_type(0x00,
                        0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381),
                            non_residue_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319,
                        0x00), non_residue_type(0x00, 0x01),
                            non_residue_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381,
                        0x00), non_residue_type(0x00,
                        0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319)};

                        constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c2 =
                        {non_residue_type(0x01, 0x00),
                            non_residue_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAD_cppui381,
                        0x00),
                            non_residue_type(0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381,
                        0x00),
                            non_residue_type(0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381,
                        0x00),
                            non_residue_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319,
                        0x00),
                            non_residue_type(0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFF_cppui319,
                        0x00)};*/

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c1 = {
                            0x01,
                            0x00,
                            0x00,
                            0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381,
                            0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319,
                            0x00,
                            0x00,
                            0x01,
                            0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381,
                            0x00,
                            0x00,
                            0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319};

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c2 = {
                            0x01,
                            0x00,
                            0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAD_cppui381,
                            0x00,
                            0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC_cppui381,
                            0x00,
                            0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381,
                            0x00,
                            0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE_cppui319,
                            0x00,
                            0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFF_cppui319,
                            0x00};

                        constexpr static const non_residue_type non_residue = non_residue_type(0x01, 0x01);
                    };

                    /************************* BLS12-377 ***********************************/

                    template<>
                    class fp6_3over2_extension_params<fields::bls12<377>> : public params<fields::bls12<377>> {

                        typedef fields::bls12<377> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef fields::fp2<base_field_type> non_residue_field_type;
                        typedef non_residue_field_type::value_type non_residue_type;
                        typedef fields::fp2<base_field_type> underlying_field_type;
                        typedef underlying_field_type::value_type underlying_type;
                        // typedef element_fp2<fp2_extension_params<field_type>> underlying_type;

                        /*constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c1 =
                        {non_residue_type(0x01, 0x00),
                            non_residue_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000002_cppui316,
                        0x00),
                            non_residue_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316,
                        0x00),
                            non_residue_type(0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000000_cppui377,
                        0x00),
                            non_residue_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377,
                        0x00),
                            non_residue_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E94577A00000000000000000000000_cppui377,
                        0x00)};

                        constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c2 =
                        {non_residue_type(0x01, 0x00),
                            non_residue_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316,
                        0x00),
                            non_residue_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377,
                        0x00), non_residue_type(0x01, 0x00),
                            non_residue_type(0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316,
                        0x00),
                            non_residue_type(0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377,
                        0x00)};*/

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c1 = {
                            0x01,
                            0x00,
                            0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000002_cppui316,
                            0x00,
                            0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316,
                            0x00,
                            0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508C00000000000_cppui377,
                            0x00,
                            0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377,
                            0x00,
                            0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E94577A00000000000000000000000_cppui377,
                            0x00};

                        constexpr static const std::array<modulus_type, 6 * 2> Frobenius_coeffs_c2 = {
                            0x01,
                            0x00,
                            0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316,
                            0x00,
                            0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377,
                            0x00,
                            0x01,
                            0x00,
                            0x9B3AF05DD14F6EC619AAF7D34594AABC5ED1347970DEC00452217CC900000008508C00000000001_cppui316,
                            0x00,
                            0x1AE3A4617C510EABC8756BA8F8C524EB8882A75CC9BC8E359064EE822FB5BFFD1E945779FFFFFFFFFFFFFFFFFFFFFFF_cppui377,
                            0x00};

                        constexpr static const non_residue_type non_residue = non_residue_type(0x00, 0x01);
                    };

                    constexpr typename fp6_3over2_extension_params<bls12_base_field<381>>::non_residue_type
                                         const fp6_3over2_extension_params<bls12_base_field<381>>::non_residue;
                    constexpr typename fp6_3over2_extension_params<bls12_base_field<377>>::non_residue_type
                                         const fp6_3over2_extension_params<bls12_base_field<377>>::non_residue;

                    constexpr std::array<typename fp6_3over2_extension_params<bls12_base_field<381>>::modulus_type,
                                         6 * 2> const
                        fp6_3over2_extension_params<bls12_base_field<381>>::Frobenius_coeffs_c1;
                    constexpr std::array<typename fp6_3over2_extension_params<bls12_base_field<381>>::modulus_type,
                                         6 * 2> const
                        fp6_3over2_extension_params<bls12_base_field<381>>::Frobenius_coeffs_c2;

                    constexpr std::array<typename fp6_3over2_extension_params<bls12_base_field<377>>::modulus_type,
                                         6 * 2> const
                        fp6_3over2_extension_params<bls12_base_field<377>>::Frobenius_coeffs_c1;
                    constexpr std::array<typename fp6_3over2_extension_params<bls12_base_field<377>>::modulus_type,
                                         6 * 2> const
                        fp6_3over2_extension_params<bls12_base_field<377>>::Frobenius_coeffs_c2;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BLS12_FP6_3OVER2_EXTENSION_PARAMS_HPP
