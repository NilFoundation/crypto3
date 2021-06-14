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

#ifndef CRYPTO3_ALGEBRA_FIELDS_MNT6_FP3_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_MNT6_FP3_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<typename BaseField>
                struct fp3;
                namespace detail {

                    template<typename BaseField>
                    struct fp3_extension_params;

                    /************************* MNT6 ***********************************/

                    template<std::size_t Version>
                    class fp3_extension_params<fields::mnt6_base_field<Version>>
                        : public params<fields::mnt6_base_field<Version>> {

                        typedef fields::mnt6_base_field<Version> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;
                        typedef typename policy_type::extended_modulus_type extended_modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef base_field_type non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef base_field_type underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;

                        constexpr static const std::size_t s = 0x22;
                        constexpr static const extended_modulus_type t =
                            0xD0F1EB0C5D321E87BF885ACDEBEDB4C0D6B30E63AB6E7BF6417A7990679AA640A7D58FB90CC708D572D32DFD6443366D2F92F48FF1A02FDB0CC11573BAB71F8E5E05B07DEA208A7E11F3E61C9968CC65F379EFCEF9472C7FC6DEE40194CA1DF9F801DC0D24656EACC72677B_cppui860;
                        constexpr static const extended_modulus_type t_minus_1_over_2 =
                            0x6878F5862E990F43DFC42D66F5F6DA606B598731D5B73DFB20BD3CC833CD532053EAC7DC8663846AB96996FEB2219B3697C97A47F8D017ED86608AB9DD5B8FC72F02D83EF510453F08F9F30E4CB46632F9BCF7E77CA3963FE36F7200CA650EFCFC00EE069232B75663933BD_cppui859;
                        constexpr static const std::array<modulus_type, 3> nqr = {0x05, 0x00, 0x00};
                        constexpr static const std::array<modulus_type, 3> nqr_to_t = {
                            0x1366271F76AB41CEEEE8C1E5E972F3CEC14A25F18B3F4B93642FAD4972356D977470E0FA674_cppui297,
                            0x00, 0x00};

                        constexpr static const extended_modulus_type group_order =
                            0x1A1E3D618BA643D0F7F10B59BD7DB6981AD661CC756DCF7EC82F4F320CF354C814FAB1F72198E11AAE5A65BFAC8866CDA5F25E91FE3405FB619822AE7756E3F1CBC0B60FBD44114FC23E7CC3932D198CBE6F3DF9DF28E58FF8DBDC80329943BF3F003B81A48CADD598E4CEF600000000_cppui893;

                        /*constexpr static const std::array<non_residue_type, 3> Frobenius_coeffs_c1 =
                        {non_residue_type(0x01),
                            non_residue_type(0x3B48E50A1662E26F0E834E15FAF68204A9845655F46B277A6D05B75068AD3F6801655344BEC_cppui298),
                            non_residue_type(0x8696C330D743F33B572CEF4DF62CE7ECB178EE24E48D1A53736E86448E74CB48DAACBB414_cppui292)};

                        constexpr static const std::array<non_residue_type, 3> Frobenius_coeffs_c2 =
                        {non_residue_type(0x01),
                            non_residue_type(0x8696C330D743F33B572CEF4DF62CE7ECB178EE24E48D1A53736E86448E74CB48DAACBB414_cppui292),
                            non_residue_type(0x3B48E50A1662E26F0E834E15FAF68204A9845655F46B277A6D05B75068AD3F6801655344BEC_cppui298)};*/

                        constexpr static const std::array<modulus_type, 3> Frobenius_coeffs_c1 = {
                            0x01,
                            0x3B48E50A1662E26F0E834E15FAF68204A9845655F46B277A6D05B75068AD3F6801655344BEC_cppui298,
                            0x8696C330D743F33B572CEF4DF62CE7ECB178EE24E48D1A53736E86448E74CB48DAACBB414_cppui292};

                        constexpr static const std::array<modulus_type, 3> Frobenius_coeffs_c2 = {
                            0x01, 0x8696C330D743F33B572CEF4DF62CE7ECB178EE24E48D1A53736E86448E74CB48DAACBB414_cppui292,
                            0x3B48E50A1662E26F0E834E15FAF68204A9845655F46B277A6D05B75068AD3F6801655344BEC_cppui298};

                        constexpr static const non_residue_type non_residue = non_residue_type(0x05);
                    };

                    template<std::size_t Version>
                    constexpr typename fp3_extension_params<mnt6_base_field<Version>>::non_residue_type const
                        fp3_extension_params<mnt6_base_field<Version>>::non_residue;

                    template<std::size_t Version>
                    constexpr typename std::size_t const fp3_extension_params<mnt6_base_field<Version>>::s;

                    template<std::size_t Version>
                    constexpr typename fp3_extension_params<mnt6_base_field<Version>>::extended_modulus_type const
                        fp3_extension_params<mnt6_base_field<Version>>::t;

                    template<std::size_t Version>
                    constexpr typename fp3_extension_params<mnt6_base_field<Version>>::extended_modulus_type const
                        fp3_extension_params<mnt6_base_field<Version>>::t_minus_1_over_2;

                    template<std::size_t Version>
                    constexpr std::array<typename fp3_extension_params<mnt6_base_field<Version>>::modulus_type,
                                         3> const fp3_extension_params<mnt6_base_field<Version>>::nqr;

                    template<std::size_t Version>
                    constexpr std::array<typename fp3_extension_params<mnt6_base_field<Version>>::modulus_type,
                                         3> const fp3_extension_params<mnt6_base_field<Version>>::nqr_to_t;

                    template<std::size_t Version>
                    constexpr typename fp3_extension_params<mnt6_base_field<Version>>::extended_modulus_type const
                        fp3_extension_params<mnt6_base_field<Version>>::group_order;

                    template<std::size_t Version>
                    constexpr typename fp3_extension_params<mnt6_base_field<Version>>::modulus_type const
                        fp3_extension_params<mnt6_base_field<Version>>::modulus;

                    template<std::size_t Version>
                    constexpr std::array<typename fp3_extension_params<mnt6_base_field<Version>>::modulus_type,
                                         3> const
                        fp3_extension_params<mnt6_base_field<Version>>::Frobenius_coeffs_c1;

                    template<std::size_t Version>
                    constexpr std::array<typename fp3_extension_params<mnt6_base_field<Version>>::modulus_type,
                                         3> const
                        fp3_extension_params<mnt6_base_field<Version>>::Frobenius_coeffs_c2;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_MNT6_FP3_EXTENSION_PARAMS_HPP
