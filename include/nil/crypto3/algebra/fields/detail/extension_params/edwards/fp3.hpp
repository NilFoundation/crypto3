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

#ifndef CRYPTO3_ALGEBRA_FIELDS_EDWARDS_FP3_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_EDWARDS_FP3_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/edwards/base_field.hpp>

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

                    /************************* EDWARDS ***********************************/

                    template<std::size_t Version>
                    class fp3_extension_params<fields::edwards_base_field<Version>>
                        : public params<fields::edwards_base_field<Version>> {

                        typedef fields::edwards_base_field<Version> base_field_type;
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

                        constexpr static const std::size_t s = 0x1F;
                        constexpr static const extended_modulus_type t =
                            0x8514C337908664095AA1E4077718C1F93B49FEBD3E1DE5A3BF284A7BC8C90EE457BC1D3D59409F6A8049FB3D3B1E20915D50941493A9E2B4B0685ACA3C9847645_cppui516;
                        constexpr static const extended_modulus_type t_minus_1_over_2 =
                            0x428A619BC8433204AD50F203BB8C60FC9DA4FF5E9F0EF2D1DF94253DE46487722BDE0E9EACA04FB54024FD9E9D8F1048AEA84A0A49D4F15A58342D651E4C23B22_cppui515;
                        constexpr static const std::array<modulus_type, 3> nqr = {0x17, 0x00, 0x00};
                        constexpr static const std::array<modulus_type, 3> nqr_to_t = {
                            0x118228ECB464A2F6EB8DACC18FA757E45B3989330150C_cppui177, 0x00, 0x00};

                        constexpr static const extended_modulus_type group_order =
                            0x214530CDE421990256A87901DDC6307E4ED27FAF4F877968EFCA129EF23243B915EF074F565027DAA0127ECF4EC788245754250524EA78AD2C1A16B28F2611D9140000000_cppui546;

                        /*constexpr static const std::array<non_residue_type, 3> Frobenius_coeffs_c1 =
                        {non_residue_type(0x01),
                            non_residue_type(0xB35E3665A18365954D018902935D4419423F84321BC3D_cppui180),
                            non_residue_type(0x35A01936D02124BA36C236460AF76D755745133CDE43C3_cppui182)};

                        constexpr static const std::array<non_residue_type, 3> Frobenius_coeffs_c2 =
                        {non_residue_type(0x01),
                            non_residue_type(0x35A01936D02124BA36C236460AF76D755745133CDE43C3_cppui182),
                            non_residue_type(0xB35E3665A18365954D018902935D4419423F84321BC3D_cppui180)};*/

                        constexpr static const std::array<modulus_type, 3> Frobenius_coeffs_c1 = {
                            0x01, 0xB35E3665A18365954D018902935D4419423F84321BC3D_cppui180,
                            0x35A01936D02124BA36C236460AF76D755745133CDE43C3_cppui182};

                        constexpr static const std::array<modulus_type, 3> Frobenius_coeffs_c2 = {
                            0x01, 0x35A01936D02124BA36C236460AF76D755745133CDE43C3_cppui182,
                            0xB35E3665A18365954D018902935D4419423F84321BC3D_cppui180};

                        constexpr static const non_residue_type non_residue = non_residue_type(0x3D);
                    };

                    template<std::size_t Version>
                    constexpr typename fp3_extension_params<edwards_base_field<Version>>::non_residue_type const
                        fp3_extension_params<edwards_base_field<Version>>::non_residue;

                    template<std::size_t Version>
                    constexpr typename std::size_t const fp3_extension_params<edwards_base_field<Version>>::s;

                    template<std::size_t Version>
                    constexpr
                        typename fp3_extension_params<edwards_base_field<Version>>::extended_modulus_type const
                            fp3_extension_params<edwards_base_field<Version>>::t;

                    template<std::size_t Version>
                    constexpr
                        typename fp3_extension_params<edwards_base_field<Version>>::extended_modulus_type const
                            fp3_extension_params<edwards_base_field<Version>>::t_minus_1_over_2;

                    template<std::size_t Version>
                    constexpr std::array<typename fp3_extension_params<edwards_base_field<Version>>::modulus_type,
                                         3> const fp3_extension_params<edwards_base_field<Version>>::nqr;

                    template<std::size_t Version>
                    constexpr std::array<typename fp3_extension_params<edwards_base_field<Version>>::modulus_type,
                                         3> const fp3_extension_params<edwards_base_field<Version>>::nqr_to_t;

                    template<std::size_t Version>
                    constexpr
                        typename fp3_extension_params<edwards_base_field<Version>>::extended_modulus_type const
                            fp3_extension_params<edwards_base_field<Version>>::group_order;

                    template<std::size_t Version>
                    constexpr typename fp3_extension_params<edwards_base_field<Version>>::modulus_type const
                        fp3_extension_params<edwards_base_field<Version>>::modulus;

                    template<std::size_t Version>
                    constexpr std::array<typename fp3_extension_params<edwards_base_field<Version>>::modulus_type,
                                         3> const
                        fp3_extension_params<edwards_base_field<Version>>::Frobenius_coeffs_c1;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_EDWARDS_FP3_EXTENSION_PARAMS_HPP
