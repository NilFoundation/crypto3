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

#ifndef CRYPTO3_ALGEBRA_FIELDS_MNT4_FP2_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_MNT4_FP2_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>

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

                    /************************* MNT4 ***********************************/

                    template<std::size_t Version>
                    class fp2_extension_params<fields::mnt4_base_field<Version>>
                        : public params<fields::mnt4_base_field<Version>> {

                        typedef fields::mnt4_base_field<Version> base_field_type;
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

                        constexpr static const std::size_t s = 0x12;
                        constexpr static const extended_modulus_type t =
                            0x37E52CE842B39321A34D7BA62E2C735153C68D35F7A312CDB18451030CB297F3B772167A8487033D5772A0EF6BEA9BCA60190FFE1CDB642F88A0FF2EFF7A6A3A80FD00203385638B3_cppui578;
                        constexpr static const extended_modulus_type t_minus_1_over_2 =
                            0x1BF296742159C990D1A6BDD3171639A8A9E3469AFBD18966D8C2288186594BF9DBB90B3D4243819EABB95077B5F54DE5300C87FF0E6DB217C4507F977FBD351D407E801019C2B1C59_cppui577;
                        constexpr static const std::array<modulus_type, 2> nqr = {0x08, 0x01};
                        constexpr static const std::array<modulus_type, 2> nqr_to_t = {
                            0x00,
                            0x3B1F45391287A9CB585B8E5504C24BF1EC2010553885078C85899ACD708205080134A9BE6A_cppui294};

                        constexpr static const extended_modulus_type group_order =
                            0x6FCA59D085672643469AF74C5C58E6A2A78D1A6BEF46259B6308A20619652FE76EE42CF5090E067AAEE541DED7D53794C0321FFC39B6C85F1141FE5DFEF4D47501FA0040670AC71660000_cppui595;

                        /*constexpr static const std::array<non_residue_type, 2> Frobenius_coeffs_c1 =
                           {non_residue_type(0x01),
                            non_residue_type(0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298)};*/

                        constexpr static const std::array<modulus_type, 2> Frobenius_coeffs_c1 = {
                            0x01,
                            0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298};

                        constexpr static const non_residue_type non_residue = non_residue_type(0x11);
                    };

                    template<std::size_t Version>
                    constexpr typename fp2_extension_params<mnt4_base_field<Version>>::non_residue_type const
                        fp2_extension_params<mnt4_base_field<Version>>::non_residue;

                    template<std::size_t Version>
                    constexpr typename std::size_t const fp2_extension_params<mnt4_base_field<Version>>::s;

                    template<std::size_t Version>
                    constexpr typename fp2_extension_params<mnt4_base_field<Version>>::extended_modulus_type const
                        fp2_extension_params<mnt4_base_field<Version>>::t;

                    template<std::size_t Version>
                    constexpr typename fp2_extension_params<mnt4_base_field<Version>>::extended_modulus_type const
                        fp2_extension_params<mnt4_base_field<Version>>::t_minus_1_over_2;

                    template<std::size_t Version>
                    constexpr std::array<typename fp2_extension_params<mnt4_base_field<Version>>::modulus_type,
                                         2> const fp2_extension_params<mnt4_base_field<Version>>::nqr;

                    template<std::size_t Version>
                    constexpr std::array<typename fp2_extension_params<mnt4_base_field<Version>>::modulus_type,
                                         2> const fp2_extension_params<mnt4_base_field<Version>>::nqr_to_t;

                    template<std::size_t Version>
                    constexpr typename fp2_extension_params<mnt4_base_field<Version>>::extended_modulus_type const
                        fp2_extension_params<mnt4_base_field<Version>>::group_order;

                    template<std::size_t Version>
                    constexpr typename fp2_extension_params<mnt4_base_field<Version>>::modulus_type const
                        fp2_extension_params<mnt4_base_field<Version>>::modulus;

                    template<std::size_t Version>
                    constexpr std::array<typename fp2_extension_params<mnt4_base_field<Version>>::modulus_type,
                                         2> const
                        fp2_extension_params<mnt4_base_field<Version>>::Frobenius_coeffs_c1;
                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_MNT4_FP2_EXTENSION_PARAMS_HPP
