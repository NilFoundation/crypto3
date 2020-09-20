//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_MNT4_EXTENSION_PARAMS_HPP
#define ALGEBRA_FIELDS_MNT4_EXTENSION_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>

#include <nil/algebra/fields/params.hpp>
#include <nil/algebra/fields/mnt4/base_field.hpp>
#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                using namespace nil::algebra;

                template<typename FieldType>
                struct fp2_extension_params;

                template<typename FieldType>
                struct fp4_extension_params;

                /************************* MNT4 ***********************************/
                
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class fp2_extension_params<fields::mnt4_base_field<ModulusBits, GeneratorBits>>
                    : public params<fields::mnt4_base_field<ModulusBits, GeneratorBits>> {

                    typedef params<fields::mnt4_base_field<ModulusBits, GeneratorBits>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;
                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp<policy_type> non_residue_type;
                    typedef element_fp<policy_type> underlying_type;

                    constexpr static const std::size_t s = 0x12;
                    constexpr static const extended_modulus_type t =
                        0x37E52CE842B39321A34D7BA62E2C735153C68D35F7A312CDB18451030CB297F3B772167A8487033D5772A0EF6BEA9BCA60190FFE1CDB642F88A0FF2EFF7A6A3A80FD00203385638B3_cppui578;
                    constexpr static const extended_modulus_type t_minus_1_over_2 =
                        0x1BF296742159C990D1A6BDD3171639A8A9E3469AFBD18966D8C2288186594BF9DBB90B3D4243819EABB95077B5F54DE5300C87FF0E6DB217C4507F977FBD351D407E801019C2B1C59_cppui577;
                    constexpr static const std::array<modulus_type, 2> nqr = {0x08, 0x01};
                    constexpr static const std::array<modulus_type, 2> nqr_to_t = 
                        {0x00, 0x3B1F45391287A9CB585B8E5504C24BF1EC2010553885078C85899ACD708205080134A9BE6A_cppui294};

                    constexpr static const std::array<underlying_type, 2> Frobenius_coeffs_c1 = {underlying_type(0x01),
                        underlying_type(0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298)};

                    constexpr static const modulus_type non_residue = modulus_type(0x11);
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class fp4_extension_params<fields::mnt4_base_field<ModulusBits, GeneratorBits>>
                    : public params<fields::mnt4_base_field<ModulusBits, GeneratorBits>> {

                    typedef fields::mnt4_base_field<ModulusBits, GeneratorBits> field_type;
                    typedef params<field_type> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp<policy_type> non_residue_type;
                    typedef element_fp2<fp2_extension_params<field_type>> underlying_type;

                    constexpr static const std::array<underlying_type, 4> Frobenius_coeffs_c1 = {underlying_type(0x01),
                        underlying_type(0xF73779FE09916DFDCC2FD1F968D534BEB17DAF7518CD9FAE5C1F7BDCF94DD5D7DEF6980C4_cppui292),
                        underlying_type(0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660000_cppui298),
                        underlying_type(0x3AD84453493094F44C0E4B334F83D9B7D7845383998B4CFE8788F285043342F78DC81FC7F3D_cppui298)};

                    constexpr static const modulus_type non_residue = modulus_type(0x11);
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::non_residue;
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp4_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp4_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename std::size_t const
                    fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::s;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                    fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::t;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                    fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::t_minus_1_over_2;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::nqr;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::nqr_to_t;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp2_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus;
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp4_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp4_extension_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus;

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_MNT4_EXTENSION_PARAMS_HPP
