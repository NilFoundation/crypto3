//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_EDWARDS_EXTENSION_PARAMS_HPP
#define ALGEBRA_FIELDS_EDWARDS_EXTENSION_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp3.hpp>

#include <nil/algebra/fields/params.hpp>
#include <nil/algebra/fields/edwards/base_field.hpp>
#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                using namespace nil::algebra;

                template<typename FieldType>
                struct fp3_extension_params;

                template<typename FieldType>
                struct fp6_2over3_extension_params;

                /************************* EDWARDS ***********************************/

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class fp3_extension_params<fields::edwards_base_field<ModulusBits, GeneratorBits>>
                    : public params<fields::edwards_base_field<ModulusBits, GeneratorBits>> {

                    typedef params<fields::edwards_base_field<ModulusBits, GeneratorBits>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;
                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp<policy_type> non_residue_type;
                    typedef element_fp<policy_type> underlying_type;

                    constexpr static const std::size_t s = 0x1F;
                    constexpr static const extended_modulus_type t =
                        0x8514C337908664095AA1E4077718C1F93B49FEBD3E1DE5A3BF284A7BC8C90EE457BC1D3D59409F6A8049FB3D3B1E20915D50941493A9E2B4B0685ACA3C9847645_cppui516;
                    constexpr static const extended_modulus_type t_minus_1_over_2 =
                        0x428A619BC8433204AD50F203BB8C60FC9DA4FF5E9F0EF2D1DF94253DE46487722BDE0E9EACA04FB54024FD9E9D8F1048AEA84A0A49D4F15A58342D651E4C23B22_cppui515;
                    constexpr static const std::array<modulus_type, 3> nqr = {0x17, 0x00, 0x00};
                    constexpr static const std::array<modulus_type, 3> nqr_to_t = 
                        {0x118228ECB464A2F6EB8DACC18FA757E45B3989330150C_cppui177, 0x00, 0x00};

                    constexpr static const std::array<underlying_type, 3> Frobenius_coeffs_c1 = {underlying_type(0x01),
                        underlying_type(0xB35E3665A18365954D018902935D4419423F84321BC3D_cppui180),
                        underlying_type(0x35A01936D02124BA36C236460AF76D755745133CDE43C3_cppui182)};

                    constexpr static const std::array<underlying_type, 3> Frobenius_coeffs_c2 = {underlying_type(0x01),
                        underlying_type(0x35A01936D02124BA36C236460AF76D755745133CDE43C3_cppui182),
                        underlying_type(0xB35E3665A18365954D018902935D4419423F84321BC3D_cppui180)};

                    constexpr static const modulus_type non_residue = modulus_type(0x3D);
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class fp6_2over3_extension_params<fields::edwards_base_field<ModulusBits, GeneratorBits>>
                    : public params<fields::edwards_base_field<ModulusBits, GeneratorBits>> {

                    typedef fields::edwards_base_field<ModulusBits, GeneratorBits> field_type;
                    typedef params<field_type> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp<policy_type> non_residue_type;
                    typedef element_fp3<fp3_extension_params<field_type>> underlying_type;

                    constexpr static const std::array<underlying_type, 6> Frobenius_coeffs_c1 = {underlying_type(0x01),
                        underlying_type(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180),
                        underlying_type(0xB35E3665A18365954D018902935D4419423F84321BC3D_cppui180),
                        underlying_type(0x40D5FC9D2A395B138B924ED6342D41B6EB690B80000000_cppui183),
                        underlying_type(0x35A01936D02124BA36C236460AF76D755745133CDE43C3_cppui182),
                        underlying_type(0x35A01936D02124BA36C236460AF76D755745133CDE43C4_cppui182)};

                    constexpr static const modulus_type non_residue = modulus_type(0x3D);
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp6_2over3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp6_2over3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename std::size_t const
                    fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::s;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                    fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::t;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                    fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::t_minus_1_over_2;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type, 3> const
                    fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::nqr;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type, 3> const
                    fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::nqr_to_t;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus;
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp6_2over3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp6_2over3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus;

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_EDWARDS_EXTENSION_PARAMS_HPP
