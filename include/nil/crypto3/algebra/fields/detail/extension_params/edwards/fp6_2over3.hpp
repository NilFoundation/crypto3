//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_EDWARDS_FP6_2OVER3_EXTENSION_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_EDWARDS_FP6_2OVER3_EXTENSION_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/edwards/base_field.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<typename FieldType>
                    struct fp6_2over3_extension_params;

                    /************************* EDWARDS ***********************************/

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    class fp6_2over3_extension_params<fields::edwards_base_field<ModulusBits, GeneratorBits>>
                        : public params<fields::edwards_base_field<ModulusBits, GeneratorBits>> {

                        typedef fields::edwards_base_field<ModulusBits, GeneratorBits> base_field_type;
                        typedef params<base_field_type> policy_type;

                    public:
                        typedef typename policy_type::number_type number_type;
                        typedef typename policy_type::modulus_type modulus_type;

                        constexpr static const modulus_type modulus = policy_type::modulus;

                        typedef base_field_type non_residue_field_type;
                        typedef typename non_residue_field_type::value_type non_residue_type;
                        typedef fields::fp3<base_field_type> underlying_field_type;
                        typedef typename underlying_field_type::value_type underlying_type;
                        //typedef element_fp3<fp3_extension_params<field_type>> underlying_type;

                        /*constexpr static const std::array<non_residue_type, 6> Frobenius_coeffs_c1 =
                           {non_residue_type(0x01),
                            non_residue_type(0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180),
                            non_residue_type(0xB35E3665A18365954D018902935D4419423F84321BC3D_cppui180),
                            non_residue_type(0x40D5FC9D2A395B138B924ED6342D41B6EB690B80000000_cppui183),
                            non_residue_type(0x35A01936D02124BA36C236460AF76D755745133CDE43C3_cppui182),
                            non_residue_type(0x35A01936D02124BA36C236460AF76D755745133CDE43C4_cppui182)};*/

                        constexpr static const std::array<modulus_type, 6> Frobenius_coeffs_c1 = {
                            0x01,
                            0xB35E3665A18365954D018902935D4419423F84321BC3E_cppui180,
                            0xB35E3665A18365954D018902935D4419423F84321BC3D_cppui180,
                            0x40D5FC9D2A395B138B924ED6342D41B6EB690B80000000_cppui183,
                            0x35A01936D02124BA36C236460AF76D755745133CDE43C3_cppui182,
                            0x35A01936D02124BA36C236460AF76D755745133CDE43C4_cppui182};

                        constexpr static const modulus_type non_residue = modulus_type(0x3D);
                    };

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr typename fp6_2over3_extension_params<
                        edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                        fp6_2over3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::non_residue;

                    template<std::size_t ModulusBits, std::size_t GeneratorBits>
                    constexpr typename fp6_2over3_extension_params<
                        edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                        fp6_2over3_extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus;

                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_EDWARDS_FP6_2OVER3_EXTENSION_PARAMS_HPP
