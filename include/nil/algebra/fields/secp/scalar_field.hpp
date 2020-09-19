//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_SECP_SCALAR_FIELD_HPP
#define ALGEBRA_FIELDS_SECP_SCALAR_FIELD_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>

#include <nil/algebra/fields/params.hpp>
#include <nil/algebra/fields/field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            /*!
             * @brief IETF IPsec groups
             * @tparam ModulusBits
             * @tparam GeneratorBits
             */
            template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
            struct secp_k1_scalar_field : public field<ModulusBits, GeneratorBits> { };

            template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
            struct secp_r1_scalar_field : public field<ModulusBits, GeneratorBits> { };

            template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
            struct secp_r2_scalar_field : public field<ModulusBits, GeneratorBits> { };

            template<>
            struct secp_k1_scalar_field<160, CHAR_BIT> : public field<160, CHAR_BIT> {
                typedef field<160, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const std::size_t number_bits = policy_type::number_bits;
                typedef typename policy_type::number_type number_type;

                constexpr static const modulus_type modulus = 0x100000000000000000001B8FA16DFAB9ACA16B6B3_cppui160;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<params<secp_k1_scalar_field<160, CHAR_BIT>>>
                    value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_r1_scalar_field<160, CHAR_BIT> : public field<160, CHAR_BIT> {
                typedef field<160, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const modulus_type modulus = 0x100000000000000000001F4C8F927AED3CA752257_cppui160;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<params<secp_r1_scalar_field<160, CHAR_BIT>>>
                    value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_r2_scalar_field<160, CHAR_BIT> : public field<160, CHAR_BIT> {
                typedef field<160, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const modulus_type modulus = 0x100000000000000000000351EE786A818F3A1A16B_cppui160;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<params<secp_r2_scalar_field<160, CHAR_BIT>>>
                    value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_k1_scalar_field<192, CHAR_BIT> : public field<192, CHAR_BIT> {
                typedef field<192, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const modulus_type modulus =
                    0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D_cppui192;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<params<secp_k1_scalar_field<192, CHAR_BIT>>>
                    value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_r1_scalar_field<192, CHAR_BIT> : public field<192, CHAR_BIT> {
                typedef field<192, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const modulus_type modulus =
                    0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D_cppui192;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<params<secp_r1_scalar_field<192, CHAR_BIT>>>
                    value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_k1_scalar_field<224, CHAR_BIT> : public field<224, CHAR_BIT> {
                typedef field<224, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const modulus_type modulus =
                    0x10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7_cppui224;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<params<secp_k1_scalar_field<224, CHAR_BIT>>>
                    value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_r1_scalar_field<224, CHAR_BIT> : public field<224, CHAR_BIT> {
                typedef field<224, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const modulus_type modulus =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D_cppui224;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<params<secp_r1_scalar_field<224, CHAR_BIT>>>
                    value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_k1_scalar_field<256, CHAR_BIT> : public field<256, CHAR_BIT> {
                typedef field<256, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const modulus_type modulus =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_cppui256;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<params<secp_k1_scalar_field<256, CHAR_BIT>>>
                    value_type;

                constexpr static const std::size_t arity = 1;
            };

            constexpr typename secp_k1_scalar_field<160, CHAR_BIT>::modulus_type const
                secp_k1_scalar_field<160, CHAR_BIT>::modulus;
            constexpr typename secp_r1_scalar_field<160, CHAR_BIT>::modulus_type const
                secp_r1_scalar_field<160, CHAR_BIT>::modulus;
            constexpr typename secp_r2_scalar_field<160, CHAR_BIT>::modulus_type const
                secp_r2_scalar_field<160, CHAR_BIT>::modulus;
            constexpr typename secp_k1_scalar_field<192, CHAR_BIT>::modulus_type const
                secp_k1_scalar_field<192, CHAR_BIT>::modulus;
            constexpr typename secp_r1_scalar_field<192, CHAR_BIT>::modulus_type const
                secp_r1_scalar_field<192, CHAR_BIT>::modulus;
            constexpr typename secp_k1_scalar_field<224, CHAR_BIT>::modulus_type const
                secp_k1_scalar_field<224, CHAR_BIT>::modulus;
            constexpr typename secp_r1_scalar_field<224, CHAR_BIT>::modulus_type const
                secp_r1_scalar_field<224, CHAR_BIT>::modulus;
            constexpr typename secp_k1_scalar_field<256, CHAR_BIT>::modulus_type const
                secp_k1_scalar_field<256, CHAR_BIT>::modulus;

            constexpr typename secp_k1_scalar_field<160, CHAR_BIT>::generator_type const
                secp_k1_scalar_field<160, CHAR_BIT>::mul_generator;
            constexpr typename secp_r1_scalar_field<160, CHAR_BIT>::generator_type const
                secp_r1_scalar_field<160, CHAR_BIT>::mul_generator;
            constexpr typename secp_r2_scalar_field<160, CHAR_BIT>::generator_type const
                secp_r2_scalar_field<160, CHAR_BIT>::mul_generator;
            constexpr typename secp_k1_scalar_field<192, CHAR_BIT>::generator_type const
                secp_k1_scalar_field<192, CHAR_BIT>::mul_generator;
            constexpr typename secp_r1_scalar_field<192, CHAR_BIT>::generator_type const
                secp_r1_scalar_field<192, CHAR_BIT>::mul_generator;
            constexpr typename secp_k1_scalar_field<224, CHAR_BIT>::generator_type const
                secp_k1_scalar_field<224, CHAR_BIT>::mul_generator;
            constexpr typename secp_r1_scalar_field<224, CHAR_BIT>::generator_type const
                secp_r1_scalar_field<224, CHAR_BIT>::mul_generator;
            constexpr typename secp_k1_scalar_field<256, CHAR_BIT>::generator_type const
                secp_k1_scalar_field<256, CHAR_BIT>::mul_generator;

            template<std::size_t ModulusBits = 160, std::size_t GeneratorBits = CHAR_BIT>
            using secp_k1_fr = secp_k1_scalar_field<ModulusBits, GeneratorBits>;
            template<std::size_t ModulusBits = 160, std::size_t GeneratorBits = CHAR_BIT>
            using secp_r1_fr = secp_r1_scalar_field<ModulusBits, GeneratorBits>;
            template<std::size_t ModulusBits = 160, std::size_t GeneratorBits = CHAR_BIT>
            using secp_r2_fr = secp_r2_scalar_field<ModulusBits, GeneratorBits>;
            template<std::size_t ModulusBits = 192, std::size_t GeneratorBits = CHAR_BIT>
            using secp_k1_fr = secp_k1_scalar_field<ModulusBits, GeneratorBits>;
            template<std::size_t ModulusBits = 192, std::size_t GeneratorBits = CHAR_BIT>
            using secp_r1_fr = secp_r1_scalar_field<ModulusBits, GeneratorBits>;
            template<std::size_t ModulusBits = 224, std::size_t GeneratorBits = CHAR_BIT>
            using secp_k1_fr = secp_k1_scalar_field<ModulusBits, GeneratorBits>;
            template<std::size_t ModulusBits = 224, std::size_t GeneratorBits = CHAR_BIT>
            using secp_r1_fr = secp_r1_scalar_field<ModulusBits, GeneratorBits>;
            template<std::size_t ModulusBits = 256, std::size_t GeneratorBits = CHAR_BIT>
            using secp_k1_fr = secp_k1_scalar_field<ModulusBits, GeneratorBits>;

        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_SECP_SCALAR_FIELD_HPP
