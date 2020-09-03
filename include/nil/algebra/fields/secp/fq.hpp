//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_SECP_FQ_HPP
#define ALGEBRA_FIELDS_SECP_FQ_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/fields/field.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            /*!
             * @brief IETF IPsec groups
             * @tparam ModulusBits
             * @tparam GeneratorBits
             */
            template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
            struct secp_k1_fq : public field<ModulusBits, GeneratorBits> { };

            template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
            struct secp_r1_fq : public field<ModulusBits, GeneratorBits> { };

            template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
            struct secp_r2_fq : public field<ModulusBits, GeneratorBits> { };

            template<>
            struct secp_k1_fq<160, CHAR_BIT> : public field<160, CHAR_BIT> {
                typedef field<160, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73_cppui160;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<detail::arithmetic_params<secp_k1_fq<160, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_r1_fq<160, CHAR_BIT> : public field<160, CHAR_BIT> {
                typedef field<160, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF_cppui160;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<detail::arithmetic_params<secp_r1_fq<160, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_r2_fq<160, CHAR_BIT> : public field<160, CHAR_BIT> {
                typedef field<160, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73_cppui160;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<detail::arithmetic_params<secp_r2_fq<160, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_k1_fq<192, CHAR_BIT> : public field<192, CHAR_BIT> {
                typedef field<192, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37_cppui192;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<detail::arithmetic_params<secp_k1_fq<192, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_r1_fq<192, CHAR_BIT> : public field<192, CHAR_BIT> {
                typedef field<192, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37_cppui192;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<detail::arithmetic_params<secp_r1_fq<192, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_k1_fq<224, CHAR_BIT> : public field<224, CHAR_BIT> {
                typedef field<224, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D_cppui224;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<detail::arithmetic_params<secp_k1_fq<224, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_r1_fq<224, CHAR_BIT> : public field<224, CHAR_BIT> {
                typedef field<224, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_cppui224;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<detail::arithmetic_params<secp_r1_fq<224, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<>
            struct secp_k1_fq<256, CHAR_BIT> : public field<256, CHAR_BIT> {
                typedef field<256, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_cppui256;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<detail::arithmetic_params<secp_k1_fq<256, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            constexpr typename secp_k1_fq<160, CHAR_BIT>::modulus_type const secp_k1_fq<160, CHAR_BIT>::modulus;
            constexpr typename secp_r1_fq<160, CHAR_BIT>::modulus_type const secp_r1_fq<160, CHAR_BIT>::modulus;
            constexpr typename secp_r2_fq<160, CHAR_BIT>::modulus_type const secp_r2_fq<160, CHAR_BIT>::modulus;
            constexpr typename secp_k1_fq<192, CHAR_BIT>::modulus_type const secp_k1_fq<192, CHAR_BIT>::modulus;
            constexpr typename secp_r1_fq<192, CHAR_BIT>::modulus_type const secp_r1_fq<192, CHAR_BIT>::modulus;
            constexpr typename secp_k1_fq<224, CHAR_BIT>::modulus_type const secp_k1_fq<224, CHAR_BIT>::modulus;
            constexpr typename secp_r1_fq<224, CHAR_BIT>::modulus_type const secp_r1_fq<224, CHAR_BIT>::modulus;
            constexpr typename secp_k1_fq<256, CHAR_BIT>::modulus_type const secp_k1_fq<256, CHAR_BIT>::modulus;

            constexpr typename secp_k1_fq<160, CHAR_BIT>::generator_type const secp_k1_fq<160, CHAR_BIT>::mul_generator;
            constexpr typename secp_r1_fq<160, CHAR_BIT>::generator_type const secp_r1_fq<160, CHAR_BIT>::mul_generator;
            constexpr typename secp_r2_fq<160, CHAR_BIT>::generator_type const secp_r2_fq<160, CHAR_BIT>::mul_generator;
            constexpr typename secp_k1_fq<192, CHAR_BIT>::generator_type const secp_k1_fq<192, CHAR_BIT>::mul_generator;
            constexpr typename secp_r1_fq<192, CHAR_BIT>::generator_type const secp_r1_fq<192, CHAR_BIT>::mul_generator;
            constexpr typename secp_k1_fq<224, CHAR_BIT>::generator_type const secp_k1_fq<224, CHAR_BIT>::mul_generator;
            constexpr typename secp_r1_fq<224, CHAR_BIT>::generator_type const secp_r1_fq<224, CHAR_BIT>::mul_generator;
            constexpr typename secp_k1_fq<256, CHAR_BIT>::generator_type const secp_k1_fq<256, CHAR_BIT>::mul_generator;

        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_SECP_FQ_HPP
