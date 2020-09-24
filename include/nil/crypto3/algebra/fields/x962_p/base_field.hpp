//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_X962_P_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_X962_P_BASE_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief IETF IPsec groups
                 * @tparam ModulusBits
                 * @tparam GeneratorBits
                 */
                template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
                struct x962_p_v1_base_field : public field<ModulusBits, GeneratorBits> { };

                template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
                struct x962_p_v2_base_field : public field<ModulusBits, GeneratorBits> { };

                template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
                struct x962_p_v3_base_field : public field<ModulusBits, GeneratorBits> { };

                template<>
                struct x962_p_v2_base_field<192, CHAR_BIT> : public field<192, CHAR_BIT> {
                    typedef field<192, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus =
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF_cppui192;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    constexpr static const generator_type mul_generator = 0x03;

                    typedef typename detail::element_fp<params<x962_p_v2_base_field<192, CHAR_BIT>>> value_type;

constexpr static const std::size_t element_size = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct x962_p_v3_base_field<192, CHAR_BIT> : public field<192, CHAR_BIT> {
                    typedef field<192, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF_cppui192;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    constexpr static const generator_type mul_generator = 0x03;

                    typedef typename detail::element_fp<params<x962_p_v3_base_field<192, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t element_size = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct x962_p_v1_base_field<239, CHAR_BIT> : public field<239, CHAR_BIT> {
                    typedef field<239, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF_cppui239;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    constexpr static const generator_type mul_generator = 0x03;

                    typedef typename detail::element_fp<params<x962_p_v1_base_field<239, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t element_size = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct x962_p_v2_base_field<239, CHAR_BIT> : public field<239, CHAR_BIT> {
                    typedef field<239, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF_cppui239;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    constexpr static const generator_type mul_generator = 0x03;

                    typedef typename detail::element_fp<params<x962_p_v2_base_field<239, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t element_size = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct x962_p_v3_base_field<239, CHAR_BIT> : public field<239, CHAR_BIT> {
                    typedef field<239, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF_cppui239;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    constexpr static const generator_type mul_generator = 0x03;

                    typedef typename detail::element_fp<params<x962_p_v3_base_field<239, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t element_size = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename x962_p_v2_base_field<192, CHAR_BIT>::modulus_type const
                    x962_p_v2_base_field<192, CHAR_BIT>::modulus;
                constexpr typename x962_p_v3_base_field<192, CHAR_BIT>::modulus_type const
                    x962_p_v3_base_field<192, CHAR_BIT>::modulus;
                constexpr typename x962_p_v1_base_field<239, CHAR_BIT>::modulus_type const
                    x962_p_v1_base_field<239, CHAR_BIT>::modulus;
                constexpr typename x962_p_v2_base_field<239, CHAR_BIT>::modulus_type const
                    x962_p_v2_base_field<239, CHAR_BIT>::modulus;
                constexpr typename x962_p_v3_base_field<239, CHAR_BIT>::modulus_type const
                    x962_p_v3_base_field<239, CHAR_BIT>::modulus;

                constexpr typename x962_p_v2_base_field<192, CHAR_BIT>::generator_type const
                    x962_p_v1_base_field<192, CHAR_BIT>::mul_generator;
                constexpr typename x962_p_v3_base_field<192, CHAR_BIT>::generator_type const
                    x962_p_v3_base_field<192, CHAR_BIT>::mul_generator;
                constexpr typename x962_p_v1_base_field<239, CHAR_BIT>::generator_type const
                    x962_p_v1_base_field<239, CHAR_BIT>::mul_generator;
                constexpr typename x962_p_v2_base_field<239, CHAR_BIT>::generator_type const
                    x962_p_v2_base_field<239, CHAR_BIT>::mul_generator;
                constexpr typename x962_p_v3_base_field<239, CHAR_BIT>::generator_type const
                    x962_p_v3_base_field<239, CHAR_BIT>::mul_generator;

                template<std::size_t ModulusBits = 192, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v2_fq = x962_p_v2_base_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 192, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v3_fq = x962_p_v3_base_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 239, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v1_fq = x962_p_v1_base_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 239, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v2_fq = x962_p_v2_base_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 239, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v3_fq = x962_p_v3_base_field<ModulusBits, GeneratorBits>;

                template<std::size_t ModulusBits = 192, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v2 = x962_p_v2_base_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 192, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v3 = x962_p_v3_base_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 239, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v1 = x962_p_v1_base_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 239, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v2 = x962_p_v2_base_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 239, std::size_t GeneratorBits = CHAR_BIT>
                using x962_p_v3 = x962_p_v3_base_field<ModulusBits, GeneratorBits>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_X962_P_BASE_FIELD_HPP
