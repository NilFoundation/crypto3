//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_EDWARDS_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_EDWARDS_BASE_FIELD_HPP

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
                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                struct edwards_base_field : public field<ModulusBits, GeneratorBits> { };

                template<>
                struct edwards_base_field<183, CHAR_BIT> : public field<183, CHAR_BIT> {
                    typedef field<183, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus =
                        0x40D5FC9D2A395B138B924ED6342D41B6EB690B80000001_cppui183;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    constexpr static const generator_type mul_generator = 0x3D;

                    typedef typename detail::element_fp<params<edwards_base_field<183, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename edwards_base_field<183, CHAR_BIT>::modulus_type const
                    edwards_base_field<183, CHAR_BIT>::modulus;

                constexpr typename edwards_base_field<183, CHAR_BIT>::generator_type const
                    edwards_base_field<183, CHAR_BIT>::mul_generator;

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                using edwards_fq = edwards_base_field<ModulusBits, GeneratorBits>;

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                using edwards = edwards_base_field<ModulusBits, GeneratorBits>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_EDWARDS_BASE_FIELD_HPP
