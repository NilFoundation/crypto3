//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_BRAINPOOL_R1_SCALAR_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BRAINPOOL_R1_SCALAR_FIELD_HPP

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
                struct brainpool_r1_scalar_field : public field<ModulusBits, GeneratorBits> { };

                template<>
                struct brainpool_r1_scalar_field<160, CHAR_BIT> : public field<160, CHAR_BIT> {
                    typedef field<160, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus = 0xE95E4A5F737059DC60DF5991D45029409E60FC09_cppui160;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<brainpool_r1_scalar_field<160, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_scalar_field<192, CHAR_BIT> : public field<192, CHAR_BIT> {
                    typedef field<192, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xC302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1_cppui192;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<brainpool_r1_scalar_field<192, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_scalar_field<224, CHAR_BIT> : public field<224, CHAR_BIT> {
                    typedef field<224, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F_cppui224;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<brainpool_r1_scalar_field<224, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_scalar_field<256, CHAR_BIT> : public field<256, CHAR_BIT> {
                    typedef field<256, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7_cppui256;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<brainpool_r1_scalar_field<256, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_scalar_field<320, CHAR_BIT> : public field<320, CHAR_BIT> {
                    typedef field<320, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311_cppui320;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<brainpool_r1_scalar_field<320, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_scalar_field<384, CHAR_BIT> : public field<384, CHAR_BIT> {
                    typedef field<384, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565_cppui384;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<brainpool_r1_scalar_field<384, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_scalar_field<512, CHAR_BIT> : public field<512, CHAR_BIT> {
                    typedef field<512, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069_cppui512;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<brainpool_r1_scalar_field<512, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename brainpool_r1_scalar_field<160, CHAR_BIT>::modulus_type const
                    brainpool_r1_scalar_field<160, CHAR_BIT>::modulus;
                constexpr typename brainpool_r1_scalar_field<192, CHAR_BIT>::modulus_type const
                    brainpool_r1_scalar_field<192, CHAR_BIT>::modulus;
                constexpr typename brainpool_r1_scalar_field<224, CHAR_BIT>::modulus_type const
                    brainpool_r1_scalar_field<224, CHAR_BIT>::modulus;
                constexpr typename brainpool_r1_scalar_field<256, CHAR_BIT>::modulus_type const
                    brainpool_r1_scalar_field<256, CHAR_BIT>::modulus;
                constexpr typename brainpool_r1_scalar_field<320, CHAR_BIT>::modulus_type const
                    brainpool_r1_scalar_field<320, CHAR_BIT>::modulus;
                constexpr typename brainpool_r1_scalar_field<384, CHAR_BIT>::modulus_type const
                    brainpool_r1_scalar_field<384, CHAR_BIT>::modulus;
                constexpr typename brainpool_r1_scalar_field<512, CHAR_BIT>::modulus_type const
                    brainpool_r1_scalar_field<512, CHAR_BIT>::modulus;

                template<std::size_t ModulusBits = 160, std::size_t GeneratorBits = CHAR_BIT>
                using brainpool_r1_fr = brainpool_r1_scalar_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 192, std::size_t GeneratorBits = CHAR_BIT>
                using brainpool_r1_fr = brainpool_r1_scalar_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 224, std::size_t GeneratorBits = CHAR_BIT>
                using brainpool_r1_fr = brainpool_r1_scalar_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 256, std::size_t GeneratorBits = CHAR_BIT>
                using brainpool_r1_fr = brainpool_r1_scalar_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 320, std::size_t GeneratorBits = CHAR_BIT>
                using brainpool_r1_fr = brainpool_r1_scalar_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 384, std::size_t GeneratorBits = CHAR_BIT>
                using brainpool_r1_fr = brainpool_r1_scalar_field<ModulusBits, GeneratorBits>;
                template<std::size_t ModulusBits = 512, std::size_t GeneratorBits = CHAR_BIT>
                using brainpool_r1_fr = brainpool_r1_scalar_field<ModulusBits, GeneratorBits>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BRAINPOOL_R1_SCALAR_FIELD_HPP
