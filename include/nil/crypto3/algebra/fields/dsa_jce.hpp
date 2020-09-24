//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_DSA_JCE_HPP
#define CRYPTO3_ALGEBRA_FIELDS_DSA_JCE_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief DSA group
                 * @tparam ModulusBits
                 * @tparam GeneratorBits
                 */
                template<std::size_t ModulusBits, std::size_t GeneratorBits = ModulusBits>
                struct dsa_jce : public field<ModulusBits, GeneratorBits> { };

                template<>
                struct dsa_jce<1024, 1024> : public field<1024, 1024> {
                    typedef field<1024, 1024> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus =
                        0xFD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B6512669455D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B76B9950A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB83F6D3C51EC3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C7_cppui1024;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    constexpr static const generator_type mul_generator =
                        0x469603512E30278CD3947595DB22EEC9826A6322ADC97344F41D740C325724C8F9EFBAA7D4D803FF8C609DCD100EBC5BDFCFAD7C6A425FAEA786EA2050EBE98351EA1FDA1FDF24D6947AA6B9AA23766953802F4D7D4A8ECBA06D19768A2491FFB16D0EF9C43A99B5F71672FF6F0A24B444D0736D04D38A1A1322DAF6CDD88C9D_cppui1024;

                    typedef typename detail::element_fp<params<dsa_jce<modulus_bits, generator_bits>>> value_type;

                    constexpr static const std::size_t element_size = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename dsa_jce<1024, 1024>::modulus_type const dsa_jce<1024, 1024>::modulus;

                constexpr typename dsa_jce<1024, 1024>::generator_type const dsa_jce<1024, 1024>::mul_generator;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_DSA_JCE_HPP
