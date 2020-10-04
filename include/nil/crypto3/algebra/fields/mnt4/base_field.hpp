//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_MNT4_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_MNT4_BASE_FIELD_HPP

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
                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_base_field : public field<ModulusBits, GeneratorBits> { };

                template<>
                struct mnt4_base_field<298, CHAR_BIT> : public field<298, CHAR_BIT> {
                    typedef field<298, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus =
                        0x3BCF7BCD473A266249DA7B0548ECAEEC9635D1330EA41A9E35E51200E12C90CD65A71660001_cppui298;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<mnt4_base_field<298, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename std::size_t const
                    mnt4_base_field<298, CHAR_BIT>::modulus_bits;

                constexpr typename std::size_t const
                    mnt4_base_field<298, CHAR_BIT>::number_bits;

                constexpr typename std::size_t const
                    mnt4_base_field<298, CHAR_BIT>::value_bits;

                constexpr
                    typename mnt4_base_field<298, CHAR_BIT>::modulus_type const mnt4_base_field<298, CHAR_BIT>::modulus;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                using mnt4_fq = mnt4_base_field<ModulusBits, GeneratorBits>;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                using mnt4 = mnt4_base_field<ModulusBits, GeneratorBits>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_MNT4_BASE_FIELD_HPP
