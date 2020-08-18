//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BN128_FR_HPP
#define ALGEBRA_FIELDS_BN128_FR_HPP

#include <nil/algebra/fields/detail/params/bn128/fr.hpp>
#include <nil/algebra/fields/fp.hpp>

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
            struct bn128_fr : public fp<ModulusBits, GeneratorBits> { };

            template <>
            struct bn128_fr<254, CHAR_BIT> : public fp<254, CHAR_BIT> {
                typedef fp<254, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus =
                    21888242871839275222246405745257275088548364400416034343698204186575808495617_cppui254;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type generator = 0x05;

                typedef typename detail::element_fp<detail::arithmetic_params<bn128_fr<254, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename bn128_fr<ModulusBits, GeneratorBits>::modulus_type const bn128_fr<ModulusBits, GeneratorBits>::modulus;

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename bn128_fr<ModulusBits, GeneratorBits>::generator_type const bn128_fr<ModulusBits, GeneratorBits>::mul_generator;

        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BN128_FR_HPP
