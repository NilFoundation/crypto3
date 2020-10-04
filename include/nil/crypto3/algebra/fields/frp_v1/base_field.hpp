//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_FRP_V1_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_FRP_V1_BASE_FIELD_HPP

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
                struct frp_v1_base_fields : public field<ModulusBits, GeneratorBits> { };

                template<>
                struct frp_v1_base_fields<256, CHAR_BIT> : public field<256, CHAR_BIT> {
                    typedef field<256, CHAR_BIT> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus =
                        0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03_cppui256;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    typedef typename detail::element_fp<params<frp_v1_base_fields<256, CHAR_BIT>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename frp_v1_base_fields<256, CHAR_BIT>::modulus_type const
                    frp_v1_base_fields<256, CHAR_BIT>::modulus;

                template<std::size_t ModulusBits = 256, std::size_t GeneratorBits = CHAR_BIT>
                using frp_v1_fq = frp_v1_base_field<ModulusBits, GeneratorBits>;

                template<std::size_t ModulusBits = 256, std::size_t GeneratorBits = CHAR_BIT>
                using frp_v1 = frp_v1_base_field<ModulusBits, GeneratorBits>;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FRP_V1_BASE_FIELD_HPP
