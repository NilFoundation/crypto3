//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_FRP_V1_FQ_HPP
#define ALGEBRA_FIELDS_FRP_V1_FQ_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

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
            struct frp_v1_base_fields : public field<ModulusBits, GeneratorBits> { };

            template<>
            struct frp_v1_base_fields<256, CHAR_BIT> : public field<256, CHAR_BIT> {
                typedef field<256, CHAR_BIT> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus =
                    0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03_cppui256;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = 0x03;

                typedef typename detail::element_fp<detail::extension_params<frp_v1_base_fields<256, CHAR_BIT>>> value_type;

                constexpr static const std::size_t arity = 1;
            };

            constexpr typename frp_v1_base_fields<256, CHAR_BIT>::modulus_type const frp_v1_base_fields<256, CHAR_BIT>::modulus;

            constexpr typename frp_v1_base_fields<256, CHAR_BIT>::generator_type const frp_v1_base_fields<256, CHAR_BIT>::mul_generator;

            template<std::size_t ModulusBits = 256, std::size_t GeneratorBits = CHAR_BIT>
            using frp_v1_fq = frp_v1_base_field<ModulusBits, GeneratorBits>;

            template<std::size_t ModulusBits = 256, std::size_t GeneratorBits = CHAR_BIT>
            using frp_v1 = frp_v1_base_field<ModulusBits, GeneratorBits>;
        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FRP_V1_FQ_HPP
