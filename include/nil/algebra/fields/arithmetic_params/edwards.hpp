//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_EDWARDS_ARITHMETIC_PARAMS_HPP
#define ALGEBRA_FIELDS_EDWARDS_ARITHMETIC_PARAMS_HPP

#include <nil/algebra/fields/params.hpp>

#include <nil/algebra/fields/fp3.hpp>
#include <nil/algebra/fields/edwards/base_field.hpp>
#include <nil/algebra/fields/edwards/scalar_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<edwards_base_field<ModulusBits, GeneratorBits>>
                : public params<edwards_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<edwards_base_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const std::size_t s = 0x1F;
                constexpr static const modulus_type t =
                    0x81ABF93A5472B62717249DAC685A836DD6D217_cppui152;
                constexpr static const modulus_type t_minus_1_over_2 =
                    0x40D5FC9D2A395B138B924ED6342D41B6EB690B_cppui151;
                constexpr static const modulus_type arithmetic_generator = 0x00;
                constexpr static const modulus_type geometric_generator = 0x00;
                constexpr static const modulus_type multiplicative_generator = 0x3D;
                constexpr static const modulus_type root_of_unity = 
                    0x30FEC8F966ACFB3EC66B728E26AE7A5C00AAE9A96D8FE8_cppui182;
                constexpr static const modulus_type nqr = 0x17;
                constexpr static const modulus_type nqr_to_t = 
                    0x1B6CA5BFFDB95045F86768636493E1C6488D1BD4605D82_cppui181;
                constexpr static const modulus_type Rsquared = 
                    0x3E0DBC8EEC1F76E0BF35FF926AC105F6D1824A80E54068_cppui182;
                constexpr static const modulus_type Rcubed = 
                    0xB4AC1B77CA0D59F20E4D04D7048823FE112E6248253AD_cppui180;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x206AFE4E951CAD89C5C9276B1A16A0DB75B485C0000000_cppui182;

            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<fp3<edwards_base_field<ModulusBits, GeneratorBits>>>
                : public params<edwards_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<edwards_base_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;
                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const std::size_t s = 0x1F;
                constexpr static const extended_modulus_type t =
                    0x8514C337908664095AA1E4077718C1F93B49FEBD3E1DE5A3BF284A7BC8C90EE457BC1D3D59409F6A8049FB3D3B1E20915D50941493A9E2B4B0685ACA3C9847645_cppui516;
                constexpr static const extended_modulus_type t_minus_1_over_2 =
                    0x428A619BC8433204AD50F203BB8C60FC9DA4FF5E9F0EF2D1DF94253DE46487722BDE0E9EACA04FB54024FD9E9D8F1048AEA84A0A49D4F15A58342D651E4C23B22_cppui515;
                constexpr static const std::array<modulus_type, 3> nqr = {0x17, 0x00, 0x00};
                constexpr static const std::array<modulus_type, 3> nqr_to_t = 
                    {0x118228ECB464A2F6EB8DACC18FA757E45B3989330150C_cppui177, 0x00, 0x00};

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const extended_modulus_type group_order =
                    0x214530CDE421990256A87901DDC6307E4ED27FAF4F877968EFCA129EF23243B915EF074F565027DAA0127ECF4EC788245754250524EA78AD2C1A16B28F2611D9140000000_cppui546;

            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<edwards_scalar_field<ModulusBits, GeneratorBits>>
                : public params<edwards_scalar_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<edwards_scalar_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const std::size_t s = 0x1F;
                constexpr static const modulus_type t =
                    0x206AFE4E951CAD89C5C927725C25983BCAA64F_cppui150;
                constexpr static const modulus_type t_minus_1_over_2 =
                    0x10357F274A8E56C4E2E493B92E12CC1DE55327_cppui149;
                constexpr static const modulus_type arithmetic_generator = 0x00;
                constexpr static const modulus_type geometric_generator = 0x00;
                constexpr static const modulus_type multiplicative_generator = 0x13;
                constexpr static const modulus_type root_of_unity = 
                    0x74269BCA66AFEC88761200401AECDBB2F967D2689CEE0_cppui179;
                constexpr static const modulus_type nqr = 0x0B;
                constexpr static const modulus_type nqr_to_t = 
                    0xDD9F9CD9D463B4BE2359BF98F83964B0CA0C9B9EB2CA9_cppui180;
                constexpr static const modulus_type Rsquared = 
                    0x67DC2BC868E4573FB10E45FEF0D1D70518837BA19AB13_cppui179;
                constexpr static const modulus_type Rcubed = 
                    0x96567C1A3452F0CC48A73504E02D6B598A5139B464B62_cppui180;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x81ABF93A5472B62717249DC9709660EF2A993C0000000_cppui181;

            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename arithmetic_params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                arithmetic_params<edwards_base_field<ModulusBits, GeneratorBits>>::group_order;
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename arithmetic_params<edwards_scalar_field<ModulusBits, GeneratorBits>>::modulus_type const
                arithmetic_params<edwards_scalar_field<ModulusBits, GeneratorBits>>::group_order;
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename arithmetic_params<fp3<edwards_base_field<ModulusBits, GeneratorBits>>>::modulus_type const
                arithmetic_params<fp3<edwards_base_field<ModulusBits, GeneratorBits>>>::group_order;

        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_EDWARDS_ARITHMETIC_PARAMS_HPP
