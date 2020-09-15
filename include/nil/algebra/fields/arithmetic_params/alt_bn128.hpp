//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BN128_ARITHMETIC_PARAMS_HPP
#define ALGEBRA_FIELDS_BN128_ARITHMETIC_PARAMS_HPP

#include <nil/algebra/fields/params.hpp>

#include <nil/algebra/fields/alt_bn128/base_field.hpp>
#include <nil/algebra/fields/alt_bn128/scalar_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<alt_bn128_base_field<ModulusBits, GeneratorBits>>
                : public params<alt_bn128_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<alt_bn128_base_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x183227397098D014DC2822DB40C0AC2ECBC0B548B438E5469E10460B6C3E7EA3_cppui254;
            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<fp2<alt_bn128_base_field<ModulusBits, GeneratorBits>>>
                : public params<alt_bn128_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<alt_bn128_base_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x492E25C3B1E5FCE2CCD37BE01A4690E5805C2A88B1BAB031376FD2E1A6359C682344F4ABD09216425280C4E36CB656E5301039684F560809DAA2C5113AEB4D8_cppui507;
            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<alt_bn128_scalar_field<ModulusBits, GeneratorBits>>
                : public params<alt_bn128_scalar_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<alt_bn128_scalar_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x183227397098D014DC2822DB40C0AC2E9419F4243CDCB848A1F0FAC9F8000000_cppui254;
            };

        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BN128_ARITHMETIC_PARAMS_HPP
