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

#include <nil/algebra/fields/bn128/base_field.hpp>
#include <nil/algebra/fields/bn128/scalar_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<bn128_base_field<ModulusBits, GeneratorBits>>
                : public params<bn128_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<bn128_base_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x183227397098D014DC2822DB40C0AC2ECBC0B548B438E5469E10460B6C3E7EA3_cppui254;
            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<fp2<bl12_base_field<ModulusBits, GeneratorBits>>>
                : public params<bl12_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<bl12_base_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<bn128_scalar_field<ModulusBits, GeneratorBits>>
                : public params<bn128_scalar_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<bn128_scalar_field<ModulusBits, GeneratorBits>> policy_type;

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
