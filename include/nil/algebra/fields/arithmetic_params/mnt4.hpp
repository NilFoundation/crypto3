//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_MNT4_ARITHMETIC_PARAMS_HPP
#define ALGEBRA_FIELDS_MNT4_ARITHMETIC_PARAMS_HPP

#include <nil/algebra/fields/params.hpp>

#include <nil/algebra/fields/mnt4/base_field.hpp>
#include <nil/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<mnt4_base_field<ModulusBits, GeneratorBits>>
                : public params<mnt4_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<mnt4_base_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x1DE7BDE6A39D133124ED3D82A47657764B1AE89987520D4F1AF2890070964866B2D38B30000_cppui297;

            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<fp2<mnt4_base_field<ModulusBits, GeneratorBits>>>
                : public params<mnt4_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<mnt4_base_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                0x6FCA59D085672643469AF74C5C58E6A2A78D1A6BEF46259B6308A20619652FE76EE42CF5090E067AAEE541DED7D53794C0321FFC39B6C85F1141FE5DFEF4D47501FA0040670AC71660000_cppui595;

            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<mnt4_scalar_field<ModulusBits, GeneratorBits>>
                : public params<mnt4_scalar_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<mnt4_scalar_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x1DE7BDE6A39D133124ED3D82A47657764B1AE7A20CA7DA4A603C92EB569DDA19A5200000000_cppui297;

            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename arithmetic_params<mnt4_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                arithmetic_params<mnt4_base_field<ModulusBits, GeneratorBits>>::group_order;
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename arithmetic_params<mnt4_scalar_field<ModulusBits, GeneratorBits>>::modulus_type const
                arithmetic_params<mnt4_scalar_field<ModulusBits, GeneratorBits>>::group_order;
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename arithmetic_params<fp2<mnt4_base_field<ModulusBits, GeneratorBits>>>::modulus_type const
                arithmetic_params<fp2<mnt4_base_field<ModulusBits, GeneratorBits>>>::group_order;

        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_MNT4_ARITHMETIC_PARAMS_HPP
