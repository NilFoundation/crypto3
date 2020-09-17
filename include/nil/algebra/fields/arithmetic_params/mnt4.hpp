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

                constexpr static const std::size_t s = 0x11;
                constexpr static const modulus_type t =
                    0x1DE7BDE6A39D133124ED3D82A47657764B1AE89987520D4F1AF2890070964866B2D38B3_cppui281;
                constexpr static const modulus_type t_minus_1_over_2 =
                    0xEF3DEF351CE899892769EC1523B2BBB258D744CC3A906A78D794480384B24335969C59_cppui280;
                constexpr static const modulus_type multiplicative_generator = 0x11;
                constexpr static const modulus_type root_of_unity = 
                    0x214431121152176339675F00F9D465A3C037F18735DB28205F2A5F57D155F151CEC101EEC43_cppui298;
                constexpr static const modulus_type nqr = 0x11;
                constexpr static const modulus_type nqr_to_t = 
                    0x214431121152176339675F00F9D465A3C037F18735DB28205F2A5F57D155F151CEC101EEC43_cppui298;
                constexpr static const modulus_type Rsquared = 
                    0x224F0918A341F32E014AD38D47B66BD7673318850E1A266A1ADBF2BC8930065ACEC5613D220_cppui298;
                constexpr static const modulus_type Rcubed = 
                    0x35B329C5C21DB492B899FB731B0626C4C908A5073171DE648C893BA7447A3FE093A2C77F995_cppui298;

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

                constexpr static const std::size_t s = 0x12;
                constexpr static const modulus_type t =
                    0x37E52CE842B39321A34D7BA62E2C735153C68D35F7A312CDB18451030CB297F3B772167A8487033D5772A0EF6BEA9BCA60190FFE1CDB642F88A0FF2EFF7A6A3A80FD00203385638B3_cppui578;
                constexpr static const modulus_type t_minus_1_over_2 =
                    0x1BF296742159C990D1A6BDD3171639A8A9E3469AFBD18966D8C2288186594BF9DBB90B3D4243819EABB95077B5F54DE5300C87FF0E6DB217C4507F977FBD351D407E801019C2B1C59_cppui577;
                constexpr static const modulus_type nqr = {0x08, 0x01};
                constexpr static const modulus_type nqr_to_t = 
                    {0x00, 0x3B1F45391287A9CB585B8E5504C24BF1EC2010553885078C85899ACD708205080134A9BE6A_cppui294};

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

                constexpr static const std::size_t s = 0x22;
                constexpr static const modulus_type t =
                    0xEF3DEF351CE899892769EC1523B2BBB258D73D10653ED25301E4975AB4EED0CD29_cppui264;
                constexpr static const modulus_type t_minus_1_over_2 =
                    0x779EF79A8E744CC493B4F60A91D95DD92C6B9E88329F692980F24BAD5A77686694_cppui263;
                constexpr static const modulus_type multiplicative_generator = 0x0A;
                constexpr static const modulus_type root_of_unity = 
                    0xF29386B6F08DFECE98F8AA2954E2CF8650D75AE5D90488A8934C1AA0BB321B07D3B48F8379_cppui296;
                constexpr static const modulus_type nqr = 0x05;
                constexpr static const modulus_type nqr_to_t = 
                    0x330D0653B5BA46A85FC6D3958E16DA566E30E50010AAC4A990E4047A12E2043EE3EF848E190_cppui298;
                constexpr static const modulus_type Rsquared = 
                    0x149BB44A34202FF00DCED8E4B6D4BBD6DCF1E3A8386034F9102ADB68371465A743C68E0596B_cppui297;
                constexpr static const modulus_type Rcubed = 
                    0x1A0B411C083B440F6A9ED2947CEAC13907BAB5D43C2F687B031B7F0B2B9B6DE2F1B99BD9C4B_cppui297;

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
