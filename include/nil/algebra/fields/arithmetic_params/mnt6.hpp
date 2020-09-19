//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_MNT6_ARITHMETIC_PARAMS_HPP
#define ALGEBRA_FIELDS_MNT6_ARITHMETIC_PARAMS_HPP

#include <nil/algebra/fields/params.hpp>

#include <nil/algebra/fields/mnt6/base_field.hpp>
#include <nil/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/algebra/fields/fp3.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct arithmetic_params<mnt6_base_field<ModulusBits, GeneratorBits>>
                : public params<mnt6_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<mnt6_base_field<ModulusBits, GeneratorBits>> policy_type;

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
            struct arithmetic_params<fp3<mnt6_base_field<ModulusBits, GeneratorBits>>>
                : public params<mnt6_base_field<ModulusBits, GeneratorBits>> {
            private:
                typedef params<mnt6_base_field<ModulusBits, GeneratorBits>> policy_type;

            public:
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const std::size_t s = 0x22;
                constexpr static const modulus_type t =
                    0xD0F1EB0C5D321E87BF885ACDEBEDB4C0D6B30E63AB6E7BF6417A7990679AA640A7D58FB90CC708D572D32DFD6443366D2F92F48FF1A02FDB0CC11573BAB71F8E5E05B07DEA208A7E11F3E61C9968CC65F379EFCEF9472C7FC6DEE40194CA1DF9F801DC0D24656EACC72677B_cppui860;
                constexpr static const modulus_type t_minus_1_over_2 =
                    0x6878F5862E990F43DFC42D66F5F6DA606B598731D5B73DFB20BD3CC833CD532053EAC7DC8663846AB96996FEB2219B3697C97A47F8D017ED86608AB9DD5B8FC72F02D83EF510453F08F9F30E4CB46632F9BCF7E77CA3963FE36F7200CA650EFCFC00EE069232B75663933BD_cppui859;
                constexpr static const std::array<modulus_type, 3> nqr = {0x05, 0x00, 0x00};
                constexpr static const std::array<modulus_type, 3> nqr_to_t = 
                    {0x1366271F76AB41CEEEE8C1E5E972F3CEC14A25F18B3F4B93642FAD4972356D977470E0FA674_cppui297, 0x00, 0x00};

                constexpr static const modulus_type modulus = policy_type::modulus;
                constexpr static const modulus_type group_order =
                    0x1A1E3D618BA643D0F7F10B59BD7DB6981AD661CC756DCF7EC82F4F320CF354C814FAB1F72198E11AAE5A65BFAC8866CDA5F25E91FE3405FB619822AE7756E3F1CBC0B60FBD44114FC23E7CC3932D198CBE6F3DF9DF28E58FF8DBDC80329943BF3F003B81A48CADD598E4CEF600000000_cppui893;

            };

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            using  arithmetic_params<mnt6_scalar_field<ModulusBits, GeneratorBits>> = arithmetic_params<mnt4_base_field<ModulusBits, GeneratorBits>>;

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename arithmetic_params<mnt6_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                arithmetic_params<mnt6_base_field<ModulusBits, GeneratorBits>>::group_order;
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename arithmetic_params<mnt6_scalar_field<ModulusBits, GeneratorBits>>::modulus_type const
                arithmetic_params<mnt6_scalar_field<ModulusBits, GeneratorBits>>::group_order;
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            constexpr typename arithmetic_params<fp3<mnt6_base_field<ModulusBits, GeneratorBits>>>::modulus_type const
                arithmetic_params<fp3<mnt6_base_field<ModulusBits, GeneratorBits>>>::group_order;

        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_MNT6_ARITHMETIC_PARAMS_HPP
