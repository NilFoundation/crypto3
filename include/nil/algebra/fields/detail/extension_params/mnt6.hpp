//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_MNT6_EXTENSION_PARAMS_HPP
#define ALGEBRA_FIELDS_MNT6_EXTENSION_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp3.hpp>

#include <nil/algebra/fields/params.hpp>
#include <nil/algebra/fields/mnt6/base_field.hpp>
#include <nil/algebra/fields/fp2.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                using namespace nil::algebra;

                template<typename FieldType>
                struct fp3_extension_params;

                template<typename FieldType>
                struct fp6_2over3_extension_params;

                /************************* MNT6 ***********************************/

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class fp3_extension_params<fields::mnt6_base_field<ModulusBits, GeneratorBits>>
                    : public params<fields::mnt6_base_field<ModulusBits, GeneratorBits>> {

                    typedef params<fields::mnt6_base_field<ModulusBits, GeneratorBits>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;
                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp<policy_type> non_residue_type;
                    typedef element_fp<policy_type> underlying_type;

                    constexpr static const std::size_t s = 0x22;
                    constexpr static const extended_modulus_type t =
                        0xD0F1EB0C5D321E87BF885ACDEBEDB4C0D6B30E63AB6E7BF6417A7990679AA640A7D58FB90CC708D572D32DFD6443366D2F92F48FF1A02FDB0CC11573BAB71F8E5E05B07DEA208A7E11F3E61C9968CC65F379EFCEF9472C7FC6DEE40194CA1DF9F801DC0D24656EACC72677B_cppui860;
                    constexpr static const extended_modulus_type t_minus_1_over_2 =
                        0x6878F5862E990F43DFC42D66F5F6DA606B598731D5B73DFB20BD3CC833CD532053EAC7DC8663846AB96996FEB2219B3697C97A47F8D017ED86608AB9DD5B8FC72F02D83EF510453F08F9F30E4CB46632F9BCF7E77CA3963FE36F7200CA650EFCFC00EE069232B75663933BD_cppui859;
                    constexpr static const std::array<modulus_type, 3> nqr = {0x05, 0x00, 0x00};
                    constexpr static const std::array<modulus_type, 3> nqr_to_t = 
                        {0x1366271F76AB41CEEEE8C1E5E972F3CEC14A25F18B3F4B93642FAD4972356D977470E0FA674_cppui297, 0x00, 0x00};

                    constexpr static const modulus_type non_residue = modulus_type(0x05);
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                class fp6_2over3_extension_params<fields::mnt6_base_field<ModulusBits, GeneratorBits>>
                    : public params<fields::mnt6_base_field<ModulusBits, GeneratorBits>> {

                    typedef fields::mnt6_base_field<ModulusBits, GeneratorBits> field_type;
                    typedef params<field_type> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef element_fp<policy_type> non_residue_type;
                    typedef element_fp3<fp3_extension_params<field_type>> underlying_type;

                    constexpr static const modulus_type non_residue = modulus_type(0x05);
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::non_residue;
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp6_2over3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp6_2over3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename std::size_t const
                    fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::s;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                    fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::t;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::extended_modulus_type const
                    fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::t_minus_1_over_2;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::modulus_type, 3> const
                    fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::nqr;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::modulus_type, 3> const
                    fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::nqr_to_t;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::modulus;
                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename fp6_2over3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    fp6_2over3_extension_params<mnt6_base_field<ModulusBits, GeneratorBits>>::modulus;

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_MNT6_EXTENSION_PARAMS_HPP
