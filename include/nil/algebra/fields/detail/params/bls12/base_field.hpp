//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BLS12_FQ_PARAMS_HPP
#define ALGEBRA_FIELDS_BLS12_FQ_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/fields/bls12/base_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<>
                struct extension_params<bls12_base_field<381, CHAR_BIT>> : public params<bls12_base_field<381, CHAR_BIT>> {
                private:
                    typedef params<bls12_base_field<381, CHAR_BIT>> policy_type;
                    typedef extension_params<bls12_base_field<381, CHAR_BIT>> element_policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0xD0088F51CBFF34D258DD3DB21A5D66BB23BA5C279C2895FB39869507B587B120F55FFFF58A9FFFFDCFF7FFFFFFFD555_cppui380;

                    typedef element_fp<element_policy_type> fp2_non_residue_type;
                    typedef element_fp2<element_policy_type> fp6_3over2_non_residue_type;
                    typedef element_fp2<element_policy_type> fp12_2over3over2_non_residue_type;

                    constexpr static const modulus_type fp2_non_residue =
                        modulus_type(0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA_cppui381);
                    constexpr static const std::array<modulus_type, 2> fp6_3over2_non_residue = {1, 1};
                    constexpr static const std::array<modulus_type, 2> fp12_2over3over2_non_residue = {1, 1};
                };

                template<>
                struct extension_params<bls12_base_field<377, CHAR_BIT>> : public params<bls12_base_field<377, CHAR_BIT>> {
                private:
                    typedef params<bls12_base_field<377, CHAR_BIT>> policy_type;
                    typedef extension_params<bls12_base_field<377, CHAR_BIT>> element_policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0xD71D230BE28875631D82E03650A49D8D116CF9807A89C78F79B117DD04A4000B85AEA2180000004284600000000000_cppui376;

                    typedef element_fp<element_policy_type> fp2_non_residue_type;
                    typedef element_fp2<element_policy_type> fp6_3over2_non_residue_type;
                    typedef element_fp2<element_policy_type> fp12_2over3over2_non_residue_type;

                    constexpr static const modulus_type fp2_non_residue =
                        modulus_type(0x1AE3A4617C510EAC63B05C06CA1493B1A22D9F300F5138F1EF3622FBA094800170B5D44300000008508BFFFFFFFFFFC_cppui377);
                    constexpr static const std::array<modulus_type, 2> fp6_3over2_non_residue = {0, 1};
                    constexpr static const std::array<modulus_type, 2> fp12_2over3over2_non_residue = {0, 1};
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename params<bls12_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    extension_params<bls12_base_field<ModulusBits, GeneratorBits>>::fp2_non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename params<bls12_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    extension_params<bls12_base_field<ModulusBits, GeneratorBits>>::fp6_3over2_non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename params<bls12_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    extension_params<bls12_base_field<ModulusBits, GeneratorBits>>::fp12_2over3over2_non_residue;
            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BLS12_FQ_PARAMS_HPP
