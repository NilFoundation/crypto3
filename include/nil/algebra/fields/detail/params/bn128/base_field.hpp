//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BN128_FQ_PARAMS_HPP
#define ALGEBRA_FIELDS_BN128_FQ_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/fields/bn128/base_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct extension_params<bn128_base_field<ModulusBits, GeneratorBits>>
                    : public params<bn128_base_field<ModulusBits, GeneratorBits>> {
                private:
                    typedef params<bn128_base_field<ModulusBits, GeneratorBits>> policy_type;
                    typedef extension_params<bn128_base_field<ModulusBits, GeneratorBits>> element_policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x183227397098D014DC2822DB40C0AC2ECBC0B548B438E5469E10460B6C3E7EA3_cppui254;

                    typedef element_fp<element_policy_type> fp2_non_residue_type;
                    typedef element_fp2<element_policy_type> fp6_3over2_non_residue_type;
                    typedef element_fp2<element_policy_type> fp12_2over3over2_non_residue_type;

                    constexpr static const modulus_type fp2_non_residue =
                        modulus_type(0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254);
                    constexpr static const std::array<modulus_type, 2> fp6_3over2_non_residue = {9, 1};
                    constexpr static const std::array<modulus_type, 2> fp12_2over3over2_non_residue = {9, 1};
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename params<bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::fp2_non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename params<bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::fp6_3over2_non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename params<bn128_base_field<ModulusBits, GeneratorBits>>::modulus_type, 2> const
                    extension_params<bn128_base_field<ModulusBits, GeneratorBits>>::fp12_2over3over2_non_residue;

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BN128_FQ_PARAMS_HPP
