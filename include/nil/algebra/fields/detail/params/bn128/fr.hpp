//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_BN128_FR_PARAMS_HPP
#define ALGEBRA_FIELDS_BN128_FR_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/fields/bn128/fr.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct arithmetic_params<bn128_fr<ModulusBits, GeneratorBits>> : public params<bn128_fr<ModulusBits, GeneratorBits>> {
                private:
                    typedef params<bn128_fr<ModulusBits, GeneratorBits>> policy_type;
                    typedef arithmetic_params<bn128_fr<ModulusBits, GeneratorBits>> element_policy_type;
                public:
                    typedef typename policy_type::number_type number_type;

                    constexpr static const number_type q =
                        0x183227397098D014DC2822DB40C0AC2E9419F4243CDCB848A1F0FAC9F8000000_cppui254;

                    typedef element_fp<element_policy_type> fp2_non_residue_type;
                    typedef element_fp2<element_policy_type> fp6_3over2_non_residue_type;
                    typedef element_fp2<element_policy_type> fp12_2over3over2_non_residue_type;

                    constexpr static const number_type fp2_non_residue = 
                        0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD46_cppui254;
                    constexpr static const std::array<number_type, 2> fp6_3over2_non_residue = {9, 1};
                    constexpr static const std::array<number_type, 2> fp12_2over3over2_non_residue = {9, 1};
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename params<bn128_fr<ModulusBits, GeneratorBits>>::number_type const arithmetic_params<bn128_fr<ModulusBits, GeneratorBits>>::fp2_non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename params<bn128_fr<ModulusBits, GeneratorBits>>::number_type, 2> const arithmetic_params<bn128_fr<ModulusBits, GeneratorBits>>::fp6_3over2_non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr std::array<typename params<bn128_fr<ModulusBits, GeneratorBits>>::number_type, 2> const arithmetic_params<bn128_fr<ModulusBits, GeneratorBits>>::fp12_2over3over2_non_residue;
            
            }    // namespace detail
        }    // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_BN128_FR_PARAMS_HPP
