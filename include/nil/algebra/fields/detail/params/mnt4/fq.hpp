//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_MNT4_FQ_PARAMS_HPP
#define ALGEBRA_FIELDS_MNT4_FQ_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/fields/mnt4/fq.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct arithmetic_params<mnt4_fq<ModulusBits, GeneratorBits>> : public params<mnt4_fq<ModulusBits, GeneratorBits>> {
                private:
                    typedef params<mnt4_fq<ModulusBits, GeneratorBits>> policy_type;
                    typedef arithmetic_params<mnt4_fq<ModulusBits, GeneratorBits>> element_policy_type;
                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type q =
                        0x1DE7BDE6A39D133124ED3D82A47657764B1AE89987520D4F1AF2890070964866B2D38B30000_cppui297;

                    constexpr static const modulus_type q2 =
                        0x6FCA59D085672643469AF74C5C58E6A2A78D1A6BEF46259B6308A20619652FE76EE42CF5090E067AAEE541DED7D53794C0321FFC39B6C85F1141FE5DFEF4D47501FA0040670AC71660000_cppui595;

                    typedef element_fp<element_policy_type> fp2_non_residue_type;
                    typedef element_fp2<element_policy_type> fp4_non_residue_type;

                    constexpr static const modulus_type fp2_non_residue = modulus_type(0x11);
                    constexpr static const modulus_type fp4_non_residue = modulus_type(0x11);
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename params<mnt4_fq<ModulusBits, GeneratorBits>>::modulus_type const arithmetic_params<mnt4_fq<ModulusBits, GeneratorBits>>::fp2_non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename params<mnt4_fq<ModulusBits, GeneratorBits>>::modulus_type const arithmetic_params<mnt4_fq<ModulusBits, GeneratorBits>>::fp4_non_residue;
                
            }    // namespace detail
        }    // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_MNT4_FQ_PARAMS_HPP
