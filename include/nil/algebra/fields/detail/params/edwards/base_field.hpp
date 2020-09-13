//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_EDWARDS_FQ_PARAMS_HPP
#define ALGEBRA_FIELDS_EDWARDS_FQ_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/fields/edwards/base_field.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct extension_params<edwards_base_field<ModulusBits, GeneratorBits>>
                    : public params<edwards_base_field<ModulusBits, GeneratorBits>> {
                private:
                    typedef params<edwards_base_field<ModulusBits, GeneratorBits>> policy_type;
                    typedef extension_params<edwards_base_field<ModulusBits, GeneratorBits>> element_policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x206AFE4E951CAD89C5C9276B1A16A0DB75B485C0000000_cppui182;

                    struct fp3{
                        constexpr static const modulus_type group_order =
                        0x214530CDE421990256A87901DDC6307E4ED27FAF4F877968EFCA129EF23243B915EF074F565027DAA0127ECF4EC788245754250524EA78AD2C1A16B28F2611D9140000000_cppui546;

                        typedef element_fp<element_policy_type> non_residue_type;

                        constexpr static const modulus_type non_residue = modulus_type(0x3D);
                    };

                    struct fp6_2over3{
                        typedef element_fp<element_policy_type> non_residue_type;

                        constexpr static const modulus_type non_residue = modulus_type(0x3D);
                    };
                };

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::fp3::non_residue;

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                constexpr typename params<edwards_base_field<ModulusBits, GeneratorBits>>::modulus_type const
                    extension_params<edwards_base_field<ModulusBits, GeneratorBits>>::fp6_2over3::non_residue;

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_EDWARDS_FQ_PARAMS_HPP
