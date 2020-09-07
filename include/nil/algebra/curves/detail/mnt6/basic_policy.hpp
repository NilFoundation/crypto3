//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_MNT6_BASIC_POLICY_HPP
#define ALGEBRA_CURVES_MNT6_BASIC_POLICY_HPP

#include <nil/algebra/fields/mnt6/fq.hpp>
#include <nil/algebra/fields/mnt6/fr.hpp>
#include <nil/algebra/fields/detail/params/mnt6/fq.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace algebra;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt6_basic_policy { };

                template<>
                struct mnt6_basic_policy<298, CHAR_BIT> {
                    constexpr static const std::size_t base_field_bits = 298;
                    typedef fields::mnt6_fq<base_field_bits, CHAR_BIT> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 298;
                    typedef fields::mnt6_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    constexpr static const number_type p = base_field_modulus;
                    constexpr static const number_type q = scalar_field_modulus;

                    constexpr static const number_type a = number_type(0x0B);
                    constexpr static const number_type b = number_type(
                        0xD68C7B1DC5DD042E957B71C44D3D6C24E683FC09B420B1A2D263FDE47DDBA59463D0C65282_cppui296);
                    constexpr static const number_type x = 0x00;    //?
                    constexpr static const number_type y = 0x00;    //?
                };

                constexpr
                    typename mnt6_basic_policy<298, CHAR_BIT>::number_type const mnt6_basic_policy<298, CHAR_BIT>::a;

                constexpr
                    typename mnt6_basic_policy<298, CHAR_BIT>::number_type const mnt6_basic_policy<298, CHAR_BIT>::b;

                constexpr
                    typename mnt6_basic_policy<298, CHAR_BIT>::number_type const mnt6_basic_policy<298, CHAR_BIT>::p;

                constexpr
                    typename mnt6_basic_policy<298, CHAR_BIT>::number_type const mnt6_basic_policy<298, CHAR_BIT>::q;

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_MNT6_BASIC_POLICY_HPP