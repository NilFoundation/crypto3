//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_MNT4_BASIC_POLICY_HPP
#define ALGEBRA_CURVES_MNT4_BASIC_POLICY_HPP

#include <nil/algebra/fields/mnt4/fq.hpp>
#include <nil/algebra/fields/mnt4/fr.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace algebra;

                template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
                struct mnt4_basic_policy { };

                template<>
                struct mnt4_basic_policy<298, CHAR_BIT> {
                    constexpr static const std::size_t base_field_bits = 298;
                    typedef fields::mnt4_fq<base_field_bits, CHAR_BIT> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type p = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 298;
                    typedef fields::mnt4_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                    constexpr static const number_type q = scalar_field_type::modulus;

                    constexpr static const number_type a = number_type(0x02);
                    constexpr static const number_type b = number_type(
                        0x3545A27639415585EA4D523234FC3EDD2A2070A085C7B980F4E9CD21A515D4B0EF528EC0FD5_cppui298);
                };

                constexpr
                    typename mnt4_basic_policy<298, CHAR_BIT>::number_type const mnt4_basic_policy<298, CHAR_BIT>::a;

                constexpr
                    typename mnt4_basic_policy<298, CHAR_BIT>::number_type const mnt4_basic_policy<298, CHAR_BIT>::b;

                constexpr typename std::size_t const mnt4_basic_policy<298, CHAR_BIT>::base_field_bits;

                constexpr typename std::size_t const mnt4_basic_policy<298, CHAR_BIT>::scalar_field_bits;

                constexpr
                    typename mnt4_basic_policy<298, CHAR_BIT>::number_type const mnt4_basic_policy<298, CHAR_BIT>::p;

                constexpr
                    typename mnt4_basic_policy<298, CHAR_BIT>::number_type const mnt4_basic_policy<298, CHAR_BIT>::q;

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_MNT4_BASIC_POLICY_HPP