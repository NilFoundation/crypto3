//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_ALT_BN128_BASIC_POLICY_HPP
#define ALGEBRA_CURVES_ALT_BN128_BASIC_POLICY_HPP

#include <nil/algebra/fields/alt_bn128/fq.hpp>
#include <nil/algebra/fields/alt_bn128/fr.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                using namespace algebra;

                template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
                struct alt_bn128_basic_policy { };

                template<>
                struct alt_bn128_basic_policy<254, CHAR_BIT> {
                    constexpr static const std::size_t base_field_bits = 254;
                    typedef fields::alt_bn128_fq<base_field_bits, CHAR_BIT> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type p = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 254;
                    typedef fields::alt_bn128_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                    constexpr static const number_type q = scalar_field_type::modulus;

                    constexpr static const number_type a = number_type(0x00);
                    constexpr static const number_type b = number_type(0x03);
                };

                constexpr
                    typename alt_bn128_basic_policy<254, CHAR_BIT>::number_type const alt_bn128_basic_policy<254, CHAR_BIT>::a;

                constexpr
                    typename alt_bn128_basic_policy<254, CHAR_BIT>::number_type const alt_bn128_basic_policy<254, CHAR_BIT>::b;

                constexpr
                    typename std::size_t const alt_bn128_basic_policy<254, CHAR_BIT>::base_field_bits;

                constexpr
                    typename std::size_t const alt_bn128_basic_policy<254, CHAR_BIT>::scalar_field_bits;

                constexpr
                    typename alt_bn128_basic_policy<254, CHAR_BIT>::number_type const alt_bn128_basic_policy<254, CHAR_BIT>::p;

                constexpr
                    typename alt_bn128_basic_policy<254, CHAR_BIT>::number_type const alt_bn128_basic_policy<254, CHAR_BIT>::q;

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_ALT_BN128_BASIC_POLICY_HPP