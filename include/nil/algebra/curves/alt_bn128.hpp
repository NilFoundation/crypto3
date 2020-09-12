//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_ALT_BN128_HPP
#define ALGEBRA_CURVES_ALT_BN128_HPP

#include <nil/algebra/curves/detail/alt_bn128/basic_policy.hpp>
#include <nil/algebra/curves/detail/alt_bn128/g1.hpp>
#include <nil/algebra/curves/detail/alt_bn128/g2.hpp>

#include <nil/algebra/fields/detail/params/alt_bn128/base_field.hpp>
#include <nil/algebra/fields/fp12_2over3over2.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            using namespace algebra;

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            struct alt_bn128 { };

            template<>
            struct alt_bn128<254, CHAR_BIT> {

                using policy_type = detail::alt_bn128_basic_policy<254>;

                typedef typename policy_type::base_field_type base_field_type;
                typedef typename policy_type::scalar_field_type scalar_field_type;
                typedef typename policy_type::number_type number_type;

                constexpr static const std::size_t base_field_bits = policy_type::base_field_bits;
                constexpr static const number_type p = policy_type::p;

                constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_bits;
                constexpr static const number_type q = policy_type::q;

                typedef typename detail::alt_bn128_g1<base_field_bits, CHAR_BIT> g1_type;
                typedef typename detail::alt_bn128_g2<base_field_bits, CHAR_BIT> g2_type;

                typedef typename fields::fp12_2over3over2<base_field_type>::value_type gt_type;

                typedef std::vector<g1_type> g1_vector;
                typedef std::vector<g2_type> g2_vector;
            };

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            using alt_bn128_g1 = typename alt_bn128<ModulusBits, GeneratorBits>::g1_type;

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            using alt_bn128_g2 = typename alt_bn128<ModulusBits, GeneratorBits>::g2_type;

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            using alt_bn128_gt = typename alt_bn128<ModulusBits, GeneratorBits>::gt_type;

        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_ALT_BN128_HPP
