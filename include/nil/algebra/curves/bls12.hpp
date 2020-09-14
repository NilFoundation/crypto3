//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BLS12_HPP
#define ALGEBRA_CURVES_BLS12_HPP

#include <nil/algebra/curves/detail/bls12/g1.hpp>
#include <nil/algebra/curves/detail/bls12/g2.hpp>

#include <nil/algebra/fields/fp12_2over3over2.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            /*
                E/Fp: y^2 = x^3 + 4.
            */

            template<std::size_t ModulusBits>
            struct bls12 { };

            template<>
            struct bls12<381> {

                using policy_type = detail::bls12_basic_policy<381>;

                typedef typename policy_type::base_field_type base_field_type;
                typedef typename policy_type::scalar_field_type scalar_field_type;
                typedef typename policy_type::number_type number_type;

                constexpr static const std::size_t base_field_bits = policy_type::base_field_bits;
                constexpr static const number_type p = policy_type::p;

                constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_bits;
                constexpr static const number_type q = policy_type::q;

                typedef typename detail::bls12_g1<base_field_bits> g1_type;
                typedef typename detail::bls12_g2<base_field_bits> g2_type;

                typedef typename fields::fp12_2over3over2<base_field_type>::value_type gt_type;
            };

            template<>
            struct bls12<377> {

                using policy_type = detail::bls12_basic_policy<377>;

                typedef typename policy_type::base_field_type base_field_type;
                typedef typename policy_type::scalar_field_type scalar_field_type;
                typedef typename policy_type::number_type number_type;

                constexpr static const std::size_t base_field_bits = policy_type::base_field_bits;
                constexpr static const number_type p = policy_type::p;

                constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_bits;
                constexpr static const number_type q = policy_type::q;

                typedef typename detail::bls12_g1<base_field_bits> g1_type;
                typedef typename detail::bls12_g2<base_field_bits> g2_type;

                typedef typename fields::fp12_2over3over2<base_field_type>::value_type gt_type;
            };

            typedef bls12<381> bls12_381;
            typedef bls12<377> bls12_377;
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_BLS12_381_HPP
