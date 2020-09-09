//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BLS12_HPP
#define ALGEBRA_CURVES_BLS12_HPP

#include <nil/algebra/curves/detail/bls12/g1.hpp>
#include <nil/algebra/curves/detail/bls12/g2.hpp>

#include <nil/algebra/fields/bls12/fq.hpp>
#include <nil/algebra/fields/bls12/fr.hpp>
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

                constexpr static const std::size_t base_field_bits = 381;
                typedef fields::bls12_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 381; // actually, 255
                typedef fields::bls12_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                typedef typename detail::bls12_g1<base_field_bits> g1_type;
                typedef typename detail::bls12_g2<base_field_bits> g2_type;

                typedef typename fields::fp12_2over3over2<base_field_type>::value_type gt_type;

                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;

                constexpr static const number_type a = 0;
                constexpr static const number_type b = 0x04;
            };

            template<>
            struct bls12<377> {

                constexpr static const std::size_t base_field_bits = 377;
                typedef fields::bls12_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 377; // actually, 253
                typedef fields::bls12_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                typedef typename detail::bls12_g1<base_field_bits> g1_type;
                typedef typename detail::bls12_g2<base_field_bits> g2_type;

                typedef typename fields::fp12_2over3over2<base_field_type>::value_type gt_type;

                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;

                constexpr static const number_type a = 0;
                constexpr static const number_type b = 0x01;
            };

            typedef bls12<381> bls12_381;
            typedef bls12<377> bls12_377;
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_BLS12_381_HPP
