//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_MNT4_HPP
#define ALGEBRA_CURVES_MNT4_HPP

#include <nil/algebra/curves/detail/element/curve_weierstrass.hpp>
#include <nil/algebra/curves/detail/params/params.hpp>
#include <nil/algebra/curves/detail/mnt4/g1.hpp>
#include <nil/algebra/curves/detail/mnt4/g2.hpp>

#include <nil/algebra/fields/mnt4/fq.hpp>
#include <nil/algebra/fields/mnt4/fr.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            using namespace algebra;

            /*
                The curve equation for a BN curve is:

                E/Fp: y^2 = x^3 + b.
            */

            /*
                Over Fp12_2over3over2
                y^2 = x^3 + b
                u^2 = -1
                xi = xi_a + xi_b u
                v^3 = xi
                w^2 = v
            */
            template<std::size_t ModulusBits>
            struct mnt4 { };

            template<>
            struct mnt4<254> {
                constexpr static const std::size_t base_field_bits = 254;
                typedef fields::mnt4_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 254;
                typedef fields::mnt4_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                typedef typename detail::element_curve_weierstrass<base_field_type::value_type> value_type;

                typedef typename detail::mnt4_g1<detail::pairing_params<mnt4<254>>> g1_type;
                typedef typename detail::mnt4_g2<detail::pairing_params<mnt4<254>>> g2_type;

                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;

                constexpr static const number_type a = 2;
                constexpr static const number_type b = 0x3545A27639415585EA4D523234FC3EDD2A2070A085C7B980F4E9CD21A515D4B0EF528EC0FD5_cppui298;
                constexpr static const number_type x = 0x09;
                constexpr static const number_type y = 0x01;
            };

        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_MNT4_HPP
