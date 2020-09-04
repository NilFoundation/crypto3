//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_MNT6_HPP
#define ALGEBRA_CURVES_MNT6_HPP

#include <nil/algebra/curves/detail/mnt6/g1.hpp>
#include <nil/algebra/curves/detail/mnt6/g2.hpp>

#include <nil/algebra/fields/mnt6/fq.hpp>
#include <nil/algebra/fields/mnt6/fr.hpp>
#include <nil/algebra/curves/detail/params/mnt6/fq.hpp>

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
            struct mnt6 { };

            template<>
            struct mnt6<298> {
                constexpr static const std::size_t base_field_bits = 298;
                typedef fields::mnt6_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 298;
                typedef fields::mnt6_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                typedef typename detail::mnt6_g1<298> g1_type;
                typedef typename detail::mnt6_g2<298> g2_type;
                typedef typename nil::algebra::fields::detail::element_fp4<nil::algebra::fields::detail::arithmetic_params<mnt6<298, CHAR_BIT>>> gt_type;

                typedef std::vector<typename g1_type> g1_vector;
                typedef std::vector<typename g2_type> g2_vector;
                
                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;
            };

        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_MNT6_HPP
