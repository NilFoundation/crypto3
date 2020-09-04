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

#include <nil/algebra/curves/detail/mnt4/g1.hpp>
#include <nil/algebra/curves/detail/mnt4/g2.hpp>

#include <nil/algebra/fields/mnt4/fq.hpp>
#include <nil/algebra/fields/mnt4/fr.hpp>
#include <nil/algebra/curves/detail/params/mnt4/fq.hpp>

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
            struct mnt4<298> {
                constexpr static const std::size_t base_field_bits = 298;
                typedef fields::mnt4_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 298;
                typedef fields::mnt4_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                typedef typename detail::mnt4_g1<298> g1_type;
                typedef typename detail::mnt4_g2<298> g2_type;
                typedef typename nil::algebra::fields::detail::element_fp4<
                    nil::algebra::fields::detail::arithmetic_params<mnt4<298, CHAR_BIT>>>
                    gt_type;

                typedef std::vector<typename g1_type> g1_vector;
                typedef std::vector<typename g2_type> g2_vector;

                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;

            };

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            using mnt4_g1 = typename mnt4<ModulusBits, GeneratorBits>::g1_type;

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            using mnt4_g2 = typename mnt4<ModulusBits, GeneratorBits>::g2_type;

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            using mnt4_gt = typename mnt4<ModulusBits, GeneratorBits>::gt_type;

        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_MNT4_HPP
