//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BN128_HPP
#define ALGEBRA_CURVES_BN128_HPP

#include <nil/algebra/curves/detail/bn128/g1.hpp>
#include <nil/algebra/curves/detail/bn128/g2.hpp>

#include <nil/algebra/fields/bn128/fq.hpp>
#include <nil/algebra/fields/bn128/fr.hpp>
#include <nil/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/algebra/fields/detail/params/bn128/fq.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            using namespace nil::algebra;

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
            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            struct bn128 { };

            template<>
            struct bn128<254, CHAR_BIT> {
                constexpr static const std::size_t base_field_bits = 254;
                typedef fields::bn128_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 254;
                typedef fields::bn128_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                typedef typename detail::bn128_g1<254, CHAR_BIT> g1_type;
                typedef typename detail::bn128_g2<254, CHAR_BIT> g2_type;
                typedef typename nil::algebra::fields::detail::element_fp12_2over3over2<
                    fields::detail::arithmetic_params<fields::bn128_fq<254, CHAR_BIT>>>
                    gt_type;

                typedef std::vector<g1_type> g1_vector;
                typedef std::vector<g2_type> g2_vector;

                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;

                constexpr static const number_type a = 0;
                constexpr static const number_type b = 0x03;
                constexpr static const number_type x = 0x09;
                constexpr static const number_type y = 0x01;
            };

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            using bn128_g1 = typename bn128<ModulusBits, GeneratorBits>::g1_type;

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            using bn128_g2 = typename bn128<ModulusBits, GeneratorBits>::g2_type;

            template<std::size_t ModulusBits = 254, std::size_t GeneratorBits = CHAR_BIT>
            using bn128_gt = typename bn128<ModulusBits, GeneratorBits>::gt_type;

        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_BN128_HPP
