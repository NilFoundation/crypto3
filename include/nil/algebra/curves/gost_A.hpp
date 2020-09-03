//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_GOST_A_HPP
#define ALGEBRA_CURVES_GOST_A_HPP

#include <nil/crypto3/algebra/curves/detail/element/curve_weierstrass.hpp>

#include <nil/algebra/fields/gost_A/fq.hpp>
#include <nil/algebra/fields/gost_A/fr.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            template<std::size_t PBits>
            struct gost_A { };

            template<>
            struct gost_A<256> {
                constexpr static const std::size_t base_field_bits = 256;
                typedef fields::frp_v1_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 256;
                typedef fields::frp_v1_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                // typedef typename detail::element_curve_weierstrass<base_field_type::value_type> value_type;

                typedef typename detail::gost_A_g1<256> g1_type;
                typedef typename detail::gost_A_g2<256> g2_type;
                typedef typename nil::algebra::fields::detail::element_fp ? ? <nil::algebra::fields::detail::
                                                                                   arithmetic_params<
                                                                                       gost_A_fq<256, CHAR_BIT>>>
                                                                                  gt_type;

                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;

                constexpr static const number_type a =
                    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94_cppui256;
                constexpr static const number_type b = 0xA6_cppui256;
                constexpr static const number_type x = 0x1_cppui256;
                constexpr static const number_type y =
                    0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14_cppui256;
            };
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_GOST_A_HPP
