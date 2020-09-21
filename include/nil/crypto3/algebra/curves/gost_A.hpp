//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_CURVES_GOST_A_HPP
#define CRYPTO3_ALGEBRA_CURVES_GOST_A_HPP

#include <nil/crypto3/algebra/fields/gost_A/base_field.hpp>
#include <nil/crypto3/algebra/fields/gost_A/scalar_field.hpp>

#include <nil/crypto3/algebra/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<std::size_t PBits>
                struct gost_A { };

                template<>
                struct gost_A<256> {
                    constexpr static const std::size_t base_field_bits = 256;
                    typedef fields::gost_A_fq<base_field_bits, CHAR_BIT> base_field_type;
                    typedef typename base_field_type::modulus_type number_type;
                    constexpr static const number_type base_field_modulus = base_field_type::modulus;

                    constexpr static const std::size_t scalar_field_bits = 256;
                    typedef fields::gost_A_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                    constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                    typedef typename detail::gost_A_g1<256> g1_type;
                    typedef typename detail::gost_A_g2<256> g2_type;

                    typedef typename fields::fp ? ? <base_field_type>::value_type gt_type;

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
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_CURVES_GOST_A_HPP
