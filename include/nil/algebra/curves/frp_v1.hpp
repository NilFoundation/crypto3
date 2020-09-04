//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_FRP_V1_HPP
#define ALGEBRA_CURVES_FRP_V1_HPP

#include <nil/crypto3/algebra/curves/detail/element/curve_weierstrass.hpp>

#include <nil/algebra/fields/frp_v1/fq.hpp>
#include <nil/algebra/fields/frp_v1/fr.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            template<std::size_t PBits>
            struct frp_v1 { };

            template<>
            struct frp_v1<256> {
                constexpr static const std::size_t base_field_bits = 256;
                typedef fields::frp_v1_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 256;
                typedef fields::frp_v1_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                // typedef typename detail::element_curve_weierstrass<base_field_type::value_type> value_type;

                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;

                constexpr static const number_type a =
                    0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00_cppui256;
                constexpr static const number_type b =
                    0xEE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F_cppui256;
                constexpr static const number_type x =
                    0xB6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF_cppui256;
                constexpr static const number_type y =
                    0x6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB_cppui256;
            };
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_FRP_V1_HPP
