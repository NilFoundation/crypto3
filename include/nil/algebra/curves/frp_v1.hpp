//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FF_CURVE_FRP_V1_HPP
#define CRYPTO3_FF_CURVE_FRP_V1_HPP

#include <memory>

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/algebra/curves/curve_gfp.hpp>

namespace nil {
    namespace algebra {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)

        template<std::size_t PBits>
        struct frp_v1 : public curve_weierstrass_policy<PBits> {};

        template<>
        struct frp_v1<256> : public curve_weierstrass_policy<256> {
            typedef typename curve_weierstrass_policy<256>::number_type number_type;

            constexpr static const number_type p =
                0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C03_cppui256;
            constexpr static const number_type a =
                0xF1FD178C0B3AD58F10126DE8CE42435B3961ADBCABC8CA6DE8FCF353D86E9C00_cppui256;
            constexpr static const number_type b =
                0xEE353FCA5428A9300D4ABA754A44C00FDFEC0C9AE4B1A1803075ED967B7BB73F_cppui256;
            constexpr static const number_type x =
                0xB6B3D4C356C139EB31183D4749D423958C27D2DCAF98B70164C97A2DD98F5CFF_cppui256;
            constexpr static const number_type y =
                0x6142E0F7C8B204911F9271F0F3ECEF8C2701C307E8E4C9E183115A1554062CFB_cppui256;
            constexpr static const number_type order =
                0xF1FD178C0B3AD58F10126DE8CE42435B53DC67E140D2BF941FFDD459C6D655E1_cppui256;
        };
    }        // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_FF_CURVE_FRP_V1_HPP
