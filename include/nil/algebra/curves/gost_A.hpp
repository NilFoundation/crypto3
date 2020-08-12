//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_FF_CURVE_GOST_A_HPP
#define CRYPTO3_FF_CURVE_GOST_A_HPP

#include <memory>

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/algebra/curves/curve_gfp.hpp>

namespace nil {
    namespace algebra {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)
    
        template<std::size_t PBits>
        struct gost_A : public curve_weierstrass_policy<PBits> {};

        template<>
        struct gost_A<256> : public curve_weierstrass_policy<256> {
            typedef typename curve_weierstrass_policy<256>::number_type number_type;

            constexpr static const number_type p =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97_cppui256;
            constexpr static const number_type a =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94_cppui256;
            constexpr static const number_type b = 0xA6_cppui256;
            constexpr static const number_type x = 0x1_cppui256;
            constexpr static const number_type y =
                0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14_cppui256;
            constexpr static const number_type order =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893_cppui256;
        };
    }        // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_FF_CURVE_GOST_A_HPP
