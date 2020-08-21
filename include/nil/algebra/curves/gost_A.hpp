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

#include <nil/crypto3/algebra/curves/curve_weierstrass.hpp>
#include <nil/crypto3/algebra/curves/detail/element/gost_A.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
        
            template<std::size_t PBits>
            struct gost_A : public curve_weierstrass<PBits> {};

            template<>
            struct gost_A<256> : public curve_weierstrass<256> {
                typedef typename curve_weierstrass<256>::number_type number_type;

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
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_GOST_A_HPP
