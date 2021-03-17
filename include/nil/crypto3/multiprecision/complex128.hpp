///////////////////////////////////////////////////////////////////////////////
//  Copyright 2018 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_MP_COMPLEX128_HPP
#define BOOST_MP_COMPLEX128_HPP

#include <nil/crypto3/multiprecision/float128.hpp>
#include <nil/crypto3/multiprecision/complex_adaptor.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            typedef number<complex_adaptor<float128_backend>, et_off> complex128;

            template<>
            struct component_type<number<complex_adaptor<float128_backend>>> {
                typedef float128 type;
            };

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif
