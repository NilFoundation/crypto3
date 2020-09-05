//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_ASSERT_HPP
#define CRYPTO3_DETAIL_ASSERT_HPP

#include <nil/algebra/detail/type_traits.hpp>

#define CRYPTO3_DETAIL_ASSERT_FLOATING_POINT(T)                                                   \
    static_assert(std::is_floating_point<typename cotila::detail::remove_complex<T>::type>::value, \
                  "argument must be a (real or complex) floating point type");

#define CRYPTO3_DETAIL_ASSERT_INTEGRAL(T) \
    static_assert(std::is_integral<T>::value, "argument must be a real integral type");

#define CRYPTO3_DETAIL_ASSERT_VALID_COMPLEX(T)                                                        \
    static_assert(!cotila::detail::is_complex<T>::value ||                                             \
                      std::is_floating_point<typename cotila::detail::remove_complex<T>::type>::value, \
                  "invalid complex type argument (valid types are "                                    \
                  "complex<float>, complex<double>, and complex<long double>)");

#define CRYPTO3_DETAIL_ASSERT_ARITHMETIC(T)                                                   \
    CRYPTO3_DETAIL_ASSERT_VALID_COMPLEX(T)                                                    \
    static_assert(std::is_arithmetic<typename cotila::detail::remove_complex<T>::type>::value, \
                  "argument must be a (real or complex) arithmetic type");

#define CRYPTO3_DETAIL_ASSERT_REAL(T) \
    static_assert(std::is_arithmetic<T>::value, "argument must be a real arithmetic type");

#define CRYPTO3_DETAIL_ASSERT_COMPLEX(T)   \
    CRYPTO3_DETAIL_ASSERT_VALID_COMPLEX(T) \
    static_assert(cotila::detail::is_complex<T>::value, "argument must be a complex type");

#endif    // CRYPTO3_DETAIL_ASSERT_H_