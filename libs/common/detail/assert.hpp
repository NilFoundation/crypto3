//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_ASSERT_HPP
#define CRYPTO3_DETAIL_ASSERT_HPP

#include <nil/crypto3/detail/type_traits.hpp>

#define CRYPTO3_DETAIL_ASSERT_FLOATING_POINT(T)                                                     \
    static_assert(std::is_floating_point<typename algebra::detail::remove_complex<T>::type>::value, \
                  "argument must be a (real or complex) floating point type");

#define CRYPTO3_DETAIL_ASSERT_INTEGRAL(T) \
    static_assert(std::is_integral<T>::value, "argument must be a real integral type");

#define CRYPTO3_DETAIL_ASSERT_VALID_COMPLEX(T)                                                          \
    static_assert(!algebra::detail::is_complex<T>::value ||                                             \
                      std::is_floating_point<typename algebra::detail::remove_complex<T>::type>::value, \
                  "invalid complex type argument (valid types are "                                     \
                  "complex<float>, complex<double>, and complex<long double>)");

#define CRYPTO3_DETAIL_ASSERT_ARITHMETIC(T)                                                     \
    CRYPTO3_DETAIL_ASSERT_VALID_COMPLEX(T)                                                      \
    static_assert(std::is_arithmetic<typename algebra::detail::remove_complex<T>::type>::value, \
                  "argument must be a (real or complex) arithmetic type");

#define CRYPTO3_DETAIL_ASSERT_REAL(T) \
    static_assert(std::is_arithmetic<T>::value, "argument must be a real arithmetic type");

#define CRYPTO3_DETAIL_ASSERT_COMPLEX(T)   \
    CRYPTO3_DETAIL_ASSERT_VALID_COMPLEX(T) \
    static_assert(algebra::detail::is_complex<T>::value, "argument must be a complex type");

#endif    // CRYPTO3_DETAIL_ASSERT_H_