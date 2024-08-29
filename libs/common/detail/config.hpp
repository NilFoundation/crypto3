//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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
// @file This file is used to define various compiler-dependent attributes macros
// absent in Boost.Config until following PRs are accepted:
// https://github.com/boostorg/config/pull/338,
// https://github.com/boostorg/config/pull/339
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_CONFIG_HPP
#define CRYPTO3_DETAIL_CONFIG_HPP

#include <boost/config.hpp>

#ifdef BOOST_CLANG
#if (__clang_major__ >= 4 || (__clang_major__ >= 3 && __clang_minor__ >= 8))
#define BOOST_ATTRIBUTE_TARGET(isa) __attribute__((target(isa)))
#endif

#if defined(__clang__) && !defined(_MSC_VER)
#define BOOST_ATTRIBUTE_MALLOC_FUNCTION __attribute__((malloc))
#endif
#endif

#ifdef BOOST_GCC
#if (BOOST_GCC_VERSION >= 40800)
#define BOOST_ATTRIBUTE_TARGET(isa) __attribute__((target(isa)))
#endif

#define BOOST_ATTRIBUTE_MALLOC_FUNCTION __attribute__((malloc))
#endif

#if defined(_MSC_VER)
#define BOOST_ATTRIBUTE_MALLOC_FUNCTION __declspec(restrict)
#endif

#endif    // CRYPTO3_PREDEF_HPP
