//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_CONFIG_HPP
#define CRYPTO3_DETAIL_CONFIG_HPP

#include <boost/config.hpp>

#if (__clang_major__ >= 4 || (__clang_major__ >= 3 && __clang_minor__ >= 8))
#define BOOST_ATTRIBUTE_TARGET(isa) __attribute__((target(isa)))
#endif

#if defined(__clang__) && !defined(_MSC_VER)
#define BOOST_ATTRIBUTE_MALLOC_FUNCTION __attribute__((malloc))
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
