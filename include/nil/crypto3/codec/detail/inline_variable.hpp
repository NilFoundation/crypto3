//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_INLINE_VARIABLE_HPP
#define CRYPTO3_INLINE_VARIABLE_HPP

#define CRYPTO3_CXX_STD_14 201402L
#define CRYPTO3_CXX_STD_17 201703L

#if defined(_MSVC_LANG) && _MSVC_LANG > __cplusplus    // Older clangs define _MSVC_LANG < __cplusplus
#define CRYPTO3_CXX_VER _MSVC_LANG
#else
#define CRYPTO3_CXX_VER __cplusplus
#endif

#ifndef CRYPTO3_CXX17_INLINE_VARIABLES
#ifdef __cpp_inline_variables
#define CRYPTO3_CXX17_INLINE_VARIABLES __cpp_inline_variables
#else
#define CRYPTO3_CXX17_INLINE_VARIABLES (CRYPTO3_CXX_VER >= CRYPTO3_CXX_STD_17)
#endif
#endif

#ifdef CRYPTO3_CXX17_INLINE_VARIABLES
#define CRYPTO3_INLINE_VARIABLE(TYPE, NAME, VALUE) \
    constexpr static inline const TYPE NAME() {    \
        return TYPE VALUE;                         \
    }
#else
#define CRYPTO3_INLINE_VARIABLE(TYPE, NAME, VALUE) \
    struct NAME {                                  \
        inline TYPE const &operator()() const {    \
            static TYPE const v VALUE;             \
            return v;                              \
        }                                          \
    };
#endif

#endif    // CRYPTO3_INLINE_VARIABLE_HPP
