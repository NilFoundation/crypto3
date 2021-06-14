//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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
    constexpr static inline TYPE NAME() {          \
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
