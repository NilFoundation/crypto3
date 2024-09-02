//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_COMPILE_CONTROL_HPP
#define MARSHALLING_COMPILE_CONTROL_HPP

#ifdef __GNUC__
#define GCC_DIAG_STR(s) #s
#define GCC_DIAG_JOINSTR(x, y) GCC_DIAG_STR(x##y)
#define GCC_DIAG_DO_PRAGMA(x) _Pragma(#x)
#define GCC_DIAG_PRAGMA(x) GCC_DIAG_DO_PRAGMA(GCC diagnostic x)
#define CC_DISABLE_WARNINGS()                      \
    GCC_DIAG_PRAGMA(push)                          \
    GCC_DIAG_PRAGMA(ignored "-Wpedantic")          \
    GCC_DIAG_PRAGMA(ignored "-Wctor-dtor-privacy") \
    GCC_DIAG_PRAGMA(ignored "-Wold-style-cast")

#define CC_ENABLE_WARNINGS() GCC_DIAG_PRAGMA(pop)

#else

#define CC_DISABLE_WARNINGS()
#define CC_ENABLE_WARNINGS()
#endif

#if !defined(CC_COMPILER_GCC47) && !defined(__clang__) && defined(__GNUC__) && (__GNUC__ == 4) && (__GNUC_MINOR__ < 8)
#define CC_COMPILER_GCC47
#endif

#endif    // MARSHALLING_COMPILE_CONTROL_HPP
