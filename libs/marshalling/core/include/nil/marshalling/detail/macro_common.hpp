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

#ifndef MARSHALLING_MACRO_COMMON_HPP
#define MARSHALLING_MACRO_COMMON_HPP

#define MARSHALLING_EXPAND(x_) x_
#define MARSHALLING_CONCATENATE_(x_, y_) x_##y_
#define MARSHALLING_CONCATENATE(x_, y_) MARSHALLING_CONCATENATE_(x_, y_)

#define MARSHALLING_NUM_ARGS_(X, X64, X63, X62, X61, X60, X59, X58, X57, X56, X55, X54, X53, X52, X51, X50, X49, X48, \
                              X47, X46, X45, X44, X43, X42, X41, X40, X39, X38, X37, X36, X35, X34, X33, X32, X31,    \
                              X30, X29, X28, X27, X26, X25, X24, X23, X22, X21, X20, X19, X18, X17, X16, X15, X14,    \
                              X13, X12, X11, X10, X9, X8, X7, X6, X5, X4, X3, X2, X1, N, ...)                         \
    N
#define MARSHALLING_NUM_ARGS(...)                                                                                    \
    MARSHALLING_EXPAND(MARSHALLING_NUM_ARGS_(0, __VA_ARGS__, 64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, \
                                             50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, \
                                             32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, \
                                             14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0))

#if __cplusplus < 201402L
#define FUNC_AUTO_REF_RETURN(name_, ret_) auto name_()->ret_
#define FUNC_AUTO_REF_RETURN_CONST(name_, ret_) auto name_() const->ret_
#define FUNC_ARGS_AUTO_REF_RETURN(name_, args_, ret_) auto name_(args_)->ret_
#define FUNC_ARGS_AUTO_REF_RETURN_CONST(name_, args_, ret_) auto name_(args_) const->ret_
#else    // #if __cplusplus < 201402L
#define FUNC_AUTO_REF_RETURN(name_, ret_) decltype(auto) name_()
#define FUNC_AUTO_REF_RETURN_CONST(name_, ret_) decltype(auto) name_() const
#define FUNC_ARGS_AUTO_REF_RETURN(name_, args_, ret_) decltype(auto) name_(args_)
#define FUNC_ARGS_AUTO_REF_RETURN_CONST(name_, args_, ret_) decltype(auto) name_(args_) const
#endif    // #if __cplusplus < 201402L
#endif    // MARSHALLING_MACRO_COMMON_HPP
