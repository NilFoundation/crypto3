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

#ifndef MARSHALLING_BASE_DETECTION_HPP
#define MARSHALLING_BASE_DETECTION_HPP

#if __cplusplus < 201402L

#ifdef __clang__
#define MARSHALLING_MUST_DEFINE_BASE
#endif

#if !defined(MARSHALLING_MUST_DEFINE_BASE) && defined(__GNUC__)
#if __GNUC__ < 5
#define MARSHALLING_MUST_DEFINE_BASE
#endif    // #if __GNUC__ < 5
#endif    // #if !defined(MARSHALLING_MUST_DEFINE_BASE) && defined(__GNUC__)

#endif    // #if __cplusplus < 201402L
#endif    // MARSHALLING_BASE_DETECTION_HPP
