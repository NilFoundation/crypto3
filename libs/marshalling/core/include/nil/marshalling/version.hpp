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

/// @file
/// Contains version information of the library

#ifndef MARSHALLING_VERSION_HPP
#define MARSHALLING_VERSION_HPP

/// @brief Major verion of the library
#define MARSHALLING_MAJOR_VERSION 0U

/// @brief Minor verion of the library
#define MARSHALLING_MINOR_VERSION 27U

/// @brief Patch level of the library
#define MARSHALLING_PATCH_VERSION 0U

/// @brief Macro to create numeric version as single unsigned number
#define MARSHALLING_MAKE_VERSION(major_, minor_, patch_) ((major_) << 24) | ((minor_) << 8) | (patch_)

/// @brief Version of the Marshalling library as single numeric value
#define MARSHALLING_VERSION \
    MARSHALLING_MAKE_VERSION(MARSHALLING_MAJOR_VERSION, MARSHALLING_MINOR_VERSION, MARSHALLING_PATCH_VERSION)

#endif    // MARSHALLING_VERSION_HPP
