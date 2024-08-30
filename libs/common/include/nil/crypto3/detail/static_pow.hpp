//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_DETAIL_STATIC_POW_HPP
#define CRYPTO3_DETAIL_STATIC_POW_HPP

namespace nil {
    namespace crypto3 {
        namespace detail {
            template<typename T, typename U>
            constexpr T pow(T x, U n) {
                T result = 1;
                while (n > 0) {
                    if (n % 2 == 0) {
                        // n is even
                        x = x * x;
                        n = n / 2;
                    } else {
                        // n isn't even
                        result = result * x;
                        n = n - 1;
                    }
                }
                return result;
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // #ifndef CRYPTO3_DETAIL_STATIC_POW_HPP
