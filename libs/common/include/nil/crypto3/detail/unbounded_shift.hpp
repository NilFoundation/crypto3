//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Alexander Sokolov <asokolov@nil.foundation>
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

#ifndef CRYPTO3_DETAIL_UNBOUNDED_SHIFT_HPP
#define CRYPTO3_DETAIL_UNBOUNDED_SHIFT_HPP

#include <boost/assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

            template<int Shift, typename T>
            struct unbounded_shifter {
                static T shl(T x) {
                    return unbounded_shifter<Shift - 1, T>::shl(T(x << 1));
                }

                static T shr(T x) {
                    return unbounded_shifter<Shift - 1, T>::shr(T(x >> 1));
                }
            };

            template<typename T>
            struct unbounded_shifter<0, T> {
                static T shl(T x) {
                    return x;
                }

                static T shr(T x) {
                    return x;
                }
            };

            template<int Shift, typename T>
            T unbounded_shl(T x) {
                return unbounded_shifter<Shift, T>::shl(x);
            }

            template<int Shift, typename T>
            T unbounded_shr(T x) {
                return unbounded_shifter<Shift, T>::shr(x);
            }

            template<typename T>
            T unbounded_shl(T x, std::size_t n) {
                if (sizeof(T) * CHAR_BIT <= n)
                    n %= sizeof(T) * CHAR_BIT;
                return x << n;
            }

            template<typename T>
            T unbounded_shr(T x, std::size_t n) {
                if (sizeof(T) * CHAR_BIT <= n)
                    return 0;
                return x >> n;
            }
            // FIXME: it wouldn't work when Shift == sizeof(T) * CHAR_BIT
            template<int Shift, typename T>
            T low_bits(T x) {
                if (sizeof(T) * CHAR_BIT <= Shift)
                    return x;
                T highmask = unbounded_shl<Shift, T>(~T());
                return T(x & ~highmask);
            }

            template<size_t Shift, std::size_t TypeBits, typename T>
            T low_bits(T x) {
                constexpr std::size_t real_shift = TypeBits - Shift;
                T lowmask = ((bool)Shift) * unbounded_shr<real_shift, T>(~T());
                return x & lowmask;
            }

            template<size_t type_bits, typename T>
            T low_bits(T x, std::size_t shift) {
                if (sizeof(T) * CHAR_BIT <= shift)
                    return x;
                T lowmask = ((bool)shift) * unbounded_shr<T>(~T(), type_bits - shift);
                return x & lowmask;
            }

            template<size_t type_bits, typename T>
            T high_bits(T x, std::size_t shift) {
                if (sizeof(T) * CHAR_BIT <= shift)
                    return x;
                T highmask = ((bool)shift) * unbounded_shl<T>(~T(), type_bits - shift);
                return x & highmask;
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_DETAIL_UNBOUNDED_SHIFT_HPP
