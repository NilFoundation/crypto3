//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DETAIL_UNBOUNDED_SHIFT_HPP
#define CRYPTO3_DETAIL_UNBOUNDED_SHIFT_HPP

#include <boost/assert.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {

            template<int N, typename T>
            struct unbounded_shifter {
                static T shl(T x) {
                    return unbounded_shifter<N - 1, T>::shl(T(x << 1));
                }

                static T shr(T x) {
                    return unbounded_shifter<N - 1, T>::shr(T(x >> 1));
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

            template<int N, typename T>
            T unbounded_shl(T x) {
                return unbounded_shifter<N, T>::shl(x);
            }

            template<int N, typename T>
            T unbounded_shr(T x) {
                return unbounded_shifter<N, T>::shr(x);
            }

            template<int N, typename T>
            T low_bits(T x) {
                T highmask = unbounded_shl<N, T>(~T());
                return T(x & ~highmask);
            }

        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CODEC_DETAIL_UNBOUNDED_SHIFT_HPP
