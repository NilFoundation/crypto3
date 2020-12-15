//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MAKE_ARRAY_HPP
#define CRYPTO3_MAKE_ARRAY_HPP

#include <array>
#include <iterator>

namespace nil {
    namespace crypto3 {
        namespace detail {
            template<std::size_t... Indices>
            struct indices {
                using next = indices<Indices..., sizeof...(Indices)>;
            };
            template<std::size_t N>
            struct build_indices {
                using type = typename build_indices<N - 1>::type::next;
            };
            template<>
            struct build_indices<0> {
                using type = indices<>;
            };
            template<std::size_t N>
            using BuildIndices = typename build_indices<N>::type;

            template<typename Iterator>
            using ValueType = typename std::iterator_traits<Iterator>::value_type;

            // internal overload with indices tag

            template<std::size_t... I,
                     typename InputIterator,
                     typename Array = std::array<ValueType<InputIterator>, sizeof...(I)>>

            Array make_array(InputIterator first, indices<I...>) {
                return Array {{(void(I), *first++)...}};
            }
        }    // namespace detail

        // externally visible interface
        template<std::size_t N, typename RandomAccessIterator>
        std::array<detail::ValueType<RandomAccessIterator>, N> make_array(RandomAccessIterator first,
                                                                          RandomAccessIterator last) {
            // last is not relevant if we're assuming the size is N
            // I'll assert it is correct anyway
            assert(last - first == N);
            return make_array(first, detail::BuildIndices<N> {});
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAKE_ARRAY_HPP
