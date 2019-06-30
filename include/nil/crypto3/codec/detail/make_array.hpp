//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAKE_ARRAY_HPP
#define CRYPTO3_MAKE_ARRAY_HPP

#include <array>
#include <iterator>

namespace nil {
    namespace crypto3 {
        namespace codec {
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
                template<std::size_t N> using BuildIndices = typename build_indices<N>::type;

                template<typename Iterator> using ValueType = typename std::iterator_traits<Iterator>::value_type;

// internal overload with indices tag

                template<std::size_t... I, typename InputIterator,
                                           typename Array = std::array<ValueType<InputIterator>, sizeof...(I)>>

                Array make_array(InputIterator first, indices<I...>) {
                    return Array{{(void(I), *first++)...}};
                }
            }

            // externally visible interface
            template<std::size_t N, typename RandomAccessIterator>
            std::array<detail::ValueType<RandomAccessIterator>, N> make_array(RandomAccessIterator first,
                                                                              RandomAccessIterator last) {
                // last is not relevant if we're assuming the size is N
                // I'll assert it is correct anyway
                assert(last - first == N);
                return make_array(first, detail::BuildIndices<N>{});
            }
        }
    }
}

#endif //CRYPTO3_MAKE_ARRAY_HPP
