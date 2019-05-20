//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_COPY_N_IF_HPP
#define CRYPTO3_COPY_N_IF_HPP

namespace nil {
    namespace crypto3 {
        namespace block {
            /*!
             * @brief Combination of std::copy_n and std::copy_if algorithms
             * @tparam TInputIterator
             * @tparam TSize
             * @tparam TOutputIterator
             * @tparam TUnaryPredicate
             * @param i_begin
             * @param n
             * @param o_begin
             * @param predicate
             * @return
             */
            template<typename TInputIterator, typename TSize, typename TOutputIterator, typename TUnaryPredicate>
            TOutputIterator copy_n_if(TInputIterator i_begin, TSize n, TOutputIterator o_begin,
                                      TUnaryPredicate predicate) {
                while (n-- > 0) {
                    if (predicate(*i_begin)) {
                        *o_begin++ = *i_begin;
                    }

                    ++i_begin;
                }

                return o_begin;
            }
        }
    }
}

#endif //CRYPTO3_COPY_N_IF_HPP