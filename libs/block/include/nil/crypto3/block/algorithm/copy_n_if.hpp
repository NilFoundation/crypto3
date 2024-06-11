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
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_COPY_N_IF_HPP
