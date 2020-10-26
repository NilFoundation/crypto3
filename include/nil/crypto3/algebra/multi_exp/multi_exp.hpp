//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Pavel Kharitonov <ipavrus@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_MULTI_EXP_HPP
#define CRYPTO3_ALGEBRA_MULTI_EXP_HPP

#include <boost/algebra/multi_exp/detail/multi_exp.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            //TODO: Implement not only for vectors
            template<typename NumberType, typename FieldType, typename detail::multi_exp_method Method>
            NumberType multi_exp(typename std::vector<NumberType>::const_iterator vec_start,
                        typename std::vector<NumberType>::const_iterator vec_end,
                        typename std::vector<FieldType>::const_iterator scalar_start,
                        typename std::vector<FieldType>::const_iterator scalar_end,
                        const std::size_t chunks_count) {

                const std::size_t total_size = std::distance(vec_start, vec_end);

                if ((total_size < chunks_count) || (chunks_count == 1)) {
                    // no need to split into "chunks_count", can call implementation directly
                    return detail::multi_exp_inner<T, FieldType, Method>(
                        vec_start, vec_end, scalar_start, scalar_end);
                }

                const std::size_t one_chunk_size = total_size/chunks_count;

                NumberType result = NumberType::zero();

                for (std::size_t i = 0; i < chunks_count; ++i) {
                    result = result + detail::multi_exp_inner<T, FieldType, Method>(
                         vec_start + i*one,
                         (i == chunks_count-1 ? vec_end : vec_start + (i+1)*one),
                         scalar_start + i*one,
                         (i == chunks_count-1 ? scalar_end : scalar_start + (i+1)*one));
                }

                return result;
            }

            template <typename FieldType>
            FieldType inner_product(typename std::vector<FieldType>::const_iterator a_start,
                            typename std::vector<FieldType>::const_iterator a_end,
                            typename std::vector<FieldType>::const_iterator b_start,
                            typename std::vector<FieldType>::const_iterator b_end) {
                return multi_exp<FieldType, FieldType, detail::multi_exp_method_naive_plain>(
                    a_start, a_end,
                    b_start, b_end, 1);
            }

        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_MULTI_EXP_HPP
