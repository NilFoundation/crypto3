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

#ifndef BOOST_MULTIPRECISION_MULTIEXP_HPP
#define BOOST_MULTIPRECISION_MULTIEXP_HPP

#include <boost/algebra/fields/detail/fp.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace detail {

                enum multi_exp_method {
                 /**
                  * Naive multi-exponentiation individually multiplies each base by the
                  * corresponding scalar and adds up the results.
                  * multi_exp_method_naive uses opt_window_wnaf_exp for exponentiation,
                  * while multi_exp_method_plain uses operator *.
                  */
                 multi_exp_method_naive_plain,
                 /**
                  * A variant of the Bos-Coster algorithm [1],
                  * with implementation suggestions from [2].
                  *
                  * [1] = Bos and Coster, "Addition chain heuristics", CRYPTO '89
                  * [2] = Bernstein, Duif, Lange, Schwabe, and Yang, "High-speed high-security signatures", CHES '11
                  */
                 multi_exp_method_bos_coster,
                 /**
                  * A special case of Pippenger's algorithm from Page 15 of
                  * Bernstein, Doumen, Lange, Oosterwijk,
                  * "Faster batch forgery identification", INDOCRYPT 2012
                  * (https://eprint.iacr.org/2012/549.pdf)
                  * When compiled with USE_MIXED_ADDITION, assumes input is in special form.
                  * Requires that T implements .dbl() (and, if USE_MIXED_ADDITION is defined,
                  * .to_special(), .mixed_add(), and batch_to_special()).
                  */
                 multi_exp_method_BDLO12
                };


                template<typename NumberType, typename FieldT, multi_exp_method Method,
                    typename std::enable_if<(Method == multi_exp_method_naive_plain), int>::type = 0>
                 NumberType multi_exp_inner(
                    typename std::vector<NumberType>::const_iterator vec_start,
                    typename std::vector<NumberType>::const_iterator vec_end,
                    typename std::vector<FieldT>::const_iterator scalar_start,
                    typename std::vector<FieldT>::const_iterator scalar_end) {
                    
                    NumberType result(NumberType::zero());

                    typename std::vector<NumberType>::const_iterator vec_it;
                    typename std::vector<FieldT>::const_iterator scalar_it;

                    for (vec_it = vec_start, scalar_it = scalar_start; vec_it != vec_end; ++vec_it, ++scalar_it) {
                        result = result + (*scalar_it) * (*vec_it);
                    }

                    assert(scalar_it == scalar_end);

                    return result;
                }

                //TODO: Implement not only for vectors
                template<typename NumberType, typename FieldT, multi_exp_method Method>
                NumberType multi_exp(typename std::vector<NumberType>::const_iterator vec_start,
                            typename std::vector<NumberType>::const_iterator vec_end,
                            typename std::vector<FieldT>::const_iterator scalar_start,
                            typename std::vector<FieldT>::const_iterator scalar_end,
                            const std::size_t chunks_count) {

                    const std::size_t total_size = std::distance(vec_start, vec_end);

                    if ((total_size < chunks_count) || (chunks_count == 1)) {
                        // no need to split into "chunks_count", can call implementation directly
                        return multi_exp_inner<T, FieldT, Method>(
                            vec_start, vec_end, scalar_start, scalar_end);
                    }

                    const std::size_t one_chunk_size = total_size/chunks_count;


                    NumberType result = NumberType::zero();

                    for (std::size_t i = 0; i < chunks_count; ++i) {
                        result = result + multi_exp_inner<T, FieldT, Method>(
                             vec_start + i*one,
                             (i == chunks_count-1 ? vec_end : vec_start + (i+1)*one),
                             scalar_start + i*one,
                             (i == chunks_count-1 ? scalar_end : scalar_start + (i+1)*one));
                    }

                    return result;
                }

            }    // namespace detail
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_MULTIEXP_HPP