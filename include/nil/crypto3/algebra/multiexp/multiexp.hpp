//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Pavel Kharitonov <ipavrus@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_MULTIEXP_HPP
#define CRYPTO3_ALGEBRA_MULTIEXP_HPP

#include <vector>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/multiexp/policies.hpp>
#include <nil/crypto3/algebra/curves/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            template<typename MultiexpMethod, typename InputBaseIterator, typename InputFieldIterator>
            typename std::iterator_traits<InputBaseIterator>::value_type
                multiexp(InputBaseIterator vec_start, InputBaseIterator vec_end, InputFieldIterator scalar_start,
                         InputFieldIterator scalar_end, const std::size_t chunks_count) {

                typedef typename std::iterator_traits<InputBaseIterator>::value_type base_value_type;
                typedef typename std::iterator_traits<InputFieldIterator>::value_type field_value_type;

                const std::size_t total_size = std::distance(vec_start, vec_end);

                if ((total_size < chunks_count) || (chunks_count == 1)) {
                    // no need to split into "chunks_count", can call implementation directly
                    return MultiexpMethod::process(vec_start, vec_end, scalar_start, scalar_end);
                }

                const std::size_t one_chunk_size = total_size / chunks_count;

                base_value_type result = base_value_type::zero();

                for (std::size_t i = 0; i < chunks_count; ++i) {
                    result =
                        result + MultiexpMethod::process(
                                     vec_start + i * one_chunk_size,
                                     (i == chunks_count - 1 ? vec_end : vec_start + (i + 1) * one_chunk_size),
                                     scalar_start + i * one_chunk_size,
                                     (i == chunks_count - 1 ? scalar_end : scalar_start + (i + 1) * one_chunk_size));
                }

                return result;
            }

            template<typename MultiexpMethod, typename InputBaseIterator, typename InputFieldIterator>
            typename std::iterator_traits<InputBaseIterator>::value_type
                multiexp_with_mixed_addition(InputBaseIterator vec_start, InputBaseIterator vec_end,
                                             InputFieldIterator scalar_start, InputFieldIterator scalar_end,
                                             const std::size_t chunks_count) {

                typedef typename std::iterator_traits<InputBaseIterator>::value_type base_value_type;
                typedef typename std::iterator_traits<InputFieldIterator>::value_type field_value_type;

                typedef MultiexpMethod method_type;

                BOOST_ASSERT(std::distance(vec_start, vec_end) == std::distance(scalar_start, scalar_end));

                InputBaseIterator vec_it = vec_start;
                InputFieldIterator scalar_it = scalar_start;

                const field_value_type zero = field_value_type::zero();
                const field_value_type one = field_value_type::one();
                std::vector<field_value_type> p;
                std::vector<base_value_type> g;

                base_value_type acc = base_value_type::zero();

                for (; scalar_it != scalar_end; ++scalar_it, ++vec_it) {
                    if (*scalar_it == one) {
#ifdef USE_MIXED_ADDITION
                        acc = acc.mixed_add(*vec_it);
#else
                        acc = acc + (*vec_it);
#endif
                    } else if (*scalar_it != zero) {
                        p.emplace_back(*scalar_it);
                        g.emplace_back(*vec_it);
                    }
                }

                return acc + multiexp<method_type>(g.begin(), g.end(), p.begin(), p.end(), chunks_count);
            }

            /**
             * A window table stores window sizes for different instance sizes for fixed-base multi-scalar
             * multiplications.
             */
            template<typename GroupType>
            using window_table = std::vector<std::vector<typename GroupType::value_type>>;

            template<typename GroupType>
            std::size_t get_exp_window_size(const std::size_t num_scalars) {
                if (curves::multiexp_params<GroupType>::fixed_base_exp_window_table.empty()) {
#ifdef LOWMEM
                    return 14;
#else
                    return 17;
#endif
                }

                std::size_t window = 1;

                for (std::size_t i = curves::multiexp_params<GroupType>::fixed_base_exp_window_table.size() - 1; i >= 0;
                     --i) {
                    if (curves::multiexp_params<GroupType>::fixed_base_exp_window_table[i] != 0 &&
                        num_scalars >= curves::multiexp_params<GroupType>::fixed_base_exp_window_table[i]) {
                        window = i + 1;
                        break;
                    }
                }

#ifdef LOWMEM
                window = std::min((std::size_t)14, window);
#endif
                return window;
            }

            template<typename GroupType>
            window_table<GroupType> get_window_table(const std::size_t scalar_size,
                                                     const std::size_t window,
                                                     const typename GroupType::value_type &g) {
                const std::size_t in_window = 1ul << window;
                const std::size_t outerc = (scalar_size + window - 1) / window;
                const std::size_t last_in_window = 1ul << (scalar_size - (outerc - 1) * window);

                window_table<GroupType> powers_of_g(
                    outerc, std::vector<typename GroupType::value_type>(in_window, GroupType::value_type::zero()));

                typename GroupType::value_type gouter = g;

                for (std::size_t outer = 0; outer < outerc; ++outer) {
                    typename GroupType::value_type ginner = GroupType::value_type::zero();
                    std::size_t cur_in_window = outer == outerc - 1 ? last_in_window : in_window;
                    for (std::size_t inner = 0; inner < cur_in_window; ++inner) {
                        powers_of_g[outer][inner] = ginner;
                        ginner = ginner + gouter;
                    }

                    for (std::size_t i = 0; i < window; ++i) {
                        gouter = gouter.doubled();
                    }
                }

                return powers_of_g;
            }

            //
            template<typename GroupType, typename FieldType>
            typename GroupType::value_type windowed_exp(const std::size_t scalar_size,
                                                        const std::size_t window,
                                                        const window_table<GroupType> &powers_of_g,
                                                        const typename FieldType::value_type &pow) {

                typedef typename FieldType::number_type number_type;

                const std::size_t outerc = (scalar_size + window - 1) / window;
                const number_type pow_val = pow.data;
                /* exp */
                typename GroupType::value_type res = powers_of_g[0][0];

                for (std::size_t outer = 0; outer < outerc; ++outer) {
                    std::size_t inner = 0;
                    for (std::size_t i = 0; i < window; ++i) {
                        if (multiprecision::bit_test(pow_val, outer * window + i)) {
                            inner |= 1u << i;
                        }
                    }

                    res = res + powers_of_g[outer][inner];
                }

                return res;
            }

            template<typename GroupType, typename FieldType, typename InputRange,
                     typename = typename std::enable_if<
                         std::is_same<typename InputRange::value_type, typename FieldType::value_type>::value>::type>
            std::vector<typename GroupType::value_type> batch_exp(const std::size_t scalar_size,
                                                                  const std::size_t window,
                                                                  const window_table<GroupType> &table,
                                                                  const InputRange &v) {
                std::vector<typename GroupType::value_type> res(std::distance(v.begin(), v.end()), table[0][0]);

                for (std::size_t i = 0; i < v.size(); ++i) {
                    res[i] = windowed_exp<GroupType, FieldType>(scalar_size, window, table, v[i]);
                }

                return res;
            }

            template<typename GroupType, typename FieldType, typename InputRange,
                     typename = typename std::enable_if<
                         std::is_same<typename InputRange::value_type, typename FieldType::value_type>::value>::type>
            std::vector<typename GroupType::value_type>
                batch_exp_with_coeff(const std::size_t scalar_size,
                                     const std::size_t window,
                                     const window_table<GroupType> &table,
                                     const typename FieldType::value_type &coeff,
                                     const InputRange &v) {
                std::vector<typename GroupType::value_type> res(std::distance(v.begin(), v.end()), table[0][0]);

                for (std::size_t i = 0; i < v.size(); ++i) {
                    res[i] = windowed_exp<GroupType, FieldType>(scalar_size, window, table, coeff * v[i]);
                }

                return res;
            }

            template<typename GroupType, typename InputRange>
            typename std::enable_if<
                std::is_same<typename InputRange::value_type, typename GroupType::value_type>::value, void>::type
                batch_to_special(InputRange &vec) {

                std::vector<typename GroupType::value_type> non_zero_vec;
                for (std::size_t i = 0; i < vec.size(); ++i) {
                    if (!vec[i].is_zero()) {
                        non_zero_vec.emplace_back(vec[i]);
                    }
                }

                GroupType::batch_to_special_all_non_zeros(non_zero_vec);
                typename std::vector<typename GroupType::value_type>::const_iterator it = non_zero_vec.begin();
                typename GroupType::value_type zero_special = GroupType::value_type::zero().to_projective();

                for (std::size_t i = 0; i < vec.size(); ++i) {
                    if (!vec[i].is_zero()) {
                        vec[i] = *it;
                        ++it;
                    } else {
                        vec[i] = zero_special;
                    }
                }
            }
        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_MULTIEXP_HPP
