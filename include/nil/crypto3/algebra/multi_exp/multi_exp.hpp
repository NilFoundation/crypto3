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

#include <vector>

#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/algebra/multi_exp/detail/multi_exp.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            //TODO: Implement not only for vectors
            template<typename BaseValueType, typename FieldValueType, typename multi_exp_method Method>
            BaseValueType multi_exp(typename std::vector<BaseValueType>::const_iterator vec_start,
                        typename std::vector<BaseValueType>::const_iterator vec_end,
                        typename std::vector<FieldValueType>::const_iterator scalar_start,
                        typename std::vector<FieldValueType>::const_iterator scalar_end,
                        const std::size_t chunks_count) {

                const std::size_t total_size = std::distance(vec_start, vec_end);

                if ((total_size < chunks_count) || (chunks_count == 1)) {
                    // no need to split into "chunks_count", can call implementation directly
                    return detail::multi_exp_inner<BaseValueType, FieldType, Method>(
                        vec_start, vec_end, scalar_start, scalar_end);
                }

                const std::size_t one_chunk_size = total_size/chunks_count;

                BaseValueType result = BaseValueType::zero();

                for (std::size_t i = 0; i < chunks_count; ++i) {
                    result = result + detail::multi_exp_inner<, FieldType, Method>(
                         vec_start + i*one,
                         (i == chunks_count-1 ? vec_end : vec_start + (i+1)*one),
                         scalar_start + i*one,
                         (i == chunks_count-1 ? scalar_end : scalar_start + (i+1)*one));
                }

                return result;
            }

            template<typename BaseValueType, typename FieldValueType, multi_exp_method Method>
            BaseValueType multi_exp_with_mixed_addition(
                    typename std::vector<BaseValueType>::const_iterator vec_start,
                    typename std::vector<BaseValueType>::const_iterator vec_end,
                    typename std::vector<FieldValueType>::const_iterator scalar_start,
                    typename std::vector<FieldValueType>::const_iterator scalar_end,
                    const std::size_t chunks_count) {

                assert(std::distance(vec_start, vec_end) == std::distance(scalar_start, scalar_end));
                
                typename std::vector<BaseValueType>::const_iterator vec_it;
                typename std::vector<FieldValueType>::const_iterator scalar_it;

                const FieldValueType zero = FieldValueType::zero();
                const FieldValueType one = FieldValueType::one();
                std::vector<FieldValueType> p;
                std::vector<BaseValueType> g;

                BaseValueType acc = BaseValueType::zero();

                for (; scalar_it != scalar_end; ++scalar_it, ++value_it) {
                    if (*scalar_it == one) {
#ifdef USE_MIXED_ADDITION
                        acc = acc.mixed_add(*value_it);
#else
                        acc = acc + (*value_it);
#endif
                    }
                    else if (*scalar_it != zero){
                        p.emplace_back(*scalar_it);
                        g.emplace_back(*value_it);
                    }
                

                return acc + multi_exp<BaseValueType, FieldValueType, Method>(g.begin(), g.end(), p.begin(), p.end(), chunks);
            }

            template <typename FieldValueType>
            FieldValueType inner_product(
                    typename std::vector<FieldValueType>::const_iterator a_start,
                    typename std::vector<FieldValueType>::const_iterator a_end,
                    typename std::vector<FieldValueType>::const_iterator b_start,
                    typename std::vector<FieldValueType>::const_iterator b_end) {

                return multi_exp<FieldValueType, FieldValueType, multi_exp_method_naive_plain>(
                    a_start, a_end,
                    b_start, b_end, 1);
            }

            /**
             * A window table stores window sizes for different instance sizes for fixed-base multi-scalar multiplications.
             */
            template<typename GroupType>
            using window_table = std::vector<std::vector<GroupType>>;

            template<typename GroupType>
            std::size_t get_exp_window_size(const std::size_t num_scalars) {
                if (multi_exp_params<GroupType>::fixed_base_exp_window_table.empty()) {
 #ifdef LOWMEM
                    return 14;
 #else
                    return 17;
 #endif
                }

                std::size_t window = 1;
                
                for (long i = multi_exp_params<GroupType>::fixed_base_exp_window_table.size()-1; i >= 0; --i) {
                    if (multi_exp_params<GroupType>::fixed_base_exp_window_table[i] != 0 
                        && num_scalars >= multi_exp_params<GroupType>::fixed_base_exp_window_table[i]) {
                        window = i+1;
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
                                             const GroupType &g) {
                const std::size_t in_window = 1ul<<window;
                const std::size_t outerc = (scalar_size+window-1)/window;
                const std::size_t last_in_window = 1ul<<(scalar_size - (outerc-1)*window);

                window_table<GroupType> powers_of_g(outerc, std::vector<GroupType>(in_window, GroupType::zero()));

                GroupType gouter = g;

                for (std::size_t outer = 0; outer < outerc; ++outer) {
                    GroupType ginner = GroupType::zero();
                    std::size_t cur_in_window = outer == outerc-1 ? last_in_window : in_window;
                    for (std::size_t inner = 0; inner < cur_in_window; ++inner) {
                        powers_of_g[outer][inner] = ginner;
                        ginner = ginner + gouter;
                    }

                    for (std::size_t i = 0; i < window; ++i) {
                        gouter = gouter + gouter;
                    }
                }

                return powers_of_g;
            }

            //
            template<typename GroupType, typename FieldType>
            GroupType windowed_exp(const std::size_t scalar_size,
                           const std::size_t window,
                           const window_table<GroupType> &powers_of_g,
                           const FieldType::value_type &pow) {

                using number_type = typename FieldType::number_type;

                const std::size_t outerc = (scalar_size+window-1)/window;
                const number_type pow_val = pow.data;
                /* exp */
                GroupType res = powers_of_g[0][0];

                for (std::size_t outer = 0; outer < outerc; ++outer) {
                    std::size_t inner = 0;
                    for (std::size_t i = 0; i < window; ++i) {
                        if (boost::multiprecision::bit_test(pow_val, outer*window + i)) {
                            inner |= 1u << i;
                        }
                    }

                    res = res + powers_of_g[outer][inner];
                }

                return res;
            }

            template<typename GroupType, typename FieldValueType>
            std::vector<GroupType> batch_exp(const std::size_t scalar_size,
                                     const std::size_t window,
                                     const window_table<GroupType> &table,
                                     const std::vector<FieldValueType> &v) {
                std::vector<GroupType> res(v.size(), table[0][0]);

                for (std::size_t i = 0; i < v.size(); ++i) {
                    res[i] = windowed_exp(scalar_size, window, table, v[i]);
                }

                return res;
            }

            template<typename GroupType, typename FieldValueType>
            std::vector<GroupType> batch_exp_with_coeff(const std::size_t scalar_size,
                                                const std::size_t window,
                                                const window_table<GroupType> &table,
                                                const FieldValueType &coeff,
                                                const std::vector<FieldValueType> &v) {
                std::vector<GroupType> res(v.size(), table[0][0]);

                for (std::size_t i = 0; i < v.size(); ++i) {
                    res[i] = windowed_exp(scalar_size, window, table, coeff * v[i]);

                }

                return res;
            }

            template<typename GroupType>
            void batch_to_special(std::vector<GroupType> &vec) {

                std::vector<GroupType> non_zero_vec;
                for (std::size_t i = 0; i < vec.size(); ++i) {
                    if (!vec[i].is_zero()) {
                        non_zero_vec.emplace_back(vec[i]);
                    }
                }

                GroupType::batch_to_special_all_non_zeros(non_zero_vec);
                typename std::vector<GroupType>::const_iterator it = non_zero_vec.begin();
                GroupType zero_special = GroupType::zero();
                zero_special.to_special();

                for (std::size_t i = 0; i < vec.size(); ++i) {
                    if (!vec[i].is_zero()) {
                        vec[i] = *it;
                        ++it;
                    }
                    else {
                        vec[i] = zero_special;
                    }
                }
            }

        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_MULTI_EXP_HPP
