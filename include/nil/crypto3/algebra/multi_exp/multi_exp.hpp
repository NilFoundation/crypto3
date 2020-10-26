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

#include <boost/algebra/multi_exp/detail/multi_exp.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            //TODO: Implement not only for vectors
            template<typename BaseValueType, typename FieldValueType, typename detail::multi_exp_method Method>
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

            template <typename FieldType>
            FieldValueType inner_product(
                    typename std::vector<FieldValueType>::const_iterator a_start,
                    typename std::vector<FieldValueType>::const_iterator a_end,
                    typename std::vector<FieldValueType>::const_iterator b_start,
                    typename std::vector<FieldValueType>::const_iterator b_end) {

                return multi_exp<FieldType, FieldType, detail::multi_exp_method_naive_plain>(
                    a_start, a_end,
                    b_start, b_end, 1);
            }

            /**
             * A window table stores window sizes for different instance sizes for fixed-base multi-scalar multiplications.
             */
            template<typename T>
            using window_table = std::vector<std::vector<T> >;
            
            template<typename GroupType>
            std::size_t get_exp_window_size(const std::size_t num_scalars) {
                if (GroupType::fixed_base_exp_window_table.empty()) {
 #ifdef LOWMEM
                    return 14;
 #else
                    return 17;
 #endif
                }

                std::size_t window = 1;
                
                for (long i = GroupType::fixed_base_exp_window_table.size()-1; i >= 0; --i) {
                    if (GroupType::fixed_base_exp_window_table[i] != 0 && num_scalars >= T::fixed_base_exp_window_table[i]) {
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

        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_MULTI_EXP_HPP
