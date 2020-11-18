//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_KC_MULTIEXP_HPP
#define CRYPTO3_ZK_KC_MULTIEXP_HPP

/*
  Split out from multiexp to prevent cyclical
  dependencies. I.e. previously multiexp dependend on
  knowledge_commitment, which dependend on sparse_vector, which
  dependend on multiexp (to do accumulate).

  Will probably go away in more general exp refactoring.
*/

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>

#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename T1, typename T2, typename Backend,
                         boost::multiprecision::expression_template_option ExpressionTemplates>
                typename knowledge_commitment<T1, T2>::value_type
                    opt_window_wnaf_exp(const typename knowledge_commitment<T1, T2>::value_type &base,
                                        const boost::multiprecision::number<Backend, ExpressionTemplates> &scalar,
                                        const std::size_t scalar_bits) {
                    return typename knowledge_commitment<T1, T2>::value_type(
                        opt_window_wnaf_exp(base.g, scalar, scalar_bits),
                        opt_window_wnaf_exp(base.h, scalar, scalar_bits));
                }

                template<typename T1, typename T2, typename FieldType, typename MultiexpMethod>
                typename knowledge_commitment<T1, T2>::value_type kc_multiexp_with_mixed_addition(
                    const knowledge_commitment_vector<T1, T2> &vec,
                    const std::size_t min_idx,
                    const std::size_t max_idx,
                    typename std::vector<typename FieldType::value_type>::const_iterator scalar_start,
                    typename std::vector<typename FieldType::value_type>::const_iterator scalar_end,
                    const std::size_t chunks) {

                    const size_t scalar_length = std::distance(scalar_start, scalar_end);
                    assert((size_t)(scalar_length) <= vec.domain_size_);

                    auto index_it = std::lower_bound(vec.indices.begin(), vec.indices.end(), min_idx);
                    const std::size_t offset = index_it - vec.indices.begin();

                    auto value_it = vec.values.begin() + offset;

                    const typename FieldType::value_type zero = FieldType::value_type::zero();
                    const typename FieldType::value_type one = FieldType::value_type::one();

                    std::vector<typename FieldType::value_type> p;
                    std::vector<typename knowledge_commitment<T1, T2>::value_type> g;

                    typename knowledge_commitment<T1, T2>::value_type acc =
                        knowledge_commitment<T1, T2>::value_type::zero();

                    while (index_it != vec.indices.end() && *index_it < max_idx) {
                        const std::size_t scalar_position = (*index_it) - min_idx;
                        assert(scalar_position < scalar_length);

                        const typename FieldType::value_type scalar = *(scalar_start + scalar_position);

                        if (scalar == zero) {
                            // do nothing
                        } else if (scalar == one) {
#ifdef USE_MIXED_ADDITION
                            acc.g = acc.g.mixed_add(value_it->g);
                            acc.h = acc.h.mixed_add(value_it->h);
#else
                            acc.g = acc.g + value_it->g;
                            acc.h = acc.h + value_it->h;
#endif
                        } else {
                            p.emplace_back(scalar);
                            g.emplace_back(*value_it);
                        }

                        ++index_it;
                        ++value_it;
                    }

                    return acc + algebra::multiexp<knowledge_commitment<T1, T2>, FieldType, MultiexpMethod>(
                                     g.begin(), g.end(), p.begin(), p.end(), chunks);
                }

                template<typename T1, typename T2, typename FieldType>
                knowledge_commitment_vector<T1, T2>
                    kc_batch_exp_internal(const std::size_t scalar_size,
                                          const std::size_t T1_window,
                                          const std::size_t T2_window,
                                          const algebra::window_table<T1> &T1_table,
                                          const algebra::window_table<T2> &T2_table,
                                          const typename FieldType::value_type &T1_coeff,
                                          const typename FieldType::value_type &T2_coeff,
                                          const std::vector<typename FieldType::value_type> &v,
                                          const std::size_t start_pos,
                                          const std::size_t end_pos,
                                          const std::size_t expected_size) {
                    knowledge_commitment_vector<T1, T2> res;

                    res.values.reserve(expected_size);
                    res.indices.reserve(expected_size);

                    for (std::size_t pos = start_pos; pos != end_pos; ++pos) {
                        if (!v[pos].is_zero()) {
                            res.values.emplace_back(typename knowledge_commitment<T1, T2>::value_type(
                                windowed_exp<T1, FieldType>(scalar_size, T1_window, T1_table, T1_coeff * v[pos]),
                                windowed_exp<T2, FieldType>(scalar_size, T2_window, T2_table, T2_coeff * v[pos])));
                            res.indices.emplace_back(pos);
                        }
                    }

                    return res;
                }

                template<typename T1, typename T2, typename FieldType>
                knowledge_commitment_vector<T1, T2> kc_batch_exp(const std::size_t scalar_size,
                                                                 const std::size_t T1_window,
                                                                 const std::size_t T2_window,
                                                                 const algebra::window_table<T1> &T1_table,
                                                                 const algebra::window_table<T2> &T2_table,
                                                                 const typename FieldType::value_type &T1_coeff,
                                                                 const typename FieldType::value_type &T2_coeff,
                                                                 const std::vector<typename FieldType::value_type> &v,
                                                                 const std::size_t suggested_num_chunks) {
                    knowledge_commitment_vector<T1, T2> res;
                    res.domain_size_ = v.size();

                    std::size_t nonzero = 0;
                    for (std::size_t i = 0; i < v.size(); ++i) {
                        nonzero += (v[i].is_zero() ? 0 : 1);
                    }

                    const std::size_t num_chunks = std::max((std::size_t)1, std::min(nonzero, suggested_num_chunks));

                    std::vector<knowledge_commitment_vector<T1, T2>> tmp(num_chunks);
                    std::vector<std::size_t> chunk_pos(num_chunks + 1);

                    const std::size_t chunk_size = nonzero / num_chunks;
                    const std::size_t last_chunk = nonzero - chunk_size * (num_chunks - 1);

                    chunk_pos[0] = 0;

                    std::size_t cnt = 0;
                    std::size_t chunkno = 1;

                    for (std::size_t i = 0; i < v.size(); ++i) {
                        cnt += (v[i].is_zero() ? 0 : 1);
                        if (cnt == chunk_size && chunkno < num_chunks) {
                            chunk_pos[chunkno] = i;
                            cnt = 0;
                            ++chunkno;
                        }
                    }

                    chunk_pos[num_chunks] = v.size();

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (std::size_t i = 0; i < num_chunks; ++i) {
                        tmp[i] = kc_batch_exp_internal<T1, T2, FieldType>(
                            scalar_size, T1_window, T2_window, T1_table, T2_table, T1_coeff, T2_coeff, v, chunk_pos[i],
                            chunk_pos[i + 1], i == num_chunks - 1 ? last_chunk : chunk_size);
#ifdef USE_MIXED_ADDITION
                        algebra::batch_to_special<typename knowledge_commitment<T1, T2>::value_type>(tmp[i].values);
#endif
                    }

                    if (num_chunks == 1) {
                        tmp[0].domain_size_ = v.size();
                        return tmp[0];
                    } else {
                        for (std::size_t i = 0; i < num_chunks; ++i) {
                            res.values.insert(res.values.end(), tmp[i].values.begin(), tmp[i].values.end());
                            res.indices.insert(res.indices.end(), tmp[i].indices.begin(), tmp[i].indices.end());
                        }
                        return res;
                    }
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // KC_MULTIEXP_HPP
