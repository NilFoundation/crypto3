//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Pavel Kharitonov <ipavrus@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MULTIEXP_HPP
#define BOOST_MULTIPRECISION_MULTIEXP_HPP

#include <cstdint>

#include <boost/algebra/fields/detail/exponentiation.hpp>
#include <boost/algebra/fields/detail/fp.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                template<typename NumberType>
                NumberType multi_exp(typename static std::array<fp::value_type>::const_iterator vec_start,
                                     typename static std::array<NumberType>::const_iterator scalar_start,
                                     size_t num_groups, const size_t bucket_size, size_t const workers_in_subgroup,
                                     const size_t n, const size_t one) {
                    size_t chunk_len = std::ceil(n / num_groups);

                    if (n < num_groups) {
                        num_groups = n;
                    }

                    typename std::array<NumberType> part_res[num_groups] = {[0 ...(num_groups - 1)] = one};

                    // do parallel for j
                    for (size_t j = 0; j < num_groups; ++j) {
                        size_t start = j * chunk_len;
                        size_t end = std::min(start + chunk_len - 1, n - 1);
                        part_res[j] =
                            multi_exp_subgroup(vec_start, scalar_start, start, end, bucket_size, workers_in_subgroup);
                    }

                    size_t L = std::ceil((std::log2(*scalar_start)) / bucket_size);
                    return ResultAggregation(part_res, L, bucket_size);
                }

                template<typename NumberType>
                NumberType multi_exp_subgroup(typename static std::array<fp::value_type>::const_iterator vec_start,
                                              typename static std::array<NumberType>::const_iterator scalar_start,
                                              const size_t start, const size_t end, const size_t bucket_size,
                                              const size_t workers_amount, const size_t n, const size_t one) {
                    size_t L = std::log2(*(scalar_start + start).data);
                    size_t b = std::ceil(L / bucket_size);
                    size_t c = std::ceil(b / workers_amount);

                    typename std::array<NumberType> part_sum[workers_amount * c] = {[0 ...(workers_amount * c) - 1] =
                                                                                        one};

                    // do parallel for j
                    for (size_t j = 0; j < workers_amount; ++j) {
                        for (size_t k = 0; k <= c - 1; ++k) {

                            size_t bucket_start = j * c * c + k * bucket_size;
                            size_t res = power(b, bucket_size);
                            typename std::array<NumberType> buckets[res] = {[0 ... res - 1] = one};

                            for (size_t i = start; i <= end; ++i) {
                                size_t idx = get_bits(*(scalar_start + i).data, bucket_start, bucket_size, 2);
                                if (idx > 0) {
                                    buckets[idx - 1] = (*(vec_start + i).data) * buckets[idx - 1];
                                }
                            }

                            size_t acc = std::numeric_limits<double>::infinity();

                            for (size_t i = 0; i <= bucket_size; ++i) {
                                acc = acc + buckets[i];
                                part_sum[j * c + k] = part_sum[j * c + k] + acc;
                            }
                        }
                    }
                    return part_sum;
                }

                template<typename NumberType>
                NumberType get_bits(typename std::vector<T>::const_iterator scalar_start, const size_t start,
                                    const size_t end, const size_t repr) {
                    NumberType res = 0, e = *(scalar_start).data;
                    e >>= i;
                    for (size_t i = start; i <= end; ++i) {
                        res = res + (e & 1) * power(repr, i - start);
                    }
                    return res;
                }

                template<typename NumberType>
                NumberType result_aggregation(typename std::array<NumberType> &r, const size_t L,
                                              const size_t bucket_size, const size_t one) {
                    typename std::array<NumberType> part_res[L] = {[0 ... L - 1] = one};

                    for (size_t i = 0; i <= L; ++i) {
                        part_res[i] = sum_par(r, i, one);
                    }

                    size_t S = one;

                    for (size_t i = 0; i <= L - 1; ++i) {
                        S = S * power(2, bucket_size);
                        S = S + part_res[i];
                    }

                    return S;
                }

                template<typename NumberType>
                NumberType sum_par(typename std::array<NumberType> &r, int n, const size_t one) {
                    size_t h = n / std::log(n);
                    typename std::array<NumberType> part_res[h] = {[0 ... h - 1] = one};

                    // do parallel for i
                    for (size_t i = 0; i <= h - 1; ++i) {
                        for (size_t j = 0; j <= std::log(n) - 1; ++j) {
                            part_res[i] = part_res[i] + r[i * std::ceil(std::log(n)) + j];
                        }
                    }

                    size_t parallel_boundary = std::ceil(std::log(n));
                    size_t m = std::ceil(n / std::log(n));

                    while (m > parallel_boundary) {
                        h = std::ceil(std::log((m)));

                        // do parallel for i
                        for (size_t i = 0; i <= (m / h) - 1; ++i) {
                            size_t d = h - 1;
                            if (i == (m / h) - 1) {
                                d = m - 1 - i * h;
                            }

                            for (size_t j = 1; j <= d; ++j) {
                                part_res[i * h] = part_res[i * h] + part_res[i * h + j];
                            }
                            part_res[i] = part_res[i * h];
                        }

                        m = std::ceil((m / h));
                    }

                    for (size_t i = 1; i <= m - 1; ++i) {
                        part_res[0] = part_res[0] * part_res[i];
                    }

                    return part_res[0];
                }
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_MULTIEXP_HPP