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

#ifndef CRYPTO3_ALGEBRA_MULTI_EXP_DETAIL_HPP
#define CRYPTO3_ALGEBRA_MULTI_EXP_DETAIL_HPP

#include <vector>

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

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
                 * Requires that typename BaseType::value_type implements .dbl() (and, if USE_MIXED_ADDITION is defined,
                 * .to_special(), .mixed_add(), and batch_to_special()).
                 */
                multi_exp_method_BDLO12
            };

            namespace detail {

                template<typename BaseType,
                         typename FieldType,
                         multi_exp_method Method,
                         typename std::enable_if<(Method == multi_exp_method_naive_plain), int>::type = 0>
                typename BaseType::value_type
                    multi_exp_inner(typename std::vector<typename BaseType::value_type>::const_iterator vec_start,
                                    typename std::vector<typename BaseType::value_type>::const_iterator vec_end,
                                    typename std::vector<typename FieldType::value_type>::const_iterator scalar_start,
                                    typename std::vector<typename FieldType::value_type>::const_iterator scalar_end) {

                    typename BaseType::value_type result(BaseType::value_type::zero());

                    typename std::vector<typename BaseType::value_type>::const_iterator vec_it;
                    typename std::vector<typename FieldType::value_type>::const_iterator scalar_it;

                    for (vec_it = vec_start, scalar_it = scalar_start; vec_it != vec_end; ++vec_it, ++scalar_it) {
                        result = result + (*scalar_it) * (*vec_it);
                    }

                    assert(scalar_it == scalar_end);

                    return result;
                }

                template<typename BaseType,
                         typename FieldType,
                         multi_exp_method Method,
                         typename std::enable_if<(Method == multi_exp_method_BDLO12), int>::type = 0>
                typename BaseType::value_type multi_exp_inner(
                    typename std::vector<typename BaseType::value_type>::const_iterator bases,
                    typename std::vector<typename BaseType::value_type>::const_iterator bases_end,
                    typename std::vector<typename FieldType::value_type>::const_iterator exponents,
                    typename std::vector<typename FieldType::value_type>::const_iterator exponents_end) {

                    using number_type = typename FieldType::modulus_type;

                    std::size_t length = std::distance(bases, bases_end);

                    // empirically, this seems to be a decent estimate of the optimal value of c
                    std::size_t log2_length = std::log2(length);
                    std::size_t c = log2_length - (log2_length / 3 - 2);

                    std::vector<number_type> bn_exponents(length);
                    std::size_t num_bits = 0;

                    for (std::size_t i = 0; i < length; i++) {
                        bn_exponents[i] = exponents[i].data;
                        num_bits = std::max(num_bits, boost::multiprecision::msb(bn_exponents[i]));
                    }

                    std::size_t num_groups = (num_bits + c - 1) / c;

                    typename BaseType::value_type result;
                    bool result_nonzero = false;

                    for (std::size_t k = num_groups - 1; k <= num_groups; k--) {
                        if (result_nonzero) {
                            for (std::size_t i = 0; i < c; i++) {
                                result = result.dbl();
                            }
                        }

                        std::vector<typename BaseType::value_type> buckets(1 << c);
                        std::vector<bool> bucket_nonzero(1 << c);

                        for (std::size_t i = 0; i < length; i++) {
                            std::size_t id = 0;
                            for (std::size_t j = 0; j < c; j++) {
                                if (boost::multiprecision::bit_test(bn_exponents[i], k * c + j)) {
                                    id |= 1 << j;
                                }
                            }

                            if (id == 0) {
                                continue;
                            }

                            if (bucket_nonzero[id]) {
#ifdef USE_MIXED_ADDITION
                                buckets[id] = buckets[id].mixed_add(bases[i]);
#else
                                buckets[id] = buckets[id] + bases[i];
#endif
                            } else {
                                buckets[id] = bases[i];
                                bucket_nonzero[id] = true;
                            }
                        }

#ifdef USE_MIXED_ADDITION
                        batch_to_special(buckets);
#endif

                        typename BaseType::value_type running_sum;
                        bool running_sum_nonzero = false;

                        for (std::size_t i = (1u << c) - 1; i > 0; i--) {
                            if (bucket_nonzero[i]) {
                                if (running_sum_nonzero) {
#ifdef USE_MIXED_ADDITION
                                    running_sum = running_sum.mixed_add(buckets[i]);
#else
                                    running_sum = running_sum + buckets[i];
#endif
                                } else {
                                    running_sum = buckets[i];
                                    running_sum_nonzero = true;
                                }
                            }

                            if (running_sum_nonzero) {
                                if (result_nonzero) {
                                    result = result + running_sum;
                                } else {
                                    result = running_sum;
                                    result_nonzero = true;
                                }
                            }
                        }
                    }

                    return result;
                }

                template<typename BaseType,
                         typename FieldType,
                         multi_exp_method Method,
                         typename = typename std::enable_if<
                             (Method == multi_exp_method_bos_coster) &&
                             ::nil::crypto3::algebra::detail::is_fp_field<FieldType>::value>::type>
                typename BaseType::value_type
                    multi_exp_inner(typename std::vector<typename BaseType::value_type>::const_iterator vec_start,
                                    typename std::vector<typename BaseType::value_type>::const_iterator vec_end,
                                    typename std::vector<typename FieldType::value_type>::const_iterator scalar_start,
                                    typename std::vector<typename FieldType::value_type>::const_iterator scalar_end) {

                    using number_type = typename FieldType::modulus_type;

                    if (vec_start == vec_end) {
                        return BaseType::value_type::zero();
                    }

                    if (vec_start + 1 == vec_end) {
                        return (*scalar_start) * (*vec_start);
                    }

                    std::vector<number_type> opt_q;
                    const std::size_t vec_len = scalar_end - scalar_start;
                    const std::size_t odd_vec_len = (vec_len % 2 == 1 ? vec_len : vec_len + 1);
                    opt_q.reserve(odd_vec_len);
                    std::vector<typename BaseType::value_type> g;
                    g.reserve(odd_vec_len);

                    typename std::vector<typename BaseType::value_type>::const_iterator vec_it;
                    typename std::vector<typename FieldType::value_type>::const_iterator scalar_it;
                    std::size_t i;
                    for (i = 0, vec_it = vec_start, scalar_it = scalar_start; vec_it != vec_end;
                         ++vec_it, ++scalar_it, ++i) {
                        g.emplace_back(*vec_it);

                        opt_q.emplace_back(number_type(scalar_it->data));
                    }
                    std::make_heap(opt_q.begin(), opt_q.end());
                    assert(scalar_it == scalar_end);

                    if (vec_len != odd_vec_len) {
                        g.emplace_back(BaseType::value_type::zero());
                        opt_q.emplace_back(number_type(0ul));
                    }
                    assert(g.size() % 2 == 1);
                    assert(opt_q.size() == g.size());

                    typename BaseType::value_type opt_result = BaseType::value_type::zero();

                    while (true) {
                        number_type &a = opt_q[0];
                        number_type &b = (opt_q[1] < opt_q[2] ? opt_q[2] : opt_q[1]);

                        const std::size_t abits = boost::multiprecision::msb(a.r);

                        if (b.r.is_zero()) {
                            // opt_result = opt_result + (a.r * g[a.idx]);
                            opt_result = opt_result + opt_window_wnaf_exp(g[a.idx], a.r, abits);
                            break;
                        }

                        const std::size_t bbits = boost::multiprecision::msb(b.r);
                        const std::size_t limit = (abits - bbits >= 20 ? 20 : abits - bbits);

                        if (bbits < 1ul << limit) {
                            /*
                              In this case, exponentiating to the power of a is cheaper than
                              subtracting b from a multiple times, so let's do it directly
                            */
                            // opt_result = opt_result + (a.r * g[a.idx]);
                            opt_result = opt_result + opt_window_wnaf_exp(g[a.idx], a.r, abits);

                            a.r.clear();
                        } else {
                            // x A + y B => (x-y) A + y (B+A)
                            a.r.data = a.r.data - b.r.data;
                            g[b.idx] = g[b.idx] + g[a.idx];
                        }

                        // regardless of whether a was cleared or subtracted from we push it down, then take back up

                        /* heapify A down */
                        std::size_t a_pos = 0;
                        while (2 * a_pos + 2 < odd_vec_len) {
                            // this is a max-heap so to maintain a heap property we swap with the largest of the two
                            if (opt_q[2 * a_pos + 1] < opt_q[2 * a_pos + 2]) {
                                std::swap(opt_q[a_pos], opt_q[2 * a_pos + 2]);
                                a_pos = 2 * a_pos + 2;
                            } else {
                                std::swap(opt_q[a_pos], opt_q[2 * a_pos + 1]);
                                a_pos = 2 * a_pos + 1;
                            }
                        }

                        /* now heapify A up appropriate amount of times */
                        while (a_pos > 0 && opt_q[(a_pos - 1) / 2] < opt_q[a_pos]) {
                            std::swap(opt_q[a_pos], opt_q[(a_pos - 1) / 2]);
                            a_pos = (a_pos - 1) / 2;
                        }
                    }

                    return opt_result;
                }
            }    // namespace detail
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_MULTI_EXP_DETAIL_HPP
