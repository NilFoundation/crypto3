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

#ifndef CRYPTO3_ALGEBRA_MULTIEXP_BASIC_POLICIES_HPP
#define CRYPTO3_ALGEBRA_MULTIEXP_BASIC_POLICIES_HPP

#include <vector>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/algebra/wnaf.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace policies {
                namespace detail {
                    template<typename NumberType>
                    class ordered_exponent {
                        using number_type = NumberType;

                    public:
                        std::size_t idx;
                        number_type r;
                        using r_type = number_type;

                        ordered_exponent(const std::size_t idx, const number_type &r) : idx(idx), r(r) {};

                        bool operator<(const ordered_exponent &other) const {
                            return (this->r < other.r);
                        }
                    };
                }    // namespace detail

                /**
                 * Naive multi-exponentiation individually multiplies each base by the
                 * corresponding scalar and adds up the results.
                 * multiexp_method_naive uses opt_window_wnaf_exp for exponentiation,
                 * while multiexp_method_plain uses operator *.
                 */
                struct multiexp_method_naive_plain {
                    template<typename InputBaseIterator, typename InputFieldIterator>
                    static inline typename std::iterator_traits<InputBaseIterator>::value_type
                        process(InputBaseIterator vec_start,
                                InputBaseIterator vec_end,
                                InputFieldIterator scalar_start,
                                InputFieldIterator scalar_end) {

                        typedef typename std::iterator_traits<InputBaseIterator>::value_type base_value_type;
                        typedef typename std::iterator_traits<InputFieldIterator>::value_type field_value_type;

                        base_value_type result = base_value_type::zero();

                        InputBaseIterator vec_it;
                        InputFieldIterator scalar_it;

                        for (vec_it = vec_start, scalar_it = scalar_start; vec_it != vec_end; ++vec_it, ++scalar_it) {
                            result = result + (*scalar_it) * (*vec_it);
                        }

                        BOOST_ASSERT(scalar_it == scalar_end);

                        return result;
                    }
                };

                /**
                 * A special case of Pippenger's algorithm from Page 15 of
                 * Bernstein, Doumen, Lange, Oosterwijk,
                 * "Faster batch forgery identification", INDOCRYPT 2012
                 * (https://eprint.iacr.org/2012/549.pdf)
                 * When compiled with USE_MIXED_ADDITION, assumes input is in special form.
                 * Requires that base_value_type implements .dbl() (and, if USE_MIXED_ADDITION is defined,
                 * .to_projective(), .mixed_add(), and batch_to_projective()).
                 */
                struct multiexp_method_BDLO12 {
                    template<typename InputBaseIterator, typename InputFieldIterator>
                    static inline typename std::iterator_traits<InputBaseIterator>::value_type
                        process(InputBaseIterator bases,
                                InputBaseIterator bases_end,
                                InputFieldIterator exponents,
                                InputFieldIterator exponents_end) {

                        typedef typename std::iterator_traits<InputBaseIterator>::value_type base_value_type;
                        typedef typename std::iterator_traits<InputFieldIterator>::value_type field_value_type;

                        std::size_t length = std::distance(bases, bases_end);
                        std::size_t scalars_length = std::distance(exponents, exponents_end);

                        assert (length == scalars_length);

                        // empirically, this seems to be a decent estimate of the optimal value of c
                        std::size_t log2_length = std::log2(length);
                        std::size_t c = log2_length - (log2_length / 3 - 2);

                        std::size_t num_bits = 0;

                        for (std::size_t i = 0; i < length; i++) {
                            // Should be
                            // std::size_t bn_exponents_i_msb = multiprecision::msb(exponents[i].data) + 1;
                            // But multiprecision::msb doesn't work for zero value
                            std::size_t bn_exponents_i_msb = 1;
                            if (exponents[i].data != 0){
                                bn_exponents_i_msb = multiprecision::msb(exponents[i].data) + 1;
                            }
                            num_bits = std::max(num_bits, bn_exponents_i_msb);
                        }

                        std::size_t num_groups = (num_bits + c - 1) / c;

                        base_value_type result;
                        bool result_nonzero = false;

                        for (std::size_t k = num_groups - 1; k <= num_groups; k--) {
                            if (result_nonzero) {
                                for (std::size_t i = 0; i < c; i++) {
                                    result = result.doubled();
                                }
                            }

                            std::vector<base_value_type> buckets(1 << c);
                            std::vector<bool> bucket_nonzero(1 << c);

                            for (std::size_t i = 0; i < length; i++) {
                                std::size_t id = 0;
                                for (std::size_t j = 0; j < c; j++) {
                                    if (multiprecision::bit_test(exponents[i].data, k * c + j)) {
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

                            base_value_type running_sum;
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
                };

                /**
                 * A variant of the Bos-Coster algorithm [1],
                 * with implementation suggestions from [2].
                 *
                 * [1] = Bos and Coster, "Addition chain heuristics", CRYPTO '89
                 * [2] = Bernstein, Duif, Lange, Schwabe, and Yang, "High-speed high-security signatures", CHES '11
                 */
                struct multiexp_method_bos_coster {
                    template<typename InputBaseIterator, typename InputFieldIterator>
                    static inline typename std::iterator_traits<InputBaseIterator>::value_type
                        process(InputBaseIterator vec_start,
                                InputBaseIterator vec_end,
                                InputFieldIterator scalar_start,
                                InputFieldIterator scalar_end) {

                        typedef typename std::iterator_traits<InputBaseIterator>::value_type base_value_type;
                        typedef typename std::iterator_traits<InputFieldIterator>::value_type field_value_type;

                        // temporary added until fixed-precision modular adaptor is ready:
                        typedef multiprecision::number<multiprecision::backends::cpp_int_backend<>>
                            non_fixed_precision_number_type;

                        if (vec_start == vec_end) {
                            return base_value_type::zero();
                        }

                        if (vec_start + 1 == vec_end) {
                            return (*scalar_start) * (*vec_start);
                        }

                        std::vector<detail::ordered_exponent<non_fixed_precision_number_type>> opt_q;
                        const std::size_t vec_len = scalar_end - scalar_start;
                        const std::size_t odd_vec_len = (vec_len % 2 == 1 ? vec_len : vec_len + 1);
                        opt_q.reserve(odd_vec_len);

                        std::vector<base_value_type> g;
                        g.reserve(odd_vec_len);

                        InputBaseIterator vec_it;
                        InputFieldIterator scalar_it;
                        std::size_t i;
                        for (i = 0, vec_it = vec_start, scalar_it = scalar_start; vec_it != vec_end;
                             ++vec_it, ++scalar_it, ++i) {
                            g.emplace_back(*vec_it);

                            opt_q.emplace_back(detail::ordered_exponent<non_fixed_precision_number_type>(
                                i, non_fixed_precision_number_type(scalar_it->data)));
                        }

                        std::make_heap(opt_q.begin(), opt_q.end());

                        assert(scalar_it == scalar_end);

                        if (vec_len != odd_vec_len) {
                            g.emplace_back(base_value_type::zero());
                            opt_q.emplace_back(
                                detail::ordered_exponent<non_fixed_precision_number_type>(odd_vec_len - 1, 0ul));
                        }
                        assert(g.size() % 2 == 1);
                        assert(opt_q.size() == g.size());

                        base_value_type opt_result = base_value_type::zero();

                        while (true) {
                            detail::ordered_exponent<non_fixed_precision_number_type> &a = opt_q[0];
                            detail::ordered_exponent<non_fixed_precision_number_type> &b =
                                (opt_q[1] < opt_q[2] ? opt_q[2] : opt_q[1]);

                            const std::size_t abits = multiprecision::msb(a.r) + 1;

                            if (b.r.is_zero()) {
                                // opt_result = opt_result + (a.r * g[a.idx]);
                                opt_result = opt_result + opt_window_wnaf_exp(g[a.idx], a.r, abits);
                                break;
                            }

                            const std::size_t bbits = multiprecision::msb(b.r) + 1;
                            const std::size_t limit = (abits - bbits >= 20 ? 20 : abits - bbits);

                            if (bbits < 1ul << limit) {
                                /*
                                  In this case, exponentiating to the power of a is cheaper than
                                  subtracting b from a multiple times, so let's do it directly
                                */
                                // opt_result = opt_result + (a.r * g[a.idx]);
                                opt_result = opt_result + opt_window_wnaf_exp(g[a.idx], a.r, abits);

                                a.r = 0;
                            } else {
                                // x A + y B => (x-y) A + y (B+A)
                                a.r = a.r - b.r;
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
                };
            }    // namespace policies
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_MULTIEXP_BASIC_POLICIES_HPP
