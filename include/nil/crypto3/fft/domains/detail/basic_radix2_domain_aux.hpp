//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_AUX_HPP
#define CRYPTO3_ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_AUX_HPP

#include <algorithm>
#include <vector>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/fft/detail/field_utils.hpp>

#ifdef MULTICORE
#define _basic_radix2_FFT detail::basic_parallel_radix2_FFT
#else
#define _basic_radix2_FFT detail::basic_serial_radix2_FFT
#endif

namespace nil {
    namespace crypto3 {
        namespace fft {
            namespace detail {

                /*
                 * Below we make use of pseudocode from [CLRS 2n Ed, pp. 864].
                 * Also, note that it's the caller's responsibility to multiply by 1/N.
                 */
                template<typename FieldType>
                void basic_serial_radix2_FFT(std::vector<typename FieldType::value_type> &a,
                                             const typename FieldType::value_type &omega) {
                    typedef typename FieldType::value_type value_type;

                    const std::size_t n = a.size(), logn = log2(n);
                    // if (n != (1u << logn))
                    //    throw std::invalid_argument("expected n == (1u << logn)");

                    /* swapping in place (from Storer's book) */
                    for (std::size_t k = 0; k < n; ++k) {
                        const std::size_t rk = bitreverse(k, logn);
                        if (k < rk)
                            std::swap(a[k], a[rk]);
                    }

                    std::size_t m = 1;    // invariant: m = 2^{s-1}
                    for (std::size_t s = 1; s <= logn; ++s) {
                        // w_m is 2^s-th root of unity now
                        const value_type w_m = omega.pow(n / (2 * m));

                        asm volatile("/* pre-inner */");
                        for (std::size_t k = 0; k < n; k += 2 * m) {
                            value_type w = value_type::one();
                            for (std::size_t j = 0; j < m; ++j) {
                                const value_type t = w * a[k + j + m];
                                a[k + j + m] = a[k + j] - t;
                                a[k + j] += t;
                                w *= w_m;
                            }
                        }
                        asm volatile("/* post-inner */");
                        m *= 2;
                    }
                }

                template<typename FieldType>
                void basic_parallel_radix2_FFT_inner(std::vector<typename FieldType::value_type> &a,
                                                     const typename FieldType::value_type &omega,
                                                     const std::size_t log_cpus) {
                    typedef typename FieldType::value_type value_type;

                    const std::size_t num_cpus = 1ul << log_cpus;

                    const std::size_t m = a.size();
                    const std::size_t log_m = log2(m);
                    // if (m != 1ul << log_m)
                    //    throw std::invalid_argument("expected m == 1ul<<log_m");

                    if (log_m < log_cpus) {
                        basic_serial_radix2_FFT<FieldType>(a, omega);
                        return;
                    }

                    std::vector<std::vector<value_type>> tmp(num_cpus);
                    for (std::size_t j = 0; j < num_cpus; ++j) {
                        tmp[j].resize(1ul << (log_m - log_cpus), value_type::zero());
                    }

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (std::size_t j = 0; j < num_cpus; ++j) {
                        const value_type omega_j = omega.pow(j);
                        const value_type omega_step = omega.pow(j << (log_m - log_cpus));

                        value_type elt = value_type::one();
                        for (std::size_t i = 0; i < 1ul << (log_m - log_cpus); ++i) {
                            for (std::size_t s = 0; s < num_cpus; ++s) {
                                // invariant: elt is omega^(j*idx)
                                const std::size_t idx = (i + (s << (log_m - log_cpus))) % (1u << log_m);
                                tmp[j][i] += a[idx] * elt;
                                elt *= omega_step;
                            }
                            elt *= omega_j;
                        }
                    }

                    const value_type omega_num_cpus = omega.pow(num_cpus);

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (std::size_t j = 0; j < num_cpus; ++j) {
                        basic_serial_radix2_FFT<FieldType>(tmp[j], omega_num_cpus);
                    }

#ifdef MULTICORE
#pragma omp parallel for
#endif
                    for (std::size_t i = 0; i < num_cpus; ++i) {
                        for (std::size_t j = 0; j < 1ul << (log_m - log_cpus); ++j) {
                            // now: i = idx >> (log_m - log_cpus) and j = idx % (1u << (log_m - log_cpus)), for idx
                            // =
                            // ((i<<(log_m-log_cpus))+j) % (1u << log_m)
                            a[(j << log_cpus) + i] = tmp[i][j];
                        }
                    }
                }

                template<typename FieldType>
                void basic_parallel_radix2_FFT(std::vector<typename FieldType::value_type> &a,
                                               const typename FieldType::value_type &omega) {
#ifdef MULTICORE
                    const std::size_t num_cpus = omp_get_max_threads();
#else
                    const std::size_t num_cpus = 1;
#endif
                    const std::size_t log_cpus =
                        ((num_cpus & (num_cpus - 1)) == 0 ? log2(num_cpus) : log2(num_cpus) - 1);

                    if (log_cpus == 0) {
                        basic_serial_radix2_FFT<FieldType>(a, omega);
                    } else {
                        basic_parallel_radix2_FFT_inner(a, omega, log_cpus);
                    }
                }

                /**
                 * Compute the m Lagrange coefficients, relative to the set S={omega^{0},...,omega^{m-1}}, at the
                 * field element t.
                 */
                template<typename FieldType>
                std::vector<typename FieldType::value_type>
                    basic_radix2_evaluate_all_lagrange_polynomials(const std::size_t m,
                                                                   const typename FieldType::value_type &t) {
                    typedef typename FieldType::value_type value_type;

                    if (m == 1) {
                        return std::vector<value_type>(1, value_type::one());
                    }

                    // if (m != (1u << static_cast<std::size_t>(std::ceil(std::log2(m)))))
                    //    throw std::invalid_argument("expected m == (1u << log2(m))");

                    const value_type omega = unity_root<FieldType>(m);

                    std::vector<value_type> u(m, value_type::zero());

                    /*
                     If t equals one of the roots of unity in S={omega^{0},...,omega^{m-1}}
                     then output 1 at the right place, and 0 elsewhere
                     */

                    if (t.pow(m) == value_type::one()) {
                        value_type omega_i = value_type::one();
                        for (std::size_t i = 0; i < m; ++i) {
                            if (omega_i == t)    // i.e., t equals omega^i
                            {
                                u[i] = value_type::one();
                                return u;
                            }

                            omega_i *= omega;
                        }
                    }

                    /*
                     Otherwise, if t does not equal any of the roots of unity in S,
                     then compute each L_{i,S}(t) as Z_{S}(t) * v_i / (t-\omega^i)
                     where:
                     - Z_{S}(t) = \prod_{j} (t-\omega^j) = (t^m-1), and
                     - v_{i} = 1 / \prod_{j \neq i} (\omega^i-\omega^j).
                     Below we use the fact that v_{0} = 1/m and v_{i+1} = \omega * v_{i}.
                     */

                    const value_type Z = (t.pow(m)) - value_type::one();
                    value_type l = Z * value_type(m).inversed();
                    value_type r = value_type::one();
                    for (std::size_t i = 0; i < m; ++i) {
                        u[i] = l * (t - r).inversed();
                        l *= omega;
                        r *= omega;
                    }

                    return u;
                }
            }    // namespace detail
        }        // namespace fft
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_AUX_HPP
