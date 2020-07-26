//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_AUX_HPP
#define ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_AUX_HPP

#include <algorithm>
#include <vector>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/algebra/common/utilities.hpp>
#include <nil/algebra/fields/field_utils.hpp>

#ifdef DEBUG
#include <nil/algebra/algebra/common/profiling.hpp>
#endif



#ifdef MULTICORE
#define _basic_radix2_FFT _basic_parallel_radix2_FFT
#else
#define _basic_radix2_FFT _basic_serial_radix2_FFT
#endif

namespace nil {
    namespace algebra {
        namespace fft {


            /*!
             * @brief Serial compute the radix-2 FFT of the vector a over the set S={omega^{0},...,omega^{m-1}}.
             *
             */
            /*
             Below we make use of pseudocode from [CLRS 2n Ed, pp. 864].
             Also, note that it's the caller's responsibility to multiply by 1/N.
             */
            template<typename FieldType>
            void _basic_serial_radix2_FFT(std::vector<FieldType> &a, const FieldType &omega) {
                const size_t n = a.size(), logn = log2(n);
                //if (n != (1u << logn))
                    //throw DomainSizeException("expected n == (1u << logn)");

                /* swapping in place (from Storer's book) */
                for (size_t k = 0; k < n; ++k) {
                    const size_t rk = ff::bitreverse(k, logn);
                    if (k < rk)
                        std::swap(a[k], a[rk]);
                }

                size_t m = 1;    // invariant: m = 2^{s-1}
                for (size_t s = 1; s <= logn; ++s) {
                    // w_m is 2^s-th root of unity now
                    const FieldType w_m = omega ^ (n / (2 * m));

                    asm volatile("/* pre-inner */");
                    for (size_t k = 0; k < n; k += 2 * m) {
                        FieldType w = FieldType::one();
                        for (size_t j = 0; j < m; ++j) {
                            const FieldType t = w * a[k + j + m];
                            a[k + j + m] = a[k + j] - t;
                            a[k + j] += t;
                            w *= w_m;
                        }
                    }
                    asm volatile("/* post-inner */");
                    m *= 2;
                }
            }

            /*!
             * @brief A multi-thread version of _basic_radix2_FFT. Inner implementation.
             *
             */
            template<typename FieldType>
            void _basic_parallel_radix2_FFT_inner(std::vector<FieldType> &a, const FieldType &omega, const size_t log_cpus) {
                const size_t num_cpus = 1ul << log_cpus;

                const size_t m = a.size();
                const size_t log_m = log2(m);
                //if (m != 1ul << log_m)
                    //throw DomainSizeException("expected m == 1ul<<log_m");

                if (log_m < log_cpus) {
                    _basic_serial_radix2_FFT(a, omega);
                    return;
                }

                std::vector<std::vector<FieldType>> tmp(num_cpus);
                for (size_t j = 0; j < num_cpus; ++j) {
                    tmp[j].resize(1ul << (log_m - log_cpus), FieldType::zero());
                }

        #ifdef MULTICORE
        #pragma omp parallel for
        #endif
                for (size_t j = 0; j < num_cpus; ++j) {
                    const FieldType omega_j = omega ^ j;
                    const FieldType omega_step = omega ^ (j << (log_m - log_cpus));

                    FieldType elt = FieldType::one();
                    for (size_t i = 0; i < 1ul << (log_m - log_cpus); ++i) {
                        for (size_t s = 0; s < num_cpus; ++s) {
                            // invariant: elt is omega^(j*idx)
                            const size_t idx = (i + (s << (log_m - log_cpus))) % (1u << log_m);
                            tmp[j][i] += a[idx] * elt;
                            elt *= omega_step;
                        }
                        elt *= omega_j;
                    }
                }

                const FieldType omega_num_cpus = omega ^ num_cpus;

        #ifdef MULTICORE
        #pragma omp parallel for
        #endif
                for (size_t j = 0; j < num_cpus; ++j) {
                    _basic_serial_radix2_FFT(tmp[j], omega_num_cpus);
                }

        #ifdef MULTICORE
        #pragma omp parallel for
        #endif
                for (size_t i = 0; i < num_cpus; ++i) {
                    for (size_t j = 0; j < 1ul << (log_m - log_cpus); ++j) {
                        // now: i = idx >> (log_m - log_cpus) and j = idx % (1u << (log_m - log_cpus)), for idx =
                        // ((i<<(log_m-log_cpus))+j) % (1u << log_m)
                        a[(j << log_cpus) + i] = tmp[i][j];
                    }
                }
            }

            /*!
             * @brief A multi-thread version of _basic_radix2_FFT.
             *
             */
            template<typename FieldType>
            void _basic_parallel_radix2_FFT(std::vector<FieldType> &a, const FieldType &omega) {
        #ifdef MULTICORE
                const size_t num_cpus = omp_get_max_threads();
        #else
                const size_t num_cpus = 1;
        #endif
                const size_t log_cpus = ((num_cpus & (num_cpus - 1)) == 0 ? log2(num_cpus) : log2(num_cpus) - 1);

        #ifdef DEBUG
                algebra::print_indent();
                printf("* Invoking parallel FFT on 2^%zu CPUs (omp_get_max_threads = %zu)\n", log_cpus, num_cpus);
        #endif

                if (log_cpus == 0) {
                    _basic_serial_radix2_FFT(a, omega);
                } else {
                    _basic_parallel_radix2_FFT_inner(a, omega, log_cpus);
                }
            }

            /*!
             * @brief Translate the vector a to a coset defined by g.
             */
            template<typename FieldType>
            void _multiply_by_coset(std::vector<FieldType> &a, const FieldType &g) {
                FieldType u = g;
                for (size_t i = 1; i < a.size(); ++i) {
                    a[i] *= u;
                    u *= g;
                }
            }

            /*!
             * @brief Compute the m Lagrange coefficients, relative to the set S={omega^{0},...,omega^{m-1}}, at the field element t.
             */
            template<typename FieldType>
            std::vector<FieldType> _basic_radix2_evaluate_all_lagrange_polynomials(const size_t m, const FieldType &t) {
                if (m == 1) {
                    return std::vector<FieldType>(1, FieldType::one());
                }

                //if (m != (1u << algebra::log2(m)))
                    //throw DomainSizeException("expected m == (1u << log2(m))");

                const FieldType omega = ff::get_root_of_unity<FieldType>(m);

                std::vector<FieldType> u(m, FieldType::zero());

                /*
                 If t equals one of the roots of unity in S={omega^{0},...,omega^{m-1}}
                 then output 1 at the right place, and 0 elsewhere
                 */

                if ((t ^ m) == (FieldType::one())) {
                    FieldType omega_i = FieldType::one();
                    for (size_t i = 0; i < m; ++i) {
                        if (omega_i == t)    // i.e., t equals omega^i
                        {
                            u[i] = FieldType::one();
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

                const FieldType Z = (t ^ m) - FieldType::one();
                FieldType l = Z * FieldType(m).inverse();
                FieldType r = FieldType::one();
                for (size_t i = 0; i < m; ++i) {
                    u[i] = l * (t - r).inverse();
                    l *= omega;
                    r *= omega;
                }

                return u;
            };

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_AUX_HPP
