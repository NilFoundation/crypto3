//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MATH_STEP_RADIX2_DOMAIN_HPP
#define CRYPTO3_MATH_STEP_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/math/domains/detail/basic_radix2_domain_aux.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            using namespace nil::crypto3::algebra;

            template<typename FieldType, typename ValueType>
            class evaluation_domain;

            template<typename FieldType, typename ValueType = typename FieldType::value_type>
            class step_radix2_domain : public evaluation_domain<FieldType, ValueType> {
                typedef typename FieldType::value_type field_value_type;
                typedef ValueType value_type;
                typedef std::pair<std::vector<field_value_type>, std::vector<field_value_type>> cache_type;

                std::unique_ptr<cache_type> small_fft_cache, big_fft_cache;

                void create_fft_cache() {
                    small_fft_cache = std::make_unique<cache_type>(
                        std::make_pair(std::vector<field_value_type>(), std::vector<field_value_type>()));
                    big_fft_cache = std::make_unique<cache_type>(
                        std::make_pair(std::vector<field_value_type>(), std::vector<field_value_type>()));
                    detail::create_fft_cache<FieldType>(big_m, big_omega, big_fft_cache->first);
                    detail::create_fft_cache<FieldType>(big_m, big_omega.inversed(), big_fft_cache->second);
                    detail::create_fft_cache<FieldType>(small_m, small_omega, small_fft_cache->first);
                    detail::create_fft_cache<FieldType>(small_m, small_omega.inversed(), small_fft_cache->second);
                }
            public:
                typedef FieldType field_type;

                const std::size_t big_m;
                const std::size_t small_m;
                const field_value_type omega;
                const field_value_type big_omega;
                const field_value_type small_omega;

                step_radix2_domain(const std::size_t m)
                        : evaluation_domain<FieldType, ValueType>(m),
                          big_m(1ul << (static_cast<std::size_t>(std::ceil(std::log2(m))) - 1)),
                          small_m(m - big_m),
                          omega(unity_root<FieldType>(1ul << static_cast<std::size_t>(std::ceil(std::log2(m))))),
                          big_omega(omega.squared()),
                          small_omega(unity_root<FieldType>(small_m)) {
                    if (m <= 1)
                        throw std::invalid_argument("step_radix2(): expected m > 1");

                    if (small_m != 1ul << static_cast<std::size_t>(std::ceil(std::log2(small_m))))
                        throw std::invalid_argument("step_radix2(): expected small_m == 1ul<<log2(small_m)");
                }

                void fft(std::vector<value_type> &a) override {
                    if (a.size() != this->m) {
                        if (a.size() < this->m) {
                            a.resize(this->m, value_type());
                        } else {
                            throw std::invalid_argument("step_radix2: expected a.size() == this->m");
                        }
                    }

                    std::vector<value_type> c(big_m, value_type::zero());
                    std::vector<value_type> d(big_m, value_type::zero());

                    field_value_type omega_i = field_value_type::one();
                    for (std::size_t i = 0; i < big_m; ++i) {
                        c[i] = (i < small_m ? a[i] + a[i + big_m] : a[i]);
                        d[i] = omega_i * (i < small_m ? a[i] - a[i + big_m] : a[i]);
                        omega_i *= omega;
                    }

                    std::vector<value_type> e(small_m, value_type::zero());
                    const std::size_t compr = 1ul << (static_cast<std::size_t>(std::ceil(std::log2(big_m))) -
                                                      static_cast<std::size_t>(std::ceil(std::log2(small_m))));
                    for (std::size_t i = 0; i < small_m; ++i) {
                        for (std::size_t j = 0; j < compr; ++j) {
                            e[i] = e[i] + d[i + j * small_m];
                        }
                    }

                    if (small_fft_cache == nullptr) {
                        create_fft_cache();
                    }
                    detail::basic_radix2_fft_cached<FieldType>(c, big_fft_cache->first);
                    detail::basic_radix2_fft_cached<FieldType>(e, small_fft_cache->first);

                    for (std::size_t i = 0; i < big_m; ++i) {
                        a[i] = c[i];
                    }

                    for (std::size_t i = 0; i < small_m; ++i) {
                        a[i + big_m] = e[i];
                    }
                }
                void inverse_fft(std::vector<value_type> &a) override {
                    if (a.size() != this->m)
                        throw std::invalid_argument("step_radix2: expected a.size() == this->m");

                    std::vector<value_type> U0(a.begin(), a.begin() + big_m);
                    std::vector<value_type> U1(a.begin() + big_m, a.end());

                    if (small_fft_cache == nullptr) {
                        create_fft_cache();
                    }
                    detail::basic_radix2_fft_cached<FieldType>(U0, big_fft_cache->second);
                    detail::basic_radix2_fft_cached<FieldType>(U1, small_fft_cache->second);

                    const field_value_type U0_size_inv = field_value_type(big_m).inversed();
                    for (std::size_t i = 0; i < big_m; ++i) {
                        U0[i] = U0[i] * U0_size_inv;
                    }

                    const field_value_type U1_size_inv = field_value_type(small_m).inversed();
                    for (std::size_t i = 0; i < small_m; ++i) {
                        U1[i] = U1[i] * U1_size_inv;
                    }

                    std::vector<value_type> tmp = U0;
                    field_value_type omega_i = field_value_type::one();
                    for (std::size_t i = 0; i < big_m; ++i) {
                        tmp[i] =  tmp[i] * omega_i;
                        omega_i *= omega;
                    }

                    // save A_suffix
                    for (std::size_t i = small_m; i < big_m; ++i) {
                        a[i] = U0[i];
                    }

                    const std::size_t compr = 1ul << (static_cast<std::size_t>(std::ceil(std::log2(big_m))) -
                                                      static_cast<std::size_t>(std::ceil(std::log2(small_m))));
                    for (std::size_t i = 0; i < small_m; ++i) {
                        for (std::size_t j = 1; j < compr; ++j) {
                            U1[i] = U1[i] - tmp[i + j * small_m];
                        }
                    }

                    const field_value_type omega_inv = omega.inversed();
                    field_value_type omega_inv_i = field_value_type::one();
                    for (std::size_t i = 0; i < small_m; ++i) {
                        U1[i] = U1[i] * omega_inv_i;
                        omega_inv_i *= omega_inv;
                    }

                    // compute A_prefix
                    const field_value_type over_two = field_value_type(2).inversed();
                    for (std::size_t i = 0; i < small_m; ++i) {
                        a[i] = (U0[i] + U1[i]) * over_two;
                    }

                    // compute B2
                    for (std::size_t i = 0; i < small_m; ++i) {
                        a[big_m + i] = (U0[i] - U1[i]) * over_two;
                    }
                }

                std::vector<field_value_type> evaluate_all_lagrange_polynomials(const field_value_type &t) override {
                    std::vector<field_value_type> inner_big =
                        detail::basic_radix2_evaluate_all_lagrange_polynomials<FieldType>(big_m, t);
                    std::vector<field_value_type> inner_small =
                        detail::basic_radix2_evaluate_all_lagrange_polynomials<FieldType>(small_m,
                                                                                          t * omega.inversed());

                    std::vector<field_value_type> result(this->m, field_value_type::zero());

                    const field_value_type L0 = t.pow(small_m) - omega.pow(small_m);
                    const field_value_type omega_to_small_m = omega.pow(small_m);
                    const field_value_type big_omega_to_small_m = big_omega.pow(small_m);
                    field_value_type elt = field_value_type::one();
                    for (std::size_t i = 0; i < big_m; ++i) {
                        result[i] = inner_big[i] * L0 * (elt - omega_to_small_m).inversed();
                        elt *= big_omega_to_small_m;
                    }

                    const field_value_type L1 =
                        (t.pow(big_m) - field_value_type::one()) * (omega.pow(big_m) - field_value_type::one()).inversed();

                    for (std::size_t i = 0; i < small_m; ++i) {
                        result[big_m + i] = L1 * inner_small[i];
                    }

                    return result;
                }

                std::vector<value_type> evaluate_all_lagrange_polynomials(const typename std::vector<value_type>::const_iterator &t_powers_begin,
                                                                          const typename std::vector<value_type>::const_iterator &t_powers_end) override {
                    if(std::size_t(std::distance(t_powers_begin, t_powers_end)) < this->m) {
                        throw std::invalid_argument("extended_radix2: expected std::distance(t_powers_begin, t_powers_end) >= this->m");
                    }

                    basic_radix2_domain<FieldType, ValueType> basic_domain_big(big_m);
                    std::vector<value_type> inner_big =
                        basic_domain_big.evaluate_all_lagrange_polynomials(t_powers_begin, t_powers_end);
                    std::vector<value_type> inner_big_times_t_to_small_m =
                        basic_domain_big.evaluate_all_lagrange_polynomials(t_powers_begin + small_m, t_powers_end);

                    basic_radix2_domain<FieldType, ValueType> basic_domain_small(small_m);
                    std::vector<value_type> omega_inverse_t_powers(small_m);
                    std::vector<value_type> omega_inverse_t_powers_times_t_to_big_m(small_m);
                    field_value_type omega_inverse = omega.inversed();
                    field_value_type omega_inverse_i = field_value_type::one();
                    for(std::size_t i = 0; i < small_m; ++i) {
                        omega_inverse_t_powers[i] = omega_inverse_i * t_powers_begin[i];
                        omega_inverse_t_powers_times_t_to_big_m[i] = omega_inverse_i * t_powers_begin[i + big_m];
                        omega_inverse_i *= omega_inverse;
                    }
                    std::vector<value_type> inner_small =
                        basic_domain_small.evaluate_all_lagrange_polynomials(omega_inverse_t_powers.cbegin(), omega_inverse_t_powers.cend());
                    std::vector<value_type> inner_small_times_t_to_big_m =
                        basic_domain_small.evaluate_all_lagrange_polynomials(omega_inverse_t_powers_times_t_to_big_m.cbegin(), omega_inverse_t_powers_times_t_to_big_m.cend());

                    std::vector<value_type> result(this->m, value_type::zero());

                    const field_value_type omega_to_small_m = omega.pow(small_m);
                    const field_value_type big_omega_to_small_m = big_omega.pow(small_m);
                    field_value_type elt = field_value_type::one();
                    for (std::size_t i = 0; i < big_m; ++i) {
                        result[i] = (inner_big_times_t_to_small_m[i] - inner_big[i] * omega_to_small_m) * (elt - omega_to_small_m).inversed();
                        elt *= big_omega_to_small_m;
                    }

                    const field_value_type one_over_small_denom = (omega.pow(big_m) - field_value_type::one()).inversed();

                    for (std::size_t i = 0; i < small_m; ++i) {
                        result[big_m + i] = (inner_small_times_t_to_big_m[i] - inner_small[i]) * one_over_small_denom;
                    }

                    return result;
                }

                const field_value_type& get_unity_root() override {
                    return omega;
                }

                field_value_type get_domain_element(const std::size_t idx) override {
                    if (idx < big_m) {
                        return big_omega.pow(idx);
                    } else {
                        return omega * (small_omega.pow(idx - big_m));
                    }
                }

                field_value_type compute_vanishing_polynomial(const field_value_type &t) override {
                    return (t.pow(big_m) - field_value_type::one()) * (t.pow(small_m) - omega.pow(small_m));
                }

                polynomial<field_value_type> get_vanishing_polynomial() override {
                    polynomial<field_value_type> z(big_m + small_m + 1, field_value_type::zero());
                    field_value_type omega_to_small_m = omega.pow(small_m);
                    z[big_m + small_m] = field_value_type::one();
                    z[big_m] = z[big_m] -omega_to_small_m;
                    z[small_m] = z[small_m] -field_value_type::one();
                    z[0] = omega_to_small_m;

                    return z;
                }

                void add_poly_z(const field_value_type &coeff, std::vector<field_value_type> &H) override {
                    // if (H.size() != this->m + 1)
                    //    throw std::invalid_argument("step_radix2: expected H.size() == this->m+1");

                    const field_value_type omega_to_small_m = omega.pow(small_m);

                    H[this->m] += coeff;
                    H[big_m] -= coeff * omega_to_small_m;
                    H[small_m] -= coeff;
                    H[0] += coeff * omega_to_small_m;
                }
                void divide_by_z_on_coset(std::vector<field_value_type> &P) override {
                    // (c^{2^k}-1) * (c^{2^r} * w^{2^{r+1}*i) - w^{2^r})
                    const field_value_type coset = fields::arithmetic_params<FieldType>::multiplicative_generator;

                    const field_value_type Z0 = coset.pow(big_m) - field_value_type::one();
                    const field_value_type coset_to_small_m_times_Z0 = coset.pow(small_m) * Z0;
                    const field_value_type omega_to_small_m_times_Z0 = omega.pow(small_m) * Z0;
                    const field_value_type omega_to_2small_m = omega.pow(2 * small_m);
                    field_value_type elt = field_value_type::one();

                    for (std::size_t i = 0; i < big_m; ++i) {
                        P[i] *= (coset_to_small_m_times_Z0 * elt - omega_to_small_m_times_Z0).inversed();
                        elt *= omega_to_2small_m;
                    }

                    // (c^{2^k}*w^{2^k}-1) * (c^{2^k} * w^{2^r} - w^{2^r})

                    const field_value_type Z1 = (((coset * omega).pow(big_m) - field_value_type::one()) *
                                           ((coset * omega).pow(small_m) - omega.pow(small_m)));
                    const field_value_type Z1_inverse = Z1.inversed();

                    for (std::size_t i = 0; i < small_m; ++i) {
                        P[big_m + i] *= Z1_inverse;
                    }
                }
            };
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_STEP_RADIX2_DOMAIN_HPP
