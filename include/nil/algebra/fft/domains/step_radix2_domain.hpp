//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_STEP_RADIX2_DOMAIN_HPP
#define ALGEBRA_FFT_STEP_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/algebra/fft/evaluation_domain.hpp>
#include <nil/algebra/fft/domains/basic_radix2_domain_aux.hpp>

namespace nil {
    namespace algebra {
        namespace fft {
            template<typename FieldType>
            class step_radix2_domain : public evaluation_domain<FieldType> {
            public:
                size_t big_m;
                size_t small_m;
                FieldType omega;
                FieldType big_omega;
                FieldType small_omega;

                step_radix2_domain(const size_t m) : evaluation_domain<FieldType>(m) {
                    if (m <= 1)
                        throw std::invalid_argument("step_radix2(): expected m > 1");

                    big_m = 1ul << (static_cast<std::size_t>(std::ceil(std::log2(m))) - 1);
                    small_m = m - big_m;

                    if (small_m != 1ul << static_cast<std::size_t>(std::ceil(std::log2(small_m))))
                        throw std::invalid_argument("step_radix2(): expected small_m == 1ul<<log2(small_m)");

                    try {
                        omega = unity_root<FieldType>(1ul << static_cast<std::size_t>(std::ceil(std::log2(m))));
                    } catch (const std::invalid_argument &e) {
                        throw std::invalid_argument(e.what());
                    }

                    big_omega = omega.squared();
                    small_omega = unity_root<FieldType>(small_m);
                }

                void FFT(std::vector<FieldType> &a) {
                    if (a.size() != this->m)
                        throw std::invalid_argument("step_radix2: expected a.size() == this->m");

                    std::vector<FieldType> c(big_m, FieldType::zero());
                    std::vector<FieldType> d(big_m, FieldType::zero());

                    FieldType omega_i = FieldType::one();
                    for (size_t i = 0; i < big_m; ++i) {
                        c[i] = (i < small_m ? a[i] + a[i + big_m] : a[i]);
                        d[i] = omega_i * (i < small_m ? a[i] - a[i + big_m] : a[i]);
                        omega_i *= omega;
                    }

                    std::vector<FieldType> e(small_m, FieldType::zero());
                    const size_t compr = 1ul << (static_cast<std::size_t>(std::ceil(std::log2(big_m))) - static_cast<std::size_t>(std::ceil(std::log2(small_m))));
                    for (size_t i = 0; i < small_m; ++i) {
                        for (size_t j = 0; j < compr; ++j) {
                            e[i] += d[i + j * small_m];
                        }
                    }

                    _basic_radix2_FFT(c, omega.squared());
                    _basic_radix2_FFT(e, unity_root<FieldType>(small_m));

                    for (size_t i = 0; i < big_m; ++i) {
                        a[i] = c[i];
                    }

                    for (size_t i = 0; i < small_m; ++i) {
                        a[i + big_m] = e[i];
                    }
                }
                void iFFT(std::vector<FieldType> &a) {
                    if (a.size() != this->m)
                        throw std::invalid_argument("step_radix2: expected a.size() == this->m");

                    std::vector<FieldType> U0(a.begin(), a.begin() + big_m);
                    std::vector<FieldType> U1(a.begin() + big_m, a.end());

                    _basic_radix2_FFT(U0, omega.squared().inverse());
                    _basic_radix2_FFT(U1, unity_root<FieldType>(small_m).inverse());

                    const FieldType U0_size_inv = FieldType(big_m).inverse();
                    for (size_t i = 0; i < big_m; ++i) {
                        U0[i] *= U0_size_inv;
                    }

                    const FieldType U1_size_inv = FieldType(small_m).inverse();
                    for (size_t i = 0; i < small_m; ++i) {
                        U1[i] *= U1_size_inv;
                    }

                    std::vector<FieldType> tmp = U0;
                    FieldType omega_i = FieldType::one();
                    for (size_t i = 0; i < big_m; ++i) {
                        tmp[i] *= omega_i;
                        omega_i *= omega;
                    }

                    // save A_suffix
                    for (size_t i = small_m; i < big_m; ++i) {
                        a[i] = U0[i];
                    }

                    const size_t compr = 1ul << (static_cast<std::size_t>(std::ceil(std::log2(big_m))) - static_cast<std::size_t>(std::ceil(std::log2(small_m))));
                    for (size_t i = 0; i < small_m; ++i) {
                        for (size_t j = 1; j < compr; ++j) {
                            U1[i] -= tmp[i + j * small_m];
                        }
                    }

                    const FieldType omega_inv = omega.inverse();
                    FieldType omega_inv_i = FieldType::one();
                    for (size_t i = 0; i < small_m; ++i) {
                        U1[i] *= omega_inv_i;
                        omega_inv_i *= omega_inv;
                    }

                    // compute A_prefix
                    const FieldType over_two = FieldType(2).inverse();
                    for (size_t i = 0; i < small_m; ++i) {
                        a[i] = (U0[i] + U1[i]) * over_two;
                    }

                    // compute B2
                    for (size_t i = 0; i < small_m; ++i) {
                        a[big_m + i] = (U0[i] - U1[i]) * over_two;
                    }
                }

                std::vector<FieldType> evaluate_all_lagrange_polynomials(const FieldType &t) {
                    std::vector<FieldType> inner_big = basic_radix2_evaluate_all_lagrange_polynomials(big_m, t);
                    std::vector<FieldType> inner_small =
                        basic_radix2_evaluate_all_lagrange_polynomials(small_m, t * omega.inverse());

                    std::vector<FieldType> result(this->m, FieldType::zero());

                    const FieldType L0 = (t ^ small_m) - (omega ^ small_m);
                    const FieldType omega_to_small_m = omega ^ small_m;
                    const FieldType big_omega_to_small_m = big_omega ^ small_m;
                    FieldType elt = FieldType::one();
                    for (size_t i = 0; i < big_m; ++i) {
                        result[i] = inner_big[i] * L0 * (elt - omega_to_small_m).inverse();
                        elt *= big_omega_to_small_m;
                    }

                    const FieldType L1 = ((t ^ big_m) - FieldType::one()) * ((omega ^ big_m) - FieldType::one()).inverse();

                    for (size_t i = 0; i < small_m; ++i) {
                        result[big_m + i] = L1 * inner_small[i];
                    }

                    return result;
                }

                FieldType get_domain_element(const size_t idx) {
                    if (idx < big_m) {
                        return big_omega ^ idx;
                    } else {
                        return omega * (small_omega ^ (idx - big_m));
                    }
                }

                FieldType compute_vanishing_polynomial(const FieldType &t) {
                    return ((t ^ big_m) - FieldType::one()) * ((t ^ small_m) - (omega ^ small_m));
                }

                void add_poly_Z(const FieldType &coeff, std::vector<FieldType> &H) {
                    if (H.size() != this->m + 1)
                        throw std::invalid_argument("step_radix2: expected H.size() == this->m+1");

                    const FieldType omega_to_small_m = omega ^ small_m;

                    H[this->m] += coeff;
                    H[big_m] -= coeff * omega_to_small_m;
                    H[small_m] -= coeff;
                    H[0] += coeff * omega_to_small_m;
                }
                void divide_by_Z_on_coset(std::vector<FieldType> &P) {
                    // (c^{2^k}-1) * (c^{2^r} * w^{2^{r+1}*i) - w^{2^r})
                    const FieldType coset = FieldType::multiplicative_generator;

                    const FieldType Z0 = (coset ^ big_m) - FieldType::one();
                    const FieldType coset_to_small_m_times_Z0 = (coset ^ small_m) * Z0;
                    const FieldType omega_to_small_m_times_Z0 = (omega ^ small_m) * Z0;
                    const FieldType omega_to_2small_m = omega ^ (2 * small_m);
                    FieldType elt = FieldType::one();

                    for (size_t i = 0; i < big_m; ++i) {
                        P[i] *= (coset_to_small_m_times_Z0 * elt - omega_to_small_m_times_Z0).inverse();
                        elt *= omega_to_2small_m;
                    }

                    // (c^{2^k}*w^{2^k}-1) * (c^{2^k} * w^{2^r} - w^{2^r})

                    const FieldType Z1 = ((((coset * omega) ^ big_m) - FieldType::one()) *
                                          (((coset * omega) ^ small_m) - (omega ^ small_m)));
                    const FieldType Z1_inverse = Z1.inverse();

                    for (size_t i = 0; i < small_m; ++i) {
                        P[big_m + i] *= Z1_inverse;
                    }
                }
            };
        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_STEP_RADIX2_DOMAIN_HPP
