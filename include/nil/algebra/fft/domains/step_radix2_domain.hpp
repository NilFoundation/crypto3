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

            template<typename FieldType, std::size_t MinSize>
            struct step_radix2_domain : public evaluation_domain<FieldType, MinSize> {
                constexpr static const std::size_t min_size = MinSize;
                constexpr static const std::size_t big_m = 1ul << (boost::static_log2<MinSize>::value - 1);
                constexpr static const std::size_t small_m = MinSize - big_m;
                constexpr static const std::size_t omega =
                    detail::unity_root<FieldType>(1ul << boost::static_log2<MinSize>::value);

                static_assert(MinSize > 1, "step_radix2(): expected m > 1");
                static_assert(small_m != 1ul << boost::static_log2<small_m>::value,
                              "step_radix2(): expected small_m "
                              "== 1ul<<log2(small_m)");

                step_radix2_domain() {
                    big_omega = omega.squared();
                    small_omega = detail::unity_root<FieldType>(small_m);
                }

                void FFT(std::vector<FieldType> &a) {
                    if (a.size() != MinSize)
                        throw DomainSizeException("step_radix2: expected a.size() == MinSize");

                    std::vector<FieldType> c(big_m, FieldType::zero());
                    std::vector<FieldType> d(big_m, FieldType::zero());

                    FieldType omega_i = FieldType::one();
                    for (size_t i = 0; i < big_m; ++i) {
                        c[i] = (i < small_m ? a[i] + a[i + big_m] : a[i]);
                        d[i] = omega_i * (i < small_m ? a[i] - a[i + big_m] : a[i]);
                        omega_i *= omega;
                    }

                    std::vector<FieldType> e(small_m, FieldType::zero());
                    const size_t compr = 1ul << (std::log2(big_m) - std::log2(small_m));
                    for (size_t i = 0; i < small_m; ++i) {
                        for (size_t j = 0; j < compr; ++j) {
                            e[i] += d[i + j * small_m];
                        }
                    }

                    _basic_radix2_FFT(c, omega.squared());
                    _basic_radix2_FFT(e, detail::unity_root<FieldType>(small_m));

                    for (size_t i = 0; i < big_m; ++i) {
                        a[i] = c[i];
                    }

                    for (size_t i = 0; i < small_m; ++i) {
                        a[i + big_m] = e[i];
                    }
                }

                void iFFT(std::vector<FieldType> &a) {
                    if (a.size() != MinSize)
                        throw DomainSizeException("step_radix2: expected a.size() == MinSize");

                    std::vector<FieldType> U0(a.begin(), a.begin() + big_m);
                    std::vector<FieldType> U1(a.begin() + big_m, a.end());

                    _basic_radix2_FFT(U0, omega.squared().inverse());
                    _basic_radix2_FFT(U1, detail::unity_root<FieldType>(small_m).inverse());

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

                    const size_t compr = 1ul << (log2(big_m) - log2(small_m));
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

                void cosetFFT(std::vector<FieldType> &a, const FieldType &g) {
                    detail::multiply_by_coset(a, g);
                    FFT(a);
                }

                void icosetFFT(std::vector<FieldType> &a, const FieldType &g) {
                    iFFT(a);
                    detail::multiply_by_coset(a, g.inverse());
                }

                std::vector<FieldType> evaluate_all_lagrange_polynomials(const FieldType &t) {
                    std::vector<FieldType> inner_big = detail::basic_radix2_evaluate_all_lagrange_polynomials(big_m, t);
                    std::vector<FieldType> inner_small =
                        detail::basic_radix2_evaluate_all_lagrange_polynomials(small_m, t * omega.inverse());

                    std::vector<FieldType> result(MinSize, FieldType::zero());

                    const FieldType L0 = (t ^ small_m) - (omega ^ small_m);
                    const FieldType omega_to_small_m = omega ^ small_m;
                    const FieldType big_omega_to_small_m = big_omega ^ small_m;
                    FieldType elt = FieldType::one();
                    for (size_t i = 0; i < big_m; ++i) {
                        result[i] = inner_big[i] * L0 * (elt - omega_to_small_m).inverse();
                        elt *= big_omega_to_small_m;
                    }

                    const FieldType L1 =
                        ((t ^ big_m) - FieldType::one()) * ((omega ^ big_m) - FieldType::one()).inverse();

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
                    if (H.size() != MinSize + 1)
                        throw DomainSizeException("step_radix2: expected H.size() == MinSize+1");

                    const FieldType omega_to_small_m = omega ^ small_m;

                    H[MinSize] += coeff;
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

            private:
                size_t big_m;
                size_t small_m;
                FieldType omega;
                FieldType big_omega;
                FieldType small_omega;
            };

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_STEP_RADIX2_DOMAIN_HPP
