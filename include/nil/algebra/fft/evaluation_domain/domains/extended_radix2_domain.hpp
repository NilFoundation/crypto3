//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_EXTENDED_RADIX2_DOMAIN_HPP
#define ALGEBRA_FFT_EXTENDED_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/algebra/fft/evaluation_domain/evaluation_domain.hpp>
#include <nil/algebra/fft/evaluation_domain/domains/basic_radix2_domain_aux.hpp>

namespace nil {
    namespace algebra {
        namespace fft {

            template<typename FieldType, std::size_t MinSize>
            struct extended_radix2_domain : public evaluation_domain<FieldType, MinSize> {

                extended_radix2_domain(const size_t m) : evaluation_domain<FieldType>(m) {
                    if (m <= 1)
                        throw InvalidSizeException("extended_radix2(): expected m > 1");

                    if (!std::is_same<FieldType, ff::Double>::value) {
                        const size_t logm = ff::log2(m);
                        if (logm != (FieldType::s + 1))
                            throw DomainSizeException("extended_radix2(): expected logm == FieldType::s + 1");
                    }

                    small_m = m / 2;

                    try {
                        omega = detail::unity_root<FieldType>(small_m);
                    } catch (const std::invalid_argument &e) {
                        throw DomainSizeException(e.what());
                    }

                    shift = detail::coset_shift<FieldType>();
                }

                void FFT(std::vector<FieldType> &a) {
                    if (a.size() != this->m)
                        throw DomainSizeException("extended_radix2: expected a.size() == this->m");

                    std::vector<FieldType> a0(small_m, FieldType::zero());
                    std::vector<FieldType> a1(small_m, FieldType::zero());

                    const FieldType shift_to_small_m = shift ^ ff::bigint<1>(small_m);

                    FieldType shift_i = FieldType::one();
                    for (size_t i = 0; i < small_m; ++i) {
                        a0[i] = a[i] + a[small_m + i];
                        a1[i] = shift_i * (a[i] + shift_to_small_m * a[small_m + i]);

                        shift_i *= shift;
                    }

                    _basic_radix2_FFT(a0, omega);
                    _basic_radix2_FFT(a1, omega);

                    for (size_t i = 0; i < small_m; ++i) {
                        a[i] = a0[i];
                        a[i + small_m] = a1[i];
                    }
                }

                void iFFT(std::vector<FieldType> &a) {
                    if (a.size() != this->m)
                        throw DomainSizeException("extended_radix2: expected a.size() == this->m");

                    // note: this is not in-place
                    std::vector<FieldType> a0(a.begin(), a.begin() + small_m);
                    std::vector<FieldType> a1(a.begin() + small_m, a.end());

                    const FieldType omega_inverse = omega.inverse();
                    _basic_radix2_FFT(a0, omega_inverse);
                    _basic_radix2_FFT(a1, omega_inverse);

                    const FieldType shift_to_small_m = shift ^ ff::bigint<1>(small_m);
                    const FieldType sconst = (FieldType(small_m) * (FieldType::one() - shift_to_small_m)).inverse();

                    const FieldType shift_inverse = shift.inverse();
                    FieldType shift_inverse_i = FieldType::one();

                    for (size_t i = 0; i < small_m; ++i) {
                        a[i] = sconst * (-shift_to_small_m * a0[i] + shift_inverse_i * a1[i]);
                        a[i + small_m] = sconst * (a0[i] - shift_inverse_i * a1[i]);

                        shift_inverse_i *= shift_inverse;
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
                    const std::vector<FieldType> T0 =
                        detail::basic_radix2_evaluate_all_lagrange_polynomials(small_m, t);
                    const std::vector<FieldType> T1 =
                        detail::basic_radix2_evaluate_all_lagrange_polynomials(small_m, t * shift.inverse());

                    std::vector<FieldType> result(this->m, FieldType::zero());

                    const FieldType t_to_small_m = t ^ ff::bigint<1>(small_m);
                    const FieldType shift_to_small_m = shift ^ ff::bigint<1>(small_m);
                    const FieldType one_over_denom = (shift_to_small_m - FieldType::one()).inverse();
                    const FieldType T0_coeff = (t_to_small_m - shift_to_small_m) * (-one_over_denom);
                    const FieldType T1_coeff = (t_to_small_m - FieldType::one()) * one_over_denom;
                    for (size_t i = 0; i < small_m; ++i) {
                        result[i] = T0[i] * T0_coeff;
                        result[i + small_m] = T1[i] * T1_coeff;
                    }

                    return result;
                }

                FieldType get_domain_element(const size_t idx) {
                    if (idx < small_m) {
                        return omega ^ idx;
                    } else {
                        return shift * (omega ^ (idx - small_m));
                    }
                }

                FieldType compute_vanishing_polynomial(const FieldType &t) {
                    return ((t ^ small_m) - FieldType::one()) * ((t ^ small_m) - (shift ^ small_m));
                }

                void add_poly_Z(const FieldType &coeff, std::vector<FieldType> &H) {
                    if (H.size() != m + 1)
                        throw DomainSizeException("extended_radix2: expected H.size() == m+1");

                    const FieldType shift_to_small_m = shift ^ small_m;

                    H[this->m] += coeff;
                    H[small_m] -= coeff * (shift_to_small_m + FieldType::one());
                    H[0] += coeff * shift_to_small_m;
                }

                void divide_by_Z_on_coset(std::vector<FieldType> &P) {
                    const FieldType coset = FieldType::multiplicative_generator;

                    const FieldType coset_to_small_m = coset ^ small_m;
                    const FieldType shift_to_small_m = shift ^ small_m;

                    const FieldType Z0 = (coset_to_small_m - FieldType::one()) * (coset_to_small_m - shift_to_small_m);
                    const FieldType Z1 = (coset_to_small_m * shift_to_small_m - FieldType::one()) *
                                         (coset_to_small_m * shift_to_small_m - shift_to_small_m);

                    const FieldType Z0_inverse = Z0.inverse();
                    const FieldType Z1_inverse = Z1.inverse();

                    for (size_t i = 0; i < small_m; ++i) {
                        P[i] *= Z0_inverse;
                        P[i + small_m] *= Z1_inverse;
                    }
                }

            private:
                size_t small_m;
                FieldType omega;
                FieldType shift;
            };

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_EXTENDED_RADIX2_DOMAIN_HPP
