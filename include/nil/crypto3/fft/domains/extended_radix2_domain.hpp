//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FFT_EXTENDED_RADIX2_DOMAIN_HPP
#define CRYPTO3_ALGEBRA_FFT_EXTENDED_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/crypto3/fft/evaluation_domain.hpp>
#include <nil/crypto3/fft/domains/basic_radix2_domain_aux.hpp>

namespace nil {
    namespace crypto3 {
        namespace fft {

            using namespace nil::crypto3::algebra;

            template<typename FieldType>
            class evaluation_domain;

            template<typename FieldType>
            class extended_radix2_domain : public evaluation_domain<FieldType> {
                using value_type = typename FieldType::value_type;

            public:
                size_t small_m;
                value_type omega;
                value_type shift;

                extended_radix2_domain(const size_t m) : evaluation_domain<FieldType>(m) {
                    //if (m <= 1)
                    //    throw std::invalid_argument("extended_radix2(): expected m > 1");

                    if (!std::is_same<value_type, std::complex<double>>::value) {
                        const size_t logm = static_cast<std::size_t>(std::ceil(std::log2(m)));
                        //if (logm != (fields::arithmetic_params<FieldType>::s + 1))
                        //    throw std::invalid_argument(
                        //        "extended_radix2(): expected logm == fields::arithmetic_params<FieldType>::s + 1");
                    }

                    small_m = m / 2;

                    omega = detail::unity_root<FieldType>(small_m);

                    shift = detail::coset_shift<FieldType>();
                }

                void FFT(std::vector<value_type> &a) {
                    //if (a.size() != this->m)
                    //    throw std::invalid_argument("extended_radix2: expected a.size() == this->m");

                    std::vector<value_type> a0(small_m, value_type::zero());
                    std::vector<value_type> a1(small_m, value_type::zero());

                    const value_type shift_to_small_m = shift.pow(small_m);

                    value_type shift_i = value_type::one();
                    for (size_t i = 0; i < small_m; ++i) {
                        a0[i] = a[i] + a[small_m + i];
                        a1[i] = shift_i * (a[i] + shift_to_small_m * a[small_m + i]);

                        shift_i *= shift;
                    }

                    _basic_radix2_FFT<FieldType>(a0, omega);
                    _basic_radix2_FFT<FieldType>(a1, omega);

                    for (size_t i = 0; i < small_m; ++i) {
                        a[i] = a0[i];
                        a[i + small_m] = a1[i];
                    }
                }
                void iFFT(std::vector<value_type> &a) {
                    //if (a.size() != this->m)
                    //    throw std::invalid_argument("extended_radix2: expected a.size() == this->m");

                    // note: this is not in-place
                    std::vector<value_type> a0(a.begin(), a.begin() + small_m);
                    std::vector<value_type> a1(a.begin() + small_m, a.end());

                    const value_type omega_inverse = omega.inversed();
                    _basic_radix2_FFT<FieldType>(a0, omega_inverse);
                    _basic_radix2_FFT<FieldType>(a1, omega_inverse);

                    const value_type shift_to_small_m = shift.pow(small_m);
                    const value_type sconst = (value_type(small_m) * (value_type::one() - shift_to_small_m)).inversed();

                    const value_type shift_inverse = shift.inversed();
                    value_type shift_inverse_i = value_type::one();

                    for (size_t i = 0; i < small_m; ++i) {
                        a[i] = sconst * (-shift_to_small_m * a0[i] + shift_inverse_i * a1[i]);
                        a[i + small_m] = sconst * (a0[i] - shift_inverse_i * a1[i]);

                        shift_inverse_i *= shift_inverse;
                    }
                }
                std::vector<value_type> evaluate_all_lagrange_polynomials(const value_type &t) {
                    const std::vector<value_type> T0 = detail::basic_radix2_evaluate_all_lagrange_polynomials<FieldType>(small_m, t);
                    const std::vector<value_type> T1 =
                        detail::basic_radix2_evaluate_all_lagrange_polynomials<FieldType>(small_m, t * shift.inversed());

                    std::vector<value_type> result(this->m, value_type::zero());

                    const value_type t_to_small_m = t.pow(small_m);
                    const value_type shift_to_small_m = shift.pow(small_m);
                    const value_type one_over_denom = (shift_to_small_m - value_type::one()).inversed();
                    const value_type T0_coeff = (t_to_small_m - shift_to_small_m) * (-one_over_denom);
                    const value_type T1_coeff = (t_to_small_m - value_type::one()) * one_over_denom;
                    for (size_t i = 0; i < small_m; ++i) {
                        result[i] = T0[i] * T0_coeff;
                        result[i + small_m] = T1[i] * T1_coeff;
                    }

                    return result;
                }

                value_type get_domain_element(const size_t idx) {
                    if (idx < small_m) {
                        return omega.pow(idx);
                    } else {
                        return shift * (omega.pow(idx - small_m));
                    }
                }

                value_type compute_vanishing_polynomial(const value_type &t) {
                    return (t.pow(small_m) - value_type::one()) * (t.pow(small_m) - shift.pow(small_m));
                }

                void add_poly_Z(const value_type &coeff, std::vector<value_type> &H) {
                    //if (H.size() != this->m + 1)
                    //    throw std::invalid_argument("extended_radix2: expected H.size() == this->m+1");

                    const value_type shift_to_small_m = shift.pow(small_m);

                    H[this->m] += coeff;
                    H[small_m] -= coeff * (shift_to_small_m + value_type::one());
                    H[0] += coeff * shift_to_small_m;
                }

                void divide_by_Z_on_coset(std::vector<value_type> &P) {
                    const value_type coset = fields::arithmetic_params<FieldType>::multiplicative_generator;

                    const value_type coset_to_small_m = coset.pow(small_m);
                    const value_type shift_to_small_m = shift.pow(small_m);

                    const value_type Z0 =
                        (coset_to_small_m - value_type::one()) * (coset_to_small_m - shift_to_small_m);
                    const value_type Z1 = (coset_to_small_m * shift_to_small_m - value_type::one()) *
                                          (coset_to_small_m * shift_to_small_m - shift_to_small_m);

                    const value_type Z0_inverse = Z0.inversed();
                    const value_type Z1_inverse = Z1.inversed();

                    for (size_t i = 0; i < small_m; ++i) {
                        P[i] *= Z0_inverse;
                        P[i + small_m] *= Z1_inverse;
                    }
                }
            };
        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_EXTENDED_RADIX2_DOMAIN_HPP
