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

#include <nil/cas/fft/evaluation_domain/evaluation_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/basic_radix2_domain_aux.hpp>


namespace nil {
    namespace algebra {
        namespace fft {

            template<typename FieldT>
            struct extended_radix2_domain : public evaluation_domain<FieldT> {

                extended_radix2_domain(const size_t m) : evaluation_domain<FieldT>(m) {
                    //if (m <= 1)
                        //throw InvalidSizeException("extended_radix2(): expected m > 1");

                    if (!std::is_same<FieldT, ff::Double>::value) {
                        const size_t logm = ff::log2(m);
                        //if (logm != (FieldT::s + 1))
                            //throw DomainSizeException("extended_radix2(): expected logm == FieldT::s + 1");
                    }

                    small_m = m / 2;

                    //try {
                    omega = ff::get_root_of_unity<FieldT>(small_m);
                    //} catch (const std::invalid_argument &e) {
                    //    throw DomainSizeException(e.what());
                    //}

                    shift = ff::coset_shift<FieldT>();
                }

                void FFT(std::vector<FieldT> &a) {
                    //if (a.size() != this->m)
                        //throw DomainSizeException("extended_radix2: expected a.size() == this->m");

                    std::vector<FieldT> a0(small_m, FieldT::zero());
                    std::vector<FieldT> a1(small_m, FieldT::zero());

                    const FieldT shift_to_small_m = shift ^ ff::bigint<1>(small_m);

                    FieldT shift_i = FieldT::one();
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

                void iFFT(std::vector<FieldT> &a) {
                    //if (a.size() != this->m)
                        //throw DomainSizeException("extended_radix2: expected a.size() == this->m");

                    // note: this is not in-place
                    std::vector<FieldT> a0(a.begin(), a.begin() + small_m);
                    std::vector<FieldT> a1(a.begin() + small_m, a.end());

                    const FieldT omega_inverse = omega.inverse();
                    _basic_radix2_FFT(a0, omega_inverse);
                    _basic_radix2_FFT(a1, omega_inverse);

                    const FieldT shift_to_small_m = shift ^ ff::bigint<1>(small_m);
                    const FieldT sconst = (FieldT(small_m) * (FieldT::one() - shift_to_small_m)).inverse();

                    const FieldT shift_inverse = shift.inverse();
                    FieldT shift_inverse_i = FieldT::one();

                    for (size_t i = 0; i < small_m; ++i) {
                        a[i] = sconst * (-shift_to_small_m * a0[i] + shift_inverse_i * a1[i]);
                        a[i + small_m] = sconst * (a0[i] - shift_inverse_i * a1[i]);

                        shift_inverse_i *= shift_inverse;
                    }
                }

                void cosetFFT(std::vector<FieldT> &a, const FieldT &g) {
                    _multiply_by_coset(a, g);
                    FFT(a);
                }

                void icosetFFT(std::vector<FieldT> &a, const FieldT &g) {
                    iFFT(a);
                    _multiply_by_coset(a, g.inverse());
                }

                std::vector<FieldT> evaluate_all_lagrange_polynomials(const FieldT &t) {
                    const std::vector<FieldT> T0 = _basic_radix2_evaluate_all_lagrange_polynomials(small_m, t);
                    const std::vector<FieldT> T1 = _basic_radix2_evaluate_all_lagrange_polynomials(small_m, t * shift.inverse());

                    std::vector<FieldT> result(this->m, FieldT::zero());

                    const FieldT t_to_small_m = t ^ ff::bigint<1>(small_m);
                    const FieldT shift_to_small_m = shift ^ ff::bigint<1>(small_m);
                    const FieldT one_over_denom = (shift_to_small_m - FieldT::one()).inverse();
                    const FieldT T0_coeff = (t_to_small_m - shift_to_small_m) * (-one_over_denom);
                    const FieldT T1_coeff = (t_to_small_m - FieldT::one()) * one_over_denom;
                    for (size_t i = 0; i < small_m; ++i) {
                        result[i] = T0[i] * T0_coeff;
                        result[i + small_m] = T1[i] * T1_coeff;
                    }

                    return result;
                }

                FieldT get_domain_element(const size_t idx) {
                    if (idx < small_m) {
                        return omega ^ idx;
                    } else {
                        return shift * (omega ^ (idx - small_m));
                    }
                }

                FieldT compute_vanishing_polynomial(const FieldT &t) {
                    return ((t ^ small_m) - FieldT::one()) * ((t ^ small_m) - (shift ^ small_m));
                }

                void add_poly_Z(const FieldT &coeff, std::vector<FieldT> &H) {
                    //if (H.size() != m + 1)
                        //throw DomainSizeException("extended_radix2: expected H.size() == m+1");

                    const FieldT shift_to_small_m = shift ^ small_m;

                    H[this->m] += coeff;
                    H[small_m] -= coeff * (shift_to_small_m + FieldT::one());
                    H[0] += coeff * shift_to_small_m;
                }

                void divide_by_Z_on_coset(std::vector<FieldT> &P) {
                    const FieldT coset = FieldT::multiplicative_generator;

                    const FieldT coset_to_small_m = coset ^ small_m;
                    const FieldT shift_to_small_m = shift ^ small_m;

                    const FieldT Z0 = (coset_to_small_m - FieldT::one()) * (coset_to_small_m - shift_to_small_m);
                    const FieldT Z1 = (coset_to_small_m * shift_to_small_m - FieldT::one()) *
                                      (coset_to_small_m * shift_to_small_m - shift_to_small_m);

                    const FieldT Z0_inverse = Z0.inverse();
                    const FieldT Z1_inverse = Z1.inverse();

                    for (size_t i = 0; i < small_m; ++i) {
                        P[i] *= Z0_inverse;
                        P[i + small_m] *= Z1_inverse;
                    }
                }

            private:
                size_t small_m;
                FieldT omega;
                FieldT shift;
            };

        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_EXTENDED_RADIX2_DOMAIN_HPP
