//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP
#define ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/algebra/fft/detail/field_utils.hpp>

#include <nil/algebra/fft/evaluation_domain.hpp>
#include <nil/algebra/fft/domains/basic_radix2_domain_aux.hpp>

namespace nil {
    namespace algebra {
        namespace fft {
            template<typename FieldType>
            class basic_radix2_domain : public evaluation_domain<FieldType> {
            public:
                FieldType omega;

                basic_radix2_domain(const size_t m) {
                    if (m <= 1)
                        throw std::invalid_argument("basic_radix2(): expected m > 1");

                    if (!std::is_same<typename FieldType::value_type, std::complex<double>>::value) {
                        const size_t logm = static_cast<std::size_t>(std::ceil(std::log2(m)));
                        if (logm > (FieldType::s))
                            throw std::invalid_argument("basic_radix2(): expected logm <= FieldType::s");
                    }

                    try {
                        omega = unity_root<FieldType>(m);
                    } catch (const std::invalid_argument &e) {
                        throw std::invalid_argument(e.what());
                    }
                }

                void FFT(std::vector<typename FieldType::value_type> &a) {
                    if (a.size() != this->m)
                        throw std::invalid_argument("basic_radix2: expected a.size() == this->m");

                    _basic_radix2_FFT(a, omega);
                }

                void iFFT(std::vector<typename FieldType::value_type> &a) {
                    if (a.size() != this->m)
                        throw std::invalid_argument("basic_radix2: expected a.size() == this->m");

                    _basic_radix2_FFT(a, omega.inverse());

                    const FieldType sconst = FieldType(a.size()).inverse();
                    for (size_t i = 0; i < a.size(); ++i) {
                        a[i] *= sconst;
                    }
                }

                std::vector<typename FieldType::value_type> evaluate_all_lagrange_polynomials(const FieldType &t) {
                    return basic_radix2_evaluate_all_lagrange_polynomials(this->m, t);
                }

                FieldType get_domain_element(const size_t idx) {
                    return omega ^ idx;
                }

                FieldType compute_vanishing_polynomial(const FieldType &t) {
                    return (t ^ this->m) - FieldType::one();
                }

                void add_poly_Z(const FieldType &coeff, std::vector<typename FieldType::value_type> &H) {
                    if (H.size() != this->m + 1)
                        throw std::invalid_argument("basic_radix2: expected H.size() == this->m+1");

                    H[this->m] += coeff;
                    H[0] -= coeff;
                }

                void divide_by_Z_on_coset(std::vector<typename FieldType::value_type> &P) {
                    const FieldType coset = FieldType::multiplicative_generator;
                    const FieldType Z_inverse_at_coset = this->compute_vanishing_polynomial(coset).inverse();
                    for (size_t i = 0; i < this->m; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }
            };
        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP
