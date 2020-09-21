//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP
#define CRYPTO3_ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/crypto3/algebra/fft/detail/field_utils.hpp>

#include <nil/crypto3/algebra/fft/evaluation_domain.hpp>
#include <nil/crypto3/algebra/fft/domains/basic_radix2_domain_aux.hpp>

namespace nil { namespace crypto3 { namespace algebra {
        namespace fft {

            using namespace nil::crypto3::algebra;

            template<typename FieldType>
            class basic_radix2_domain : public evaluation_domain<FieldType::value_type> {
                using value_type = typename FieldType::value_type;
            public:
                value_type omega;

                basic_radix2_domain(const size_t m) {
                    if (m <= 1)
                        throw std::invalid_argument("basic_radix2(): expected m > 1");

                    if (!std::is_same<value_type, std::complex<double>>::value) {
                        const size_t logm = static_cast<std::size_t>(std::ceil(std::log2(m)));
                        if (logm > (fields::arithmetic_params<FieldType>::s))
                            throw std::invalid_argument("basic_radix2(): expected logm <= fields::arithmetic_params<FieldType>::s");
                    }

                    try {
                        omega = unity_root<FieldType>(m);
                    } catch (const std::invalid_argument &e) {
                        throw std::invalid_argument(e.what());
                    }
                }

                void FFT(std::vector<value_type> &a) {
                    if (a.size() != this->m)
                        throw std::invalid_argument("basic_radix2: expected a.size() == this->m");

                    _basic_radix2_FFT(a, omega);
                }

                void iFFT(std::vector<value_type> &a) {
                    if (a.size() != this->m)
                        throw std::invalid_argument("basic_radix2: expected a.size() == this->m");

                    _basic_radix2_FFT(a, omega.inversed());

                    const value_type sconst = value_type(a.size()).inversed();
                    for (size_t i = 0; i < a.size(); ++i) {
                        a[i] *= sconst;
                    }
                }

                std::vector<value_type> evaluate_all_lagrange_polynomials(const value_type &t) {
                    return basic_radix2_evaluate_all_lagrange_polynomials(this->m, t);
                }

                value_type get_domain_element(const size_t idx) {
                    return omega ^ idx;
                }

                value_type compute_vanishing_polynomial(const value_type &t) {
                    return (t ^ this->m) - value_type::one();
                }

                void add_poly_Z(const value_type &coeff, std::vector<value_type> &H) {
                    if (H.size() != this->m + 1)
                        throw std::invalid_argument("basic_radix2: expected H.size() == this->m+1");

                    H[this->m] += coeff;
                    H[0] -= coeff;
                }

                void divide_by_Z_on_coset(std::vector<value_type> &P) {
                    const value_type coset = fields::arithmetic_params<FieldType>::multiplicative_generator;
                    const value_type Z_inverse_at_coset = this->compute_vanishing_polynomial(coset).inversed();
                    for (size_t i = 0; i < this->m; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }
            };
        }    // namespace fft
    }}        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP
