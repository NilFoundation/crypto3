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

#ifndef CRYPTO3_ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP
#define CRYPTO3_ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/crypto3/fft/detail/field_utils.hpp>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/domains/detail/basic_radix2_domain_aux.hpp>

namespace nil {
    namespace crypto3 {
        namespace fft {

            using namespace nil::crypto3::algebra;

            template<typename FieldType>
            class evaluation_domain;

            template<typename FieldType>
            class basic_radix2_domain : public evaluation_domain<FieldType> {
                typedef typename FieldType::value_type value_type;

            public:
                value_type omega;

                basic_radix2_domain(const std::size_t m) : evaluation_domain<FieldType>(m) {
                    // if (m <= 1)
                    //    throw std::invalid_argument("basic_radix2(): expected m > 1");

                    if (!std::is_same<value_type, std::complex<double>>::value) {
                        const std::size_t logm = static_cast<std::size_t>(std::ceil(std::log2(m)));
                        // if (logm > (fields::arithmetic_params<FieldType>::s))
                        //    throw std::invalid_argument(
                        //        "basic_radix2(): expected logm <= fields::arithmetic_params<FieldType>::s");
                    }

                    omega = detail::unity_root<FieldType>(m);
                }

                void FFT(std::vector<value_type> &a) {
                    // if (a.size() != this->m)
                    //    throw std::invalid_argument("basic_radix2: expected a.size() == this->m");

                    _basic_radix2_FFT<FieldType>(a, omega);
                }

                void iFFT(std::vector<value_type> &a) {
                    // if (a.size() != this->m)
                    //    throw std::invalid_argument("basic_radix2: expected a.size() == this->m");

                    _basic_radix2_FFT<FieldType>(a, omega.inversed());

                    const value_type sconst = value_type(a.size()).inversed();
                    for (std::size_t i = 0; i < a.size(); ++i) {
                        a[i] *= sconst;
                    }
                }

                std::vector<value_type> evaluate_all_lagrange_polynomials(const value_type &t) {
                    return detail::basic_radix2_evaluate_all_lagrange_polynomials<FieldType>(this->m, t);
                }

                value_type get_domain_element(const std::size_t idx) {
                    return omega.pow(idx);
                }

                value_type compute_vanishing_polynomial(const value_type &t) {
                    return (t.pow(this->m)) - value_type::one();
                }

                void add_poly_Z(const value_type &coeff, std::vector<value_type> &H) {
                    // if (H.size() != this->m + 1)
                    //    throw std::invalid_argument("basic_radix2: expected H.size() == this->m+1");

                    H[this->m] += coeff;
                    H[0] -= coeff;
                }

                void divide_by_Z_on_coset(std::vector<value_type> &P) {
                    const value_type coset = fields::arithmetic_params<FieldType>::multiplicative_generator;
                    const value_type Z_inverse_at_coset = this->compute_vanishing_polynomial(coset).inversed();
                    for (std::size_t i = 0; i < this->m; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }
            };
        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP
