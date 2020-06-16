//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CAS_FFT_BASIC_RADIX2_DOMAIN_HPP
#define CAS_FFT_BASIC_RADIX2_DOMAIN_HPP

#include <vector>

#include <nil/cas/fft/evaluation_domain/evaluation_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/basic_radix2_domain_aux.hpp>

#include <nil/algebra/fields/field_utils.hpp>
#include <nil/algebra/common/double.hpp>
#include <nil/algebra/common/utils.hpp>


namespace nil {
    namespace algebra {
        namespace fft {

            template<typename FieldT>
            struct basic_radix2_domain : public evaluation_domain<FieldT> {

                basic_radix2_domain(const size_t m) : evaluation_domain<FieldT>(m) {
                    //if (m <= 1)
                        //throw InvalidSizeException("basic_radix2(): expected m > 1");

                    if (!std::is_same<FieldT, ff::Double>::value) {
                        const size_t logm = ff::log2(m);
                        //if (logm > (FieldT::s))
                            //throw DomainSizeException("basic_radix2(): expected logm <= FieldT::s");
                    }

                    //try {
                    omega = ff::get_root_of_unity<FieldT>(m);
                    //} catch (const std::invalid_argument &e) {
                        //throw DomainSizeException(e.what());
                    //}
                }

                void FFT(std::vector<FieldT> &a) {
                    //if (a.size() != this->m)
                        //throw DomainSizeException("basic_radix2: expected a.size() == this->m");

                    _basic_radix2_FFT(a, omega);
                }

                void iFFT(std::vector<FieldT> &a) {
                    //if (a.size() != this->m)
                        //throw DomainSizeException("basic_radix2: expected a.size() == this->m");

                    _basic_radix2_FFT(a, omega.inverse());

                    const FieldT sconst = FieldT(a.size()).inverse();
                    for (size_t i = 0; i < a.size(); ++i) {
                        a[i] *= sconst;
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
                    return _basic_radix2_evaluate_all_lagrange_polynomials(this->m, t);
                }

                FieldT get_domain_element(const size_t idx) {
                    return omega ^ idx;
                }

                FieldT compute_vanishing_polynomial(const FieldT &t) {
                    return (t ^ this->m) - FieldT::one();
                }

                void add_poly_Z(const FieldT &coeff, std::vector<FieldT> &H) {
                    //if (H.size() != this->m + 1)
                        //throw DomainSizeException("basic_radix2: expected H.size() == this->m+1");

                    H[this->m] += coeff;
                    H[0] -= coeff;
                }

                void divide_by_Z_on_coset(std::vector<FieldT> &P) {
                    const FieldT coset = FieldT::multiplicative_generator;
                    const FieldT Z_inverse_at_coset = compute_vanishing_polynomial(coset).inverse();
                    for (size_t i = 0; i < this->m; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }

            private:
                FieldT omega;
            };
        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // CAS_FFT_BASIC_RADIX2_DOMAIN_HPP
