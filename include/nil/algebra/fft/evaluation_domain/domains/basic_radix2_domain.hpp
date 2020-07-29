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

#include <nil/algebra/fft/evaluation_domain/evaluation_domain.hpp>
#include <nil/algebra/fft/evaluation_domain/domains/basic_radix2_domain_aux.hpp>

namespace nil {
    namespace algebra {
        namespace fft {
            template<typename FieldType, std::size_t MinSize>
            struct basic_radix2_domain : public evaluation_domain<FieldType, MinSize> {
                static_assert(MinSize > 1, "m is expected to be > 1");
                static_assert(boost::static_log2<MinSize>::value <= FieldType::s, "expected logm <= FieldType::s");

                constexpr static const std::size_t min_size = MinSize;
                constexpr static const std::size_t omega = detail::unity_root<FieldType>(MinSize);

                void FFT(std::vector<FieldType> &a) {
                    if (a.size() != MinSize)
                        throw DomainSizeException("basic_radix2: expected a.size() == MinSize");

                    _basic_radix2_FFT(a, omega);
                }

                void iFFT(std::vector<FieldType> &a) {
                    if (a.size() != MinSize)
                        throw DomainSizeException("basic_radix2: expected a.size() == MinSize");

                    _basic_radix2_FFT(a, omega.inverse());

                    const FieldType sconst = FieldType(a.size()).inverse();
                    for (size_t i = 0; i < a.size(); ++i) {
                        a[i] *= sconst;
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
                    return detail::basic_radix2_evaluate_all_lagrange_polynomials(MinSize, t);
                }

                FieldType get_domain_element(const size_t idx) {
                    return omega ^ idx;
                }

                FieldType compute_vanishing_polynomial(const FieldType &t) {
                    return (t ^ MinSize) - FieldType::one();
                }

                void add_poly_Z(const FieldType &coeff, std::vector<FieldType> &H) {
                    if (H.size() != MinSize + 1)
                        throw DomainSizeException("basic_radix2: expected H.size() == MinSize+1");

                    H[MinSize] += coeff;
                    H[0] -= coeff;
                }

                void divide_by_Z_on_coset(std::vector<FieldType> &P) {
                    const FieldType coset = FieldType::multiplicative_generator;
                    const FieldType Z_inverse_at_coset = compute_vanishing_polynomial(coset).inverse();
                    for (size_t i = 0; i < MinSize; ++i) {
                        P[i] *= Z_inverse_at_coset;
                    }
                }

            private:
                typename FieldType::value_type omega;
            };
        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_BASIC_RADIX2_DOMAIN_HPP
