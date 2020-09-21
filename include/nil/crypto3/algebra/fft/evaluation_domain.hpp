//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FFT_EVALUATION_DOMAIN_HPP
#define CRYPTO3_ALGEBRA_FFT_EVALUATION_DOMAIN_HPP

#include <vector>

#include <boost/math/tools/polynomial.hpp>

#include <nil/crypto3/algebra/fft/domains/arithmetic_sequence_domain.hpp>
#include <nil/crypto3/algebra/fft/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/algebra/fft/domains/extended_radix2_domain.hpp>
#include <nil/crypto3/algebra/fft/domains/geometric_sequence_domain.hpp>
#include <nil/crypto3/algebra/fft/domains/step_radix2_domain.hpp>

#include <nil/crypto3/algebra/fft/detail/field_utils.hpp>
#include <nil/crypto3/algebra/fft/detail/type_traits.hpp>

namespace nil { 
    namespace crypto3 { 
        namespace algebra {
            namespace fft {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<typename FieldType, typename FieldType, std::size_t MinSize>
                    struct domain_switch_impl {
                        constexpr static const std::size_t big = 1ul << (boost::static_log2<MinSize>::value - 1);
                        constexpr static const std::size_t rounded_small =
                            (1ul << boost::static_log2<MinSize - big>::value);

                        typedef std::conditional<
                            detail::is_basic_radix2_domain<MinSize>::value, basic_radix2_domain<FieldType, MinSize>,
                        std::conditional<
                            !detail::is_basic_radix2_domain<MinSize>::value &&
                            detail::is_basic_radix2_domain<big + rounded_small>::value,
                            basic_radix2_domain<FieldType, big + rounded_small>,
                        std::conditional<
                            detail::is_extended_radix2_domain<MinSize>::value,
                            extended_radix2_domain<FieldType, MinSize>,
                        std::conditional<
                            !detail::is_extended_radix2_domain<MinSize>::value &&
                            detail::is_extended_radix2_domain<big + rounded_small>::value,
                            extended_radix2_domain<FieldType, big + rounded_small>,
                        std::conditional<
                            detail::is_step_radix2_domain<MinSize>::value,
                            step_radix2_domain<FieldType, MinSize>,
                        std::conditional<
                            !detail::is_step_radix2_domain<MinSize>::value &&
                            detail::is_step_radix2_domain<big + rounded_small>::value,
                            step_radix2_domain<FieldType, big + rounded_small>,
                        std::conditional<!(fields::arithmetic_params<FieldType>::geometric_generator.is_zero()),
                            geometric_sequence_domain<FieldType, MinSize>,
                        std::conditional<!(fields::arithmetic_params<FieldType>::arithmetic_generator.is_zero()),
                                         arithmetic_sequence_domain<FieldType, MinSize>, void>::
                        type>::type>::type>::type>::type>::type>::type>::type domain_type;
                    };

                    template<typename FieldType, std::size_t MinSize>
                    struct domain_switch_impl<std::complex<double>> {
                        typedef std::conditional<is_basic_radix2_domain<MinSize>::value,
                                                 basic_radix2_domain<FieldType, MinSize>, void>::type domain_type;
                    };
                }    // namespace detail

                /**
                 * An evaluation domain.
                 */
                template<typename FieldValueType>
                struct evaluation_domain {

                    const size_t m;

                    /**
                     * Construct an evaluation domain S of size m, if possible.
                     *
                     * (See the function get_evaluation_domain below.)
                     */
                    evaluation_domain(const size_t m) : m(m) {};

                    /**
                     * Get the idx-th element in S.
                     */
                    virtual FieldValueType get_domain_element(const size_t idx) = 0;

                    /**
                     * Compute the FFT, over the domain S, of the vector a.
                     */
                    virtual void FFT(std::vector<FieldValueType> &a) = 0;

                    /**
                     * Compute the inverse FFT, over the domain S, of the vector a.
                     */
                    virtual void iFFT(std::vector<FieldValueType> &a) = 0;

                    /**
                     * Evaluate all Lagrange polynomials.
                     *
                     * The inputs are:
                     * - an integer m
                     * - an element t
                     * The output is a vector (b_{0},...,b_{m-1})
                     * where b_{i} is the evaluation of L_{i,S}(z) at z = t.
                     */
                    virtual std::vector<FieldValueType> evaluate_all_lagrange_polynomials(const FieldValueType &t) = 0;

                    /**
                     * Evaluate the vanishing polynomial of S at the field element t.
                     */
                    virtual FieldValueType compute_vanishing_polynomial(const FieldValueType &t) = 0;

                    /**
                     * Add the coefficients of the vanishing polynomial of S to the coefficients of the polynomial H.
                     */
                    virtual void add_poly_Z(const FieldValueType &coeff, std::vector<FieldValueType> &H) = 0;

                    /**
                     * Multiply by the evaluation, on a coset of S, of the inverse of the vanishing polynomial of S.
                     */
                    virtual void divide_by_Z_on_coset(std::vector<FieldValueType> &P) = 0;
                };

                /*!
                @brief
                 A convenience method for choosing an evaluation domain
                 Returns an evaluation domain object in which the domain S has size
                 |S| >= MinSize.
                 The function get_evaluation_domain is chosen from different supported domains,
                 depending on MinSize.
                */

                template<typename FieldType, std::size_t MinSize>
                struct domain_switch {
                    typedef
                    typename detail::domain_switch_impl<typename FieldType::value_type, FieldType, MinSize>::domain_type
                        domain_type;
                };

                template<typename FieldValueType>
                std::shared_ptr<evaluation_domain<FieldValueType>> make_evaluation_domain(std::size_t m) {

                }
            }    // namespace fft
        }        // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_EVALUATION_DOMAIN_HPP
