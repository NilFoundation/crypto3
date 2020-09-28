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

#include <nil/crypto3/fft/domains/arithmetic_sequence_domain.hpp>
#include <nil/crypto3/fft/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/fft/domains/extended_radix2_domain.hpp>
#include <nil/crypto3/fft/domains/geometric_sequence_domain.hpp>
#include <nil/crypto3/fft/domains/step_radix2_domain.hpp>

#include <nil/crypto3/fft/detail/field_utils.hpp>
#include <nil/crypto3/fft/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace fft {
            namespace detail {

                using namespace nil::crypto3::algebra;

                /*template<typename FieldType, std::size_t MinSize>
                struct domain_switch {

                    typedef std::shared_ptr<evaluation_domain<FieldType>> ret_type;

                    constexpr static const std::size_t big = 1ul << (boost::static_log2<MinSize>::value - 1);
                    constexpr static const std::size_t rounded_small = (1ul << boost::static_log2<MinSize - big>::value);

                    typename std::enable_if<is_basic_radix2_domain<FieldType, MinSize>::value, ret_type>::type 
                        get_evaluation_domain() {
                        ret_type result;
                        result.reset(new basic_radix2_domain<FieldType, MinSize>());
                        return result;
                    }

                    typename std::enable_if<!is_basic_radix2_domain<FieldType, MinSize>::value && 
                                             is_basic_radix2_domain<FieldType, big + rounded_small>::value, ret_type>::type 
                        get_evaluation_domain() {
                        ret_type result;
                        result.reset(new basic_radix2_domain<FieldType, big + rounded_small>());
                        return result;
                    }

                    typename std::enable_if<is_extended_radix2_domain<FieldType, MinSize>::value, ret_type>::type 
                        get_evaluation_domain() {
                        ret_type result;
                        result.reset(new extended_radix2_domain<FieldType, MinSize>());
                        return result;
                    }

                    typename std::enable_if<!is_extended_radix2_domain<FieldType, MinSize>::value &&
                                             is_extended_radix2_domain<FieldType, big + rounded_small>::value, ret_type>::type 
                        get_evaluation_domain() {
                        ret_type result;
                        result.reset(new extended_radix2_domain<FieldType, big + rounded_small>());
                        return result;
                    }

                    typename std::enable_if<is_step_radix2_domain<FieldType, MinSize>::value, ret_type>::type 
                        get_evaluation_domain() {
                        ret_type result;
                        result.reset(new step_radix2_domain<FieldType, MinSize>());
                        return result;
                    }

                    typename std::enable_if<!is_step_radix2_domain<FieldType, MinSize>::value && 
                                             is_step_radix2_domain<FieldType, big + rounded_small>::value, ret_type>::type 
                        get_evaluation_domain() {
                        ret_type result;
                        result.reset(new step_radix2_domain<FieldType, big + rounded_small>());
                        return result;
                    }

                    /*typename std::enable_if<FieldType::value_type(fields::arithmetic_params<FieldType>::geometric_generator) != FieldType::value_type::zero(), ret_type>::type 
                        get_evaluation_domain() {
                        ret_type result;
                        result.reset(new geometric_sequence_domain<FieldType, MinSize>());
                        return result;
                    }
                    // uncomment
                    // when constexpr field element ready

                    /*typename std::enable_if<FieldType::value_type(fields::arithmetic_params<FieldType>::arithmetic_generator) != FieldType::value_type::zero(), ret_type>::type 
                        get_evaluation_domain() {
                        ret_type result;
                        result.reset(new arithmetic_sequence_domain<FieldType, MinSize>());
                        return result;
                    }*/
                    // uncomment
                    // when constexpr field element ready
                /*};

                template<std::size_t MinSize>
                struct domain_switch<std::complex<double>, MinSize> {

                    typedef std::shared_ptr<evaluation_domain<std::complex<double>>> ret_type;

                    ret_type get_evaluation_domain() {
                        ret_type result;
                        result.reset(new basic_radix2_domain<std::complex<double>, MinSize>());
                        return result;
                    }
                };*/
            }    // namespace detail

            /**
             * An evaluation domain.
             */
            template<typename FieldType>
            class evaluation_domain {

                using value_type = typename FieldType::value_type;

            public:

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
                virtual value_type get_domain_element(const size_t idx) = 0;

                /**
                 * Compute the FFT, over the domain S, of the vector a.
                 */
                virtual void FFT(std::vector<value_type> &a) = 0;

                /**
                 * Compute the inverse FFT, over the domain S, of the vector a.
                 */
                virtual void iFFT(std::vector<value_type> &a) = 0;

                /**
                 * Evaluate all Lagrange polynomials.
                 *
                 * The inputs are:
                 * - an integer m
                 * - an element t
                 * The output is a vector (b_{0},...,b_{m-1})
                 * where b_{i} is the evaluation of L_{i,S}(z) at z = t.
                 */
                virtual std::vector<value_type> evaluate_all_lagrange_polynomials(const value_type &t) = 0;

                /**
                 * Evaluate the vanishing polynomial of S at the field element t.
                 */
                virtual value_type compute_vanishing_polynomial(const value_type &t) = 0;

                /**
                 * Add the coefficients of the vanishing polynomial of S to the coefficients of the polynomial H.
                 */
                virtual void add_poly_Z(const value_type &coeff, std::vector<value_type> &H) = 0;

                /**
                 * Multiply by the evaluation, on a coset of S, of the inverse of the vanishing polynomial of S.
                 */
                virtual void divide_by_Z_on_coset(std::vector<value_type> &P) = 0;
            };

            /*!
            @brief
             A convenience method for choosing an evaluation domain
             Returns an evaluation domain object in which the domain S has size
             |S| >= MinSize.
             The function get_evaluation_domain is chosen from different supported domains,
             depending on MinSize.
            */

            /*template<typename FieldType, std::size_t MinSize>
            struct domain_switch {
                typedef
                    typename detail::domain_switch_impl<FieldType, MinSize>::domain_type
                        domain_type;
            };*/

            template<typename FieldValueType>
            std::shared_ptr<evaluation_domain<FieldValueType>> make_evaluation_domain(std::size_t m) {
            }
        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FFT_EVALUATION_DOMAIN_HPP
