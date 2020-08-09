//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_EVALUATION_DOMAIN_SWITCH_HPP
#define ALGEBRA_FFT_EVALUATION_DOMAIN_SWITCH_HPP

#include <memory>

#include <nil/algebra/fft/domains/arithmetic_sequence_domain.hpp>
#include <nil/algebra/fft/domains/basic_radix2_domain.hpp>
#include <nil/algebra/fft/domains/extended_radix2_domain.hpp>
#include <nil/algebra/fft/domains/geometric_sequence_domain.hpp>
#include <nil/algebra/fft/domains/step_radix2_domain.hpp>
#include <nil/algebra/fft/evaluation_domain.hpp>

#include <nil/algebra/fft/detail/type_traits.hpp>

namespace nil {
    namespace algebra {
        namespace fft {
            namespace detail {
                template<typename FieldValueType, typename FieldType, std::size_t MinSize>
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
                                            std::conditional<
                                                FieldType::geometric_generator() != FieldType::zero(),
                                                geometric_sequence_domain<FieldType, MinSize>,
                                                std::conditional<FieldType::arithmetic_generator() != FieldType::zero(),
                                                                 arithmetic_sequence_domain<FieldType, MinSize>, void>::
                                                    type>::type>::type>::type>::type>::type>::type>::type domain_type;
                };

                template<typename FieldType, std::size_t MinSize>
                struct domain_switch_impl<std::complex<double>> {
                    typedef std::conditional<is_basic_radix2_domain<MinSize>::value,
                                             basic_radix2_domain<FieldType, MinSize>, void>::type domain_type;
                };
            }    // namespace detail

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
        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_EVALUATION_DOMAIN_SWITCH_HPP
