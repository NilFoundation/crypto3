//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_GET_EVALUATION_DOMAIN_HPP
#define ALGEBRA_FFT_GET_EVALUATION_DOMAIN_HPP

#include <memory>

#include <nil/algebra/fft/evaluation_domain/evaluation_domain.hpp>

#include <nil/algebra/fft/evaluation_domain/domains/arithmetic_sequence_domain.hpp>
#include <nil/algebra/fft/evaluation_domain/domains/basic_radix2_domain.hpp>
#include <nil/algebra/fft/evaluation_domain/domains/extended_radix2_domain.hpp>
#include <nil/algebra/fft/evaluation_domain/domains/geometric_sequence_domain.hpp>
#include <nil/algebra/fft/evaluation_domain/domains/step_radix2_domain.hpp>
#include <nil/algebra/fft/evaluation_domain/evaluation_domain.hpp>

#include <nil/algebra/fft/tools/exceptions.hpp>

#include <nil/algebra/fft/detail/type_traits.hpp>

namespace nil {
    namespace algebra {
        namespace fft {

            /*!
            @brief
             A convenience method for choosing an evaluation domain
             Returns an evaluation domain object in which the domain S has size
             |S| >= min_size.
             The function get_evaluation_domain is chosen from different supported domains,
             depending on min_size.
            */

            template<typename FieldType, std::size_t min_size>
            struct domain_switch {
                constexpr static const std::size_t big = 1ul << (boost::static_log2<min_size> - 1);
                constexpr static const std::size_t rounded_small = (1ul << boost::static_log2<min_size - big>);

                typedef std::conditional<
                    is_basic_radix2_domain<min_size>::value,
                    basic_radix2_domain<
                        FieldType, min_size,
                        std::conditional<
                            !is_basic_radix2_domain<min_size>::value &&
                                is_basic_radix2_domain<big + rounded_small>::value,
                            basic_radix2_domain<FieldType, big + rounded_small>,
                            std::conditional<
                                is_extended_radix2_domain<min_size>::value, extended_radix2_domain<FieldType, min_size>,
                                std::conditional<
                                    !is_extended_radix2_domain<min_size>::value &&
                                        is_extended_radix2_domain<big + rounded_small>::value,
                                    extended_radix2_domain<FieldType, big + rounded_small>,
                                    std::conditional<
                                        is_step_radix2_domain<min_size>::value, step_radix2_domain<FieldType, min_size>,
                                        std::conditional<
                                            !is_step_radix2_domain<min_size>::value &&
                                                is_step_radix2_domain<big + rounded_small>::value,
                                            step_radix2_domain<FieldType, big + rounded_small>,
                                            std::conditional<
                                                FieldType::geometric_generator() != FieldType::zero(),
                                                geometric_sequence_domain<FieldType, min_size>,
                                                std::conditional<FieldType::arithmetic_generator() != FieldType::zero(),
                                                                 arithmetic_sequence_domain<FieldType, min_size>,
                                                                 void>::type>::type>::type>::type>::type>::type>::
                            type>::type>::type type;
            };

            template<std::size_t min_size>
            struct domain_switch<ff::Double, min_size> {

                typedef std::shared_ptr<evaluation_domain<ff::Double, min_size>> ret_type;

                ret_type get_evaluation_domain() {
                    ret_type result;
                    result.reset(new basic_radix2_domain<ff::Double, min_size>());
                    return result;
                }
            };
        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FFT_GET_EVALUATION_DOMAIN_HPP
