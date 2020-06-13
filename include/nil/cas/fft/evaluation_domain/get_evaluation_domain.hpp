//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CAS_FFT_GET_EVALUATION_DOMAIN_HPP
#define CAS_FFT_GET_EVALUATION_DOMAIN_HPP

#include <memory>

#include <nil/cas/fft/evaluation_domain/evaluation_domain.hpp>

#include <nil/cas/fft/evaluation_domain/domains/arithmetic_sequence_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/basic_radix2_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/extended_radix2_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/geometric_sequence_domain.hpp>
#include <nil/cas/fft/evaluation_domain/domains/step_radix2_domain.hpp>
#include <nil/cas/fft/evaluation_domain/evaluation_domain.hpp>

#include <nil/cas/fft/tools/exceptions.hpp>

namespace nil {
    namespace cas {
        namespace fft {

            /*!
            @brief
             A convenience method for choosing an evaluation domain
             Returns an evaluation domain object in which the domain S has size
             |S| >= min_size.
             The function get_evaluation_domain is chosen from different supported domains, 
             depending on min_size.
            */


            template<std::size_t m>
            struct is_basic_radix2_domain() {
                constexpr static bool const value = (m > 1) && !(m & (m - 1)) && (ff::log2(m) <= FieldT::s);
            }

            template<std::size_t m>
            struct is_extended_radix2_domain() {
                constexpr static bool const value = (m > 1) && !(m & (m - 1)) && (ff::log2(m) == FieldT::s + 1);
            }

            template<std::size_t m>
            struct is_step_radix2_domain() {
            private:
                constexpr std::size_t const small_m = m - (1ul << (ff::log2(m) - 1));
            public:
                constexpr static bool const value = (m > 1) && (m & (m - 1)) && (ff::log2(m) <= FieldT::s) &&
                                                    !(small_m & (small_m - 1));
            }
           

            template<typename FieldT, std::size_t min_size>
            struct domain_switch {

                typedef std::shared_ptr<evaluation_domain<FieldT, min_size>> ret_type;

                constexpr std::size_t const big = 1ul << (ff::log2(min_size) - 1);
                constexpr std::size_t const rounded_small = (1ul << ff::log2(min_size - big));

                typename std::enable_if<is_basic_radix2_domain<min_size>::value, ret_type>::type 
                    get_evaluation_domain() {
                    ret_type result;
                    result.reset(new basic_radix2_domain<FieldT, min_size>());
                    return result;
                }

                typename std::enable_if<!is_basic_radix2_domain<min_size>::value && 
                                         is_basic_radix2_domain<big + rounded_small>::value, ret_type>::type 
                    get_evaluation_domain() {
                    ret_type result;
                    result.reset(new basic_radix2_domain<FieldT, big + rounded_small>());
                    return result;
                }

                typename std::enable_if<is_extended_radix2_domain<min_size>::value, ret_type>::type 
                    get_evaluation_domain() {
                    ret_type result;
                    result.reset(new extended_radix2_domain<FieldT, min_size>());
                    return result;
                }

                typename std::enable_if<!is_extended_radix2_domain<min_size>::value &&
                                         is_extended_radix2_domain<big + rounded_small>::value, ret_type>::type 
                    get_evaluation_domain() {
                    ret_type result;
                    result.reset(new extended_radix2_domain<FieldT, big + rounded_small>());
                    return result;
                }

                typename std::enable_if<is_step_radix2_domain<min_size>::value, ret_type>::type 
                    get_evaluation_domain() {
                    ret_type result;
                    result.reset(new step_radix2_domain<FieldT, min_size>());
                    return result;
                }

                typename std::enable_if<!is_step_radix2_domain<min_size>::value && 
                                         is_step_radix2_domain<big + rounded_small>::value, ret_type>::type 
                    get_evaluation_domain() {
                    ret_type result;
                    result.reset(new step_radix2_domain<FieldT, big + rounded_small>());
                    return result;
                }

                typename std::enable_if<FieldT::geometric_generator() != FieldT::zero(), ret_type>::type 
                    get_evaluation_domain() {
                    ret_type result;
                    result.reset(new geometric_sequence_domain<FieldT, min_size>());
                    return result;
                }

                typename std::enable_if<FieldT::arithmetic_generator() != FieldT::zero(), ret_type>::type 
                    get_evaluation_domain() {
                    ret_type result;
                    result.reset(new arithmetic_sequence_domain<FieldT, min_size>());
                    return result;
                }
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
    }        // namespace cas
}    // namespace nil

#endif    // CAS_FFT_GET_EVALUATION_DOMAIN_HPP
