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

#ifndef CRYPTO3_ALGEBRA_FFT_MAKE_EVALUATION_DOMAIN_HPP
#define CRYPTO3_ALGEBRA_FFT_MAKE_EVALUATION_DOMAIN_HPP

#include <vector>

#include <boost/math/tools/polynomial.hpp>

#include <nil/crypto3/fft/domains/evaluation_domain.hpp>
#include <nil/crypto3/fft/domains/arithmetic_sequence_domain.hpp>
#include <nil/crypto3/fft/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/fft/domains/extended_radix2_domain.hpp>
#include <nil/crypto3/fft/domains/geometric_sequence_domain.hpp>
#include <nil/crypto3/fft/domains/step_radix2_domain.hpp>

#include <nil/crypto3/fft/detail/field_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace fft {

            /*!
            @brief
             A convenience method for choosing an evaluation domain
             Returns an evaluation domain object in which the domain S has size
             |S| >= MinSize.
             The function get_evaluation_domain is chosen from different supported domains,
             depending on MinSize.
            */

            namespace detail {
                using namespace nil::crypto3::algebra;

                template<typename FieldType>
                bool is_basic_radix2_domain(std::size_t m) {
                    const std::size_t log_m = static_cast<std::size_t>(std::ceil(std::log2(m)));

                    return (m > 1) && (log_m <= fields::arithmetic_params<FieldType>::s) && (m == (1ul << log_m));
                }

                template<typename FieldType>
                bool is_extended_radix2_domain(std::size_t m) {
                    const std::size_t log_m = static_cast<std::size_t>(std::ceil(std::log2(m)));
                    const std::size_t small_m = m / 2;
                    const std::size_t log_small_m = static_cast<std::size_t>(std::ceil(std::log2(small_m)));

                    return (m > 1) && (log_m == fields::arithmetic_params<FieldType>::s + 1) &&
                           (small_m == (1ul << log_small_m)) &&
                           (log_small_m <= fields::arithmetic_params<FieldType>::s);
                }

                template<typename FieldType>
                bool is_step_radix2_domain(std::size_t m) {
                    const std::size_t log_m = static_cast<std::size_t>(std::ceil(std::log2(m)));
                    const std::size_t shift_log_m = (1ul << log_m);
                    const std::size_t log_shift_log_m = static_cast<std::size_t>(std::ceil(std::log2(shift_log_m)));
                    const std::size_t small_m = m - (1ul << (static_cast<std::size_t>(std::ceil(std::log2(m))) - 1));
                    const std::size_t log_small_m = static_cast<std::size_t>(std::ceil(std::log2(small_m)));

                    return (m > 1) && (small_m == (1ul << log_small_m)) && (shift_log_m == (1ul << log_shift_log_m)) &&
                           (log_shift_log_m <= fields::arithmetic_params<FieldType>::s);
                }

                template<typename FieldType>
                bool is_geometric_sequence_domain(std::size_t m) {
                    return (m > 1) &&
                           (typename FieldType::value_type(fields::arithmetic_params<FieldType>::geometric_generator) !=
                            FieldType::value_type::zero());
                }

                template<typename FieldType>
                bool is_arithmetic_sequence_domain(std::size_t m) {
                    return (m > 1) && (typename FieldType::value_type(
                                           fields::arithmetic_params<FieldType>::arithmetic_generator) !=
                                       FieldType::value_type::zero());
                }

            }    // namespace detail

            template<typename FieldType>
            std::shared_ptr<evaluation_domain<FieldType>> make_evaluation_domain(std::size_t m) {
                typedef std::shared_ptr<evaluation_domain<FieldType>> ret_type;

                const std::size_t big = 1ul << (std::size_t(std::ceil(std::log2(m))) - 1);
                const std::size_t rounded_small = (1ul << std::size_t(std::ceil(std::log2(m - big))));

                if (detail::is_basic_radix2_domain<FieldType>(m)) {
                    ret_type result;
                    result.reset(new basic_radix2_domain<FieldType>(m));
                    return result;
                }

                if (detail::is_extended_radix2_domain<FieldType>(m)) {
                    ret_type result;
                    result.reset(new extended_radix2_domain<FieldType>(m));
                    return result;
                }

                if (detail::is_step_radix2_domain<FieldType>(m)) {
                    ret_type result;
                    result.reset(new step_radix2_domain<FieldType>(m));
                    return result;
                }

                if (detail::is_basic_radix2_domain<FieldType>(big + rounded_small)) {
                    ret_type result;
                    result.reset(new basic_radix2_domain<FieldType>(big + rounded_small));
                    return result;
                }

                if (detail::is_extended_radix2_domain<FieldType>(big + rounded_small)) {
                    ret_type result;
                    result.reset(new extended_radix2_domain<FieldType>(big + rounded_small));
                    return result;
                }

                if (detail::is_step_radix2_domain<FieldType>(big + rounded_small)) {
                    ret_type result;
                    result.reset(new step_radix2_domain<FieldType>(big + rounded_small));
                    return result;
                }

                if (detail::is_geometric_sequence_domain<FieldType>(m)) {
                    ret_type result;
                    result.reset(new geometric_sequence_domain<FieldType>(m));
                    return result;
                }

                if (detail::is_arithmetic_sequence_domain<FieldType>(m)) {
                    ret_type result;
                    result.reset(new arithmetic_sequence_domain<FieldType>(m));
                    return result;
                }

                return ret_type();
            }
        }    // namespace fft
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FFT_MAKE_EVALUATION_DOMAIN_HPP
