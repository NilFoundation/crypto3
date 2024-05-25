//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MATH_TYPE_TRAITS_HPP
#define CRYPTO3_MATH_TYPE_TRAITS_HPP

#include <vector>

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/domains/arithmetic_sequence_domain.hpp>
#include <nil/crypto3/math/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/math/domains/extended_radix2_domain.hpp>
#include <nil/crypto3/math/domains/geometric_sequence_domain.hpp>
#include <nil/crypto3/math/domains/step_radix2_domain.hpp>

#include <nil/crypto3/math/detail/field_utils.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace detail {

            /*!
            @brief
             A convenience method for choosing an evaluation domain
             Returns an evaluation domain object in which the domain S has size
             |S| >= MinSize.
             The function get_evaluation_domain is chosen from different supported domains,
             depending on MinSize.
            */
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
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_TYPE_TRAITS_HPP
