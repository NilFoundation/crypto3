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

#ifndef CRYPTO3_MATH_MAKE_EVALUATION_DOMAIN_HPP
#define CRYPTO3_MATH_MAKE_EVALUATION_DOMAIN_HPP

#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/domains/arithmetic_sequence_domain.hpp>
#include <nil/crypto3/math/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/math/domains/extended_radix2_domain.hpp>
#include <nil/crypto3/math/domains/geometric_sequence_domain.hpp>
#include <nil/crypto3/math/domains/step_radix2_domain.hpp>

#include <nil/crypto3/math/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            /*!
            @brief
             A convenience method for choosing an evaluation domain
             Returns an evaluation domain object in which the domain S has size
             |S| >= MinSize.
             The function get_evaluation_domain is chosen from different supported domains,
             depending on MinSize.
            */
            template<typename FieldType, typename ValueType = typename FieldType::value_type>
            std::shared_ptr<evaluation_domain<FieldType, ValueType>> make_evaluation_domain(std::size_t m) {

                typedef std::shared_ptr<evaluation_domain<FieldType, ValueType>> result_type;

                const std::size_t big = 1ul << (std::size_t(std::ceil(std::log2(m))) - 1);
                const std::size_t rounded_small = (1ul << std::size_t(std::ceil(std::log2(m - big))));

                if (detail::is_basic_radix2_domain<FieldType>(m)) {
                    result_type result;
                    result.reset(new basic_radix2_domain<FieldType, ValueType>(m));
                    return result;
                }

                if (detail::is_extended_radix2_domain<FieldType>(m)) {
                    result_type result;
                    result.reset(new extended_radix2_domain<FieldType, ValueType>(m));
                    return result;
                }

                if (detail::is_step_radix2_domain<FieldType>(m)) {
                    result_type result;
                    result.reset(new step_radix2_domain<FieldType, ValueType>(m));
                    return result;
                }

                if (detail::is_basic_radix2_domain<FieldType>(big + rounded_small)) {
                    result_type result;
                    result.reset(new basic_radix2_domain<FieldType, ValueType>(big + rounded_small));
                    return result;
                }

                if (detail::is_extended_radix2_domain<FieldType>(big + rounded_small)) {
                    result_type result;
                    result.reset(new extended_radix2_domain<FieldType, ValueType>(big + rounded_small));
                    return result;
                }

                if (detail::is_step_radix2_domain<FieldType>(big + rounded_small)) {
                    result_type result;
                    result.reset(new step_radix2_domain<FieldType, ValueType>(big + rounded_small));
                    return result;
                }

                if (detail::is_geometric_sequence_domain<FieldType>(m)) {
                    result_type result;
                    result.reset(new geometric_sequence_domain<FieldType, ValueType>(m));
                    return result;
                }

                if (detail::is_arithmetic_sequence_domain<FieldType>(m)) {
                    result_type result;
                    result.reset(new arithmetic_sequence_domain<FieldType, ValueType>(m));
                    return result;
                }

                return result_type();
            }
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_MAKE_EVALUATION_DOMAIN_HPP
