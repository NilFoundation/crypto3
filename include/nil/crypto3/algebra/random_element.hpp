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

#ifndef CRYPTO3_ALGEBRA_RANDOM_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_RANDOM_ELEMENT_HPP

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/multiprecision/debug_adaptor.hpp>
#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <boost/core/ignore_unused.hpp>

#include <boost/random/independent_bits.hpp>
#include <boost/random/discard_block.hpp>
#include <boost/random/xor_combine.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/random_number_generator.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/uniform_smallint.hpp>
#include <boost/random/discrete_distribution.hpp>
#include <boost/random/random_device.hpp>

#include <random>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            template<
                typename FieldType,
                typename DistributionType = boost::random::uniform_int_distribution<typename FieldType::modulus_type>,
                typename GeneratorType = boost::random::mt19937>
            typename std::enable_if<is_field<FieldType>::value &&
                                        !(is_extended_field<FieldType>::value),
                                    typename FieldType::value_type>::type
                random_element() {

                using field_type = FieldType;
                using distribution_type = DistributionType;
                using generator_type = GeneratorType;

                distribution_type d(0, field_type::modulus);

                boost::random_device rd;
                // rd.seed(time(0));

                typename field_type::value_type value(d(rd));

                return value;
            }

            template<
                typename FieldType,
                typename DistributionType = boost::random::uniform_int_distribution<typename FieldType::modulus_type>,
                typename GeneratorType = boost::random::mt19937>
            typename std::enable_if<is_field<FieldType>::value
                                        && is_extended_field<FieldType>::value,
                                    typename FieldType::value_type>::type
                random_element() {

                using field_type = FieldType;
                using distribution_type = DistributionType;
                using generator_type = GeneratorType;

                typename field_type::value_type::data_type data;
                const std::size_t data_dimension = field_type::arity / field_type::underlying_field_type::arity;

                for (int n = 0; n < data_dimension; ++n) {
                    data[n] =
                        random_element<typename FieldType::underlying_field_type, distribution_type, generator_type>();
                }

                return typename field_type::value_type(data);
            }

            template<typename CurveGroupType,
                     typename DistributionType = boost::random::uniform_int_distribution<
                         typename CurveGroupType::underlying_field_type::modulus_type>,
                     typename GeneratorType = boost::random::mt19937>
            typename std::enable_if<is_curve_group<CurveGroupType>::value,
                                    typename CurveGroupType::value_type>::type
                random_element() {

                using curve_type = typename CurveGroupType::curve_type;
                using field_type = typename curve_type::scalar_field_type;
                using distribution_type = boost::random::uniform_int_distribution<typename field_type::modulus_type>;
                using generator_type = GeneratorType;
            

                return random_element<typename curve_type::scalar_field_type, distribution_type, generator_type>() *
                       CurveGroupType::value_type::one();
            }

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_RANDOM_ELEMENT_HPP
