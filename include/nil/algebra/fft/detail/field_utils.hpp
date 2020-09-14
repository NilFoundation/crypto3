//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELD_UTILS_HPP
#define ALGEBRA_FIELD_UTILS_HPP

#include <type_traits>
#include <complex>

namespace nil {
    namespace algebra {
        namespace fft {
            template<typename FieldType>
            FieldType coset_shift() {
                return FieldType::multiplicative_generator.squared();
            }

            template<typename FieldValueType>
            typename std::enable_if<std::is_same<FieldValueType, std::complex<double>>::value,
                                    FieldValueType>::type
                unity_root(const size_t n) {
                const double PI = 3.141592653589793238460264338328L;

                return typename FieldValueType(cos(2 * PI / n), sin(2 * PI / n));
            }

            template<typename FieldType>
            typename std::enable_if<!std::is_same<typename FieldType::value_type, std::complex<double>>::value,
                                    FieldType>::type
                unity_root(const size_t n) {
                const std::size_t logn = std::ceil(std::log2(n));
                if (n != (1u << logn))
                    throw std::invalid_argument("expected n == (1u << logn)");
                if (logn > FieldType::s)
                    throw std::invalid_argument("expected logn <= FieldType::s");

                typename FieldType::value_type omega = FieldType::root_of_unity;
                for (size_t i = FieldType::s; i > logn; --i) {
                    omega *= omega;
                }

                return omega;
            }
        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_FIELD_UTILS_HPP
