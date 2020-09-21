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

#include <nil/algebra/fields/params.hpp>

namespace nil {
    namespace algebra {
        namespace fft {
            namespace detail {

                using namespace nil::algebra;

                size_t bitreverse(size_t n, const size_t l) {
                    size_t r = 0;
                    for (size_t k = 0; k < l; ++k) {
                        r = (r << 1) | (n & 1);
                        n >>= 1;
                    }
                    return r;
                }

                size_t get_power_of_two(size_t n) {
                    n--;
                    n |= n >> 1;
                    n |= n >> 2;
                    n |= n >> 4;
                    n |= n >> 8;
                    n |= n >> 16;
                    n++;

                    return n;
                }

                template<typename FieldType>
                typename FieldType::value_type coset_shift() {
                    return value_type(fields::arithmetic_params<FieldType>::multiplicative_generator).squared();
                }

                template<typename FieldType>
                typename std::enable_if<std::is_same<typename FieldType::value_type, std::complex<double>>::value,
                                        typename FieldType::value_type>::type
                    unity_root(const size_t n) {
                    const double PI = 3.141592653589793238460264338328L;

                    return FieldType::value_type(cos(2 * PI / n), sin(2 * PI / n));
                }

                template<typename FieldType>
                typename std::enable_if<!std::is_same<typename FieldType::value_type, std::complex<double>>::value,
                                        typename FieldType::value_type>::type
                    unity_root(const size_t n) {

                    using value_type = typename FieldType::value_type;

                    const std::size_t logn = std::ceil(std::log2(n));
                    const std::size_t s_ = fields::arithmetic_params<FieldType>::s;

                    if (n != (1u << logn)){
                        throw std::invalid_argument("expected n == (1u << logn)");
                    }
                    
                    if (logn > s_){
                        throw std::invalid_argument("expected logn <= arithmetic_params<FieldType>::s");
                    }

                    value_type omega = value_type( fields::arithmetic_params<FieldType>::root_of_unity );
                    for (size_t i = fields::arithmetic_params<FieldType>::s; i > logn; --i) {
                        omega *= omega;
                    }

                    return omega;
                }
            }
        }    // namespace fft
    }        // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_FIELD_UTILS_HPP
