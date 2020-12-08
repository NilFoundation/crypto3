//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELD_UTILS_HPP
#define CRYPTO3_ALGEBRA_FIELD_UTILS_HPP

#include <type_traits>
#include <complex>

#include <nil/crypto3/algebra/fields/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace fft {
            namespace detail {

                using namespace nil::crypto3::algebra;

                std::size_t bitreverse(std::size_t n, const std::size_t l) {
                    std::size_t r = 0;
                    for (std::size_t k = 0; k < l; ++k) {
                        r = (r << 1) | (n & 1);
                        n >>= 1;
                    }
                    return r;
                }

                std::size_t get_power_of_two(std::size_t n) {
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
                    return
                        typename FieldType::value_type(fields::arithmetic_params<FieldType>::multiplicative_generator)
                            .squared();
                }

                template<typename FieldType>
                typename std::enable_if<std::is_same<typename FieldType::value_type, std::complex<double>>::value,
                                        typename FieldType::value_type>::type
                    unity_root(const std::size_t n) {
                    const double PI = 3.141592653589793238460264338328L;

                    return typename FieldType::value_type(cos(2 * PI / n), sin(2 * PI / n));
                }

                template<typename FieldType>
                typename std::enable_if<!std::is_same<typename FieldType::value_type, std::complex<double>>::value,
                                        typename FieldType::value_type>::type
                    unity_root(const std::size_t n) {

                    typedef typename FieldType::value_type value_type;

                    const std::size_t logn = std::ceil(std::log2(n));

                    if (n != (1u << logn))
                        throw std::invalid_argument("expected n == (1u << logn)");
                    if (logn > fields::arithmetic_params<FieldType>::s)
                        throw std::invalid_argument("expected logn <= arithmetic_params<FieldType>::s");

                    value_type omega = value_type(fields::arithmetic_params<FieldType>::root_of_unity);
                    for (std::size_t i = fields::arithmetic_params<FieldType>::s; i > logn; --i) {
                        omega *= omega;
                    }

                    return omega;
                }
            }    // namespace detail
        }        // namespace fft
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_FIELD_UTILS_HPP
