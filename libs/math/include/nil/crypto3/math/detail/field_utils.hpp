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

#ifndef CRYPTO3_MATH_FIELD_UTILS_HPP
#define CRYPTO3_MATH_FIELD_UTILS_HPP

#include <type_traits>
#include <complex>

#include <boost/math/constants/constants.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            namespace detail {

                using namespace nil::crypto3::algebra;

                inline std::size_t bitreverse(std::size_t n, const std::size_t l) {
                    std::size_t r = 0;
                    for (std::size_t k = 0; k < l; ++k) {
                        r = (r << 1) | (n & 1);
                        n >>= 1;
                    }
                    return r;
                }

                /**
                 * Determines if a number is a power of 2.
                 *
                 * @param n to test if it is a power of 2.
                 * @return is true if the unsigned int is a power of 2.
                 */
                inline bool is_power_of_two(uint32_t n) {
                    return n && !(n & (n - 1));
                }

                constexpr std::size_t power_of_two(std::size_t n) {
                    n--;
                    n |= n >> 1;
                    n |= n >> 2;
                    n |= n >> 4;
                    n |= n >> 8;
                    n |= n >> 16;
                    n |= n >> 32;
                    n++;

                    return n;
                }

                template<typename FieldType>
                typename FieldType::value_type coset_shift() {
                    return
                            typename FieldType::value_type(
                                    fields::arithmetic_params<FieldType>::multiplicative_generator)
                                    .squared();
                }

            }    // namespace detail
        }        // namespace fft
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_FIELD_UTILS_HPP
