//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MATH_LAGRANGE_INTERPOLATION_HPP
#define CRYPTO3_MATH_LAGRANGE_INTERPOLATION_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            // Default implementation according to Wikipedia
            // https://en.wikipedia.org/wiki/Lagrange_polynomial
            template<typename InputRange,
                     typename FieldValueType =
                         typename std::iterator_traits<typename InputRange::iterator>::value_type::first_type>
            typename std::enable_if<
                std::is_same<std::pair<FieldValueType, FieldValueType>,
                             typename std::iterator_traits<typename InputRange::iterator>::value_type>::value,
                polynomial<FieldValueType>>::type
                lagrange_interpolation(const InputRange &points) {

                std::size_t k = std::size(points);

                polynomial<FieldValueType> result;
                for (std::size_t j = 0; j < k; ++j) {
                    polynomial<FieldValueType> term({points[j].second});
                    for (std::size_t m = 0; m < k; ++m) {
                        if (m != j) {
                            term = term * (polynomial<FieldValueType>({-points[m].first, FieldValueType::one()}) /
                                           polynomial<FieldValueType>({points[j].first - points[m].first}));
                        }
                    }
                    result = result + term;
                }
                return result;
            }
        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_LAGRANGE_INTERPOLATION_HPP
