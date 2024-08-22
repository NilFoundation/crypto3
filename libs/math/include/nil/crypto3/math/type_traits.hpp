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
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            // Type trait to check if a given structure is math::polynomial.
            template<typename T>
            struct is_polynomial : std::integral_constant<bool, false> {};

            template<typename FieldValueType>
            struct is_polynomial<nil::crypto3::math::polynomial<FieldValueType>> : std::integral_constant<bool, true> { };

            template<typename T>
            struct is_polynomial_dfs : std::integral_constant<bool, false> {};

            template<typename FieldValueType>
            struct is_polynomial_dfs<nil::crypto3::math::polynomial_dfs<FieldValueType>> : std::integral_constant<bool, true> { };

        }    // namespace math
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MATH_TYPE_TRAITS_HPP
