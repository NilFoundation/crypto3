//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_UTILS_HPP
#define CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_UTILS_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    using namespace nil::crypto3::algebra::fields::detail;

                    template<typename FieldParams>
                    inline bool sgn0(const element_fp<FieldParams> &e) {
                        using number_type = typename element_fp<FieldParams>::number_type;

                        static const number_type two = number_type(2, element_fp<FieldParams>::modulus);

                        return static_cast<bool>(e.data % two);
                    }

                    template<typename FieldParams>
                    inline bool sgn0(const element_fp2<FieldParams> &e) {
                        using underlying_type = typename element_fp2<FieldParams>::underlying_type;
                        typedef typename underlying_type::number_type number_type;

                        static const number_type two = number_type(2, underlying_type::modulus);

                        number_type sign_0 = e.data[0].data % two;
                        bool zero_0 = e.data[0].data.is_zero();
                        number_type sign_1 = e.data[1].data % two;
                        return static_cast<bool>(sign_0) || (zero_0 && static_cast<bool>(sign_1));
                    }
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_UTILS_HPP
