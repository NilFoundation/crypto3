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

#ifndef CRYPTO3_ALGEBRA_FIELDS_ELEMENT_OPERATIONS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_ELEMENT_OPERATIONS_HPP

#include <nil/crypto3/algebra/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                namespace detail {
                    template<typename FieldElement, typename Integral,
                             typename = typename std::enable_if<is_field_element<FieldElement>::value &&
                                                     std::is_constructible<FieldElement, Integral>::value>::type>
                    constexpr FieldElement operator+(const FieldElement &A, Integral B) {
                        return A + FieldElement(B);
                    }

                    template<typename FieldElement, typename Integral,
                             typename = typename std::enable_if<is_field_element<FieldElement>::value &&
                                                     std::is_constructible<FieldElement, Integral>::value>::type>
                    constexpr FieldElement operator-(const FieldElement &A, Integral B) {
                        return A - FieldElement(B);
                    }

                    template<typename FieldElement, typename Integral,
                             typename = typename std::enable_if<is_field_element<FieldElement>::value &&
                                                     std::is_constructible<FieldElement, Integral>::value>::type>
                    constexpr FieldElement operator*(const FieldElement &A, Integral B) {
                        return A * FieldElement(B);
                    }

                    template<typename FieldElement, typename Integral,
                             typename = typename std::enable_if<is_field_element<FieldElement>::value &&
                                                     std::is_constructible<FieldElement, Integral>::value>::type>
                    constexpr FieldElement operator/(const FieldElement &A, Integral B) {
                        //                        return element_fp2(data / B.data);
                        return A / FieldElement(B);
                    }

                    template<typename FieldElement, typename Integral,
                             typename = typename std::enable_if<is_field_element<FieldElement>::value &&
                                                     std::is_constructible<FieldElement, Integral>::value>::type>
                    constexpr FieldElement operator+(Integral A, const FieldElement &B) {
                        return FieldElement(A) + B;
                    }

                    template<typename FieldElement, typename Integral,
                             typename = typename std::enable_if<is_field_element<FieldElement>::value &&
                                 std::is_constructible<FieldElement, Integral>::value>::type>
                    constexpr FieldElement operator-(Integral A, const FieldElement &B) {
                        return FieldElement(A) - B;
                    }

                    template<typename FieldElement, typename Integral,
                             typename = typename std::enable_if<is_field_element<FieldElement>::value &&
                                 std::is_constructible<FieldElement, Integral>::value>::type>
                    constexpr FieldElement operator*(Integral A, const FieldElement &B) {
                        return FieldElement(A) * B;
                    }

                    template<typename FieldElement, typename Integral,
                             typename = typename std::enable_if<is_field_element<FieldElement>::value &&
                                 std::is_constructible<FieldElement, Integral>::value>::type>
                    constexpr FieldElement operator/(Integral A, const FieldElement &B) {
                        //                        return element_fp2(data / B.data);
                        return FieldElement(A) / B;
                    }
                }    // namespace detail
            }        // namespace fields
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // MINA_OPERATIONS_HPP
