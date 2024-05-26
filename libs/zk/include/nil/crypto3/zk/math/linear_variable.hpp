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
// @file Declaration of interfaces for:
// - a linear_variable (i.e., x_i)
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MATH_LINEAR_VARIABLE_HPP
#define CRYPTO3_ZK_MATH_LINEAR_VARIABLE_HPP

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace math {

            /**
             * Forward declaration.
             */
            template<typename VariableType>
            class linear_term;

            /**
             * Forward declaration.
             */
            template<typename VariableType>
            class linear_combination;

            /********************************* Variable **********************************/

            /**
             * A variable represents a formal expression of the form "x_{index}".
             */
            template<typename FieldType>
            class linear_variable {

                using variable_type = linear_variable<FieldType>;
            public:

                using field_type = FieldType;
                using value_type = typename FieldType::value_type;
                using index_type = std::size_t;
                std::size_t index;

                linear_variable(const std::size_t index = 0) : index(index) {};

                linear_term<variable_type>
                    operator*(const typename FieldType::value_type &field_coeff) const {
                    return linear_term<variable_type>(*this) * field_coeff;
                }

                linear_combination<variable_type>
                    operator+(const linear_combination<variable_type> &other) const {
                    linear_combination<variable_type> result;

                    result.add_term(*this);
                    result.terms.insert(result.terms.begin(), other.terms.begin(), other.terms.end());

                    return result;
                }

                linear_combination<variable_type>
                    operator-(const linear_combination<variable_type> &other) const {
                    return (*this) + (-other);
                }

                linear_term<variable_type> operator-() const {
                    return linear_term<FieldType>(*this) * (-FieldType::value_type::one());
                }

                bool operator==(const linear_variable &other) const {
                    return (this->index == other.index);
                }
            };

            template<typename FieldType>
            linear_term<linear_variable<FieldType>> operator*(const typename FieldType::value_type &field_coeff,
                                                    const linear_variable<FieldType> &var) {
                return var * field_coeff;
            }

            template<typename FieldType>
            linear_combination<linear_variable<FieldType>> operator+(const typename FieldType::value_type &field_coeff,
                                                           const linear_variable<FieldType> &var) {
                return var + field_coeff;
            }

            template<typename FieldType>
            linear_combination<linear_variable<FieldType>> operator-(const typename FieldType::value_type &field_coeff,
                                                           const linear_variable<FieldType> &var) {
                return linear_combination<linear_variable<FieldType>>(field_coeff) - var;
            }

        }    // namespace math
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MATH_LINEAR_VARIABLE_HPP
