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
// - a variable (i.e., x_i),
// - a linear term (i.e., a_i * x_i), and
// - a linear combination (i.e., sum_i a_i * x_i).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_VARIABLE_HPP
#define CRYPTO3_ZK_VARIABLE_HPP

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Forward declaration.
                 */
                template<typename FieldType, bool RotationSupport>
                struct linear_term;

                /**
                 * Forward declaration.
                 */
                template<typename FieldType, bool RotationSupport>
                struct linear_combination;

                /********************************* Variable **********************************/

                template<typename FieldType, bool RotationSupport = false>
                struct variable;

                /**
                 * A variable represents a formal expression of the form "x_{index}".
                 */
                template<typename FieldType>
                class variable<FieldType, false> {

                    constexpr static const bool RotationSupport = false;

                public:
                    /**
                     * Mnemonic typedefs.
                     */
                    typedef long integer_coeff_type;
                    typedef std::size_t index_type;
                    index_type index;

                    variable(const index_type index = 0) : index(index) {};

                    linear_term<FieldType, RotationSupport> operator*(const integer_coeff_type int_coeff) const {
                        return linear_term<FieldType, RotationSupport>(*this)* int_coeff;
                    }

                    linear_term<FieldType, RotationSupport> operator*(const typename FieldType::value_type &field_coeff) const {
                        return linear_term<FieldType, RotationSupport>(*this)* field_coeff;
                    }

                    linear_combination<FieldType, RotationSupport> operator+(const linear_combination<FieldType, RotationSupport> &other) const {
                        linear_combination<FieldType, RotationSupport> result;

                        result.add_term(*this);
                        result.terms.insert(result.terms.begin(), other.terms.begin(), other.terms.end());

                        return result;
                    }

                    linear_combination<FieldType, RotationSupport> operator-(const linear_combination<FieldType, RotationSupport> &other) const {
                        return (*this) + (-other);
                    }

                    linear_term<FieldType, RotationSupport> operator-() const {
                        return linear_term<FieldType, RotationSupport>(*this) * (-FieldType::value_type::one());
                    }

                    bool operator==(const variable<FieldType> &other) const {
                        return (this->index == other.index);
                    }
                };

                /**
                 * A variable represents a formal expression of the form "w^{index}_{rotation}".
                 */
                template<typename FieldType>
                class variable<FieldType, true> {

                    constexpr static const bool RotationSupport = false;

                public:

                    /**
                     * Mnemonic typedefs.
                     */
                    typedef long integer_coeff_type;
                    typedef std::size_t wire_index_type;
                    enum rotation_type{
                        pre_previous = -2,
                        previous,
                        current,
                        nex,
                        after_next
                    };
                    wire_index_type index;
                    rotation_type rotation;

                    variable(const wire_index_type index = 0, rotation_type rotation = rotation_type::current) : 
                        index(index), rotation(rotation) {};

                    linear_term<FieldType, RotationSupport> operator*(const integer_coeff_type int_coeff) const {
                        return linear_term<FieldType, RotationSupport>(*this) * int_coeff;
                    }

                    // non_linear_term<FieldType, RotationSupport> operator^(const integer_coeff_type power) const {
                    //     return non_linear_term<FieldType, RotationSupport>(*this, power);
                    // }

                    linear_term<FieldType, RotationSupport> operator*(const typename FieldType::value_type &field_coeff) const {
                        return linear_term<FieldType, RotationSupport>(*this) * field_coeff;
                    }

                    linear_combination<FieldType, RotationSupport> operator+(const linear_combination<FieldType, RotationSupport> &other) const {
                        linear_combination<FieldType, RotationSupport> result;

                        result.add_term(*this);
                        result.terms.insert(result.terms.begin(), other.terms.begin(), other.terms.end());

                        return result;
                    }

                    linear_combination<FieldType, RotationSupport> operator-(const linear_combination<FieldType, RotationSupport> &other) const {
                        return (*this) + (-other);
                    }

                    linear_term<FieldType, RotationSupport> operator-() const {
                        return linear_term<FieldType, RotationSupport>(*this) * ( -FieldType::value_type::one());
                    }

                    bool operator==(const variable<FieldType> &other) const {
                        return ((this->index == other.index) && (this->rotation == other.rotation));
                    }
                };

                template<typename FieldType, bool RotationSupport>
                linear_term<FieldType, RotationSupport> operator*(const typename variable<FieldType, RotationSupport>::integer_coeff_type int_coeff, 
                                                 const variable<FieldType, RotationSupport> &var) {
                    return var * int_coeff;
                }

                template<typename FieldType, bool RotationSupport>
                linear_term<FieldType, RotationSupport> operator*(const typename FieldType::value_type &field_coeff,
                                                 const variable<FieldType, RotationSupport> &var) {
                    return var * field_coeff;
                }

                template<typename FieldType, bool RotationSupport>
                linear_combination<FieldType, RotationSupport> operator+(const typename variable<FieldType, RotationSupport>::integer_coeff_type int_coeff,
                                                        const variable<FieldType, RotationSupport> &var) {
                    return var + int_coeff;
                }

                template<typename FieldType, bool RotationSupport>
                linear_combination<FieldType, RotationSupport> operator+(const typename FieldType::value_type &field_coeff,
                                                        const variable<FieldType, RotationSupport> &var) {
                    return var + field_coeff;
                }

                template<typename FieldType, bool RotationSupport>
                linear_combination<FieldType, RotationSupport> operator-(const typename variable<FieldType, RotationSupport>::integer_coeff_type int_coeff,
                                                        const variable<FieldType, RotationSupport> &var) {
                    return linear_combination<FieldType, RotationSupport>(int_coeff) - var;
                }

                template<typename FieldType, bool RotationSupport>
                linear_combination<FieldType, RotationSupport> operator-(const typename FieldType::value_type &field_coeff,
                                                        const variable<FieldType, RotationSupport> &var) {
                    return linear_combination<FieldType, RotationSupport>(field_coeff) - var;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_VARIABLE_HPP
