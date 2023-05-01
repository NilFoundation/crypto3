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

#ifndef CRYPTO3_ZK_PLONK_VARIABLE_HPP
#define CRYPTO3_ZK_PLONK_VARIABLE_HPP

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace math {

            /**
             * Forward declaration.
             */
            template<typename VariableType>
            struct term;

            /**
             * Forward declaration.
             */
            template<typename VariableType>
            struct expression;
        }    // namespace math
        namespace zk {
            namespace snark {

                /********************************* Variable **********************************/

                /**
                 * A variable represents a formal expression of the form "w^{index}_{rotation}" and type type.
                 */
                template<typename FieldType>
                class plonk_variable {

                public:
                    using field_type = FieldType;
                    using assignment_type = typename FieldType::value_type;

                    /**
                     * Mnemonic typedefs.
                     */
                    std::int32_t rotation;
                    enum column_type : std::uint8_t { witness, public_input, constant, selector } type;
                    std::size_t index;
                    bool relative;

                    constexpr plonk_variable() : index(0), rotation(0), relative(false), type(column_type::witness) {};

                    constexpr plonk_variable(const std::size_t index,
                                             std::int32_t rotation,
                                             bool relative = true,
                                             column_type type = column_type::witness) :
                        index(index),
                        rotation(rotation), relative(relative), type(type) {};

                    math::expression<plonk_variable<FieldType>> pow(const std::size_t power) const {
                        return math::term<plonk_variable<FieldType>>(*this).pow(power);
                    }

                    math::term<plonk_variable<FieldType>>
                        operator*(const assignment_type &field_coeff) const {
                        return math::term<plonk_variable<FieldType>>(*this) * field_coeff;
                    }

                    math::term<plonk_variable<FieldType>> operator*(const plonk_variable &other) const {
                        return math::term<plonk_variable<FieldType>>(*this) * other;
                    }

                    math::expression<plonk_variable<FieldType>>
                        operator+(const math::expression<plonk_variable<FieldType>> &other) const {
                        math::expression<plonk_variable<FieldType>> result(*this);
                        result += other;
                        return result;
                    }

                    math::expression<plonk_variable<FieldType>>
                        operator-(const math::expression<plonk_variable<FieldType>> &other) const {
                        math::expression<plonk_variable<FieldType>> result(*this);
                        result -= other;
                        return result;
                    }

                    math::term<plonk_variable<FieldType>> operator-() const {
                        return math::term<plonk_variable<FieldType>>(*this) * (-assignment_type::one());
                    }

                    bool operator==(const plonk_variable &other) const {
                        return ((this->index == other.index) && (this->rotation == other.rotation) &&
                                this->type == other.type);
                    }

                    bool operator<(const plonk_variable &other) const {
                        return ((this->index < other.index) ||
                                ((this->index == other.index) && (this->rotation < other.rotation)));
                    }
                };

                template<typename FieldType>
                math::term<plonk_variable<FieldType>>
                    operator*(const typename FieldType::value_type &field_coeff, const plonk_variable<FieldType> &var) {
                    return var * field_coeff;
                }

                template<typename FieldType>
                math::expression<plonk_variable<FieldType>>
                    operator+(const typename FieldType::value_type &field_val, const plonk_variable<FieldType> &var) {
                    return var + field_val;
                }

                template<typename FieldType>
                math::expression<plonk_variable<FieldType>>
                    operator-(const typename FieldType::value_type &field_val, const plonk_variable<FieldType> &var) {
                    return -(var - field_val);
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_VARIABLE_HPP
