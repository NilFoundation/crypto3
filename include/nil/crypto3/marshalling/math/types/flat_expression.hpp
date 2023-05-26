//---------------------------------------------------------------------------//
// Copyright (c) 2022-2023 Martun Karapetyan <martun@nil.foundation>
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
// @file Classes for mathematical expressions:
// Flattens the expression tree into array. Used for marshalling only.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MARSHALLING_ZK_MATH_FLAT_EXPRESSION_HPP
#define CRYPTO3_MARSHALLING_ZK_MATH_FLAT_EXPRESSION_HPP

#include <vector>
#include <nil/crypto3/zk/math/expression.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            enum class flat_node_type : std::uint8_t {
                TERM = 0,
                POWER = 1,
                BINARY_ARITHMETIC = 2
            };

            struct flat_pow_operation {
                int power;

                // Type of the base expression.
                flat_node_type type;
                // Index in corresponding array.
                // if type == TERM, then this is index in array 'terms'.
                std::uint32_t child_index;
            };

            struct flat_binary_arithmetic_operation {
                ArithmeticOperator op;

                // Type of the left base expression.
                flat_node_type left_type;
                // Index in corresponding array.
                // if type == TERM, then this is index in array 'terms'.
                std::uint32_t left_index;

                // Type of the right base expression.
                flat_node_type right_type;
                // Index in corresponding array.
                // if type == TERM, then this is index in array 'terms'.
                std::uint32_t right_index;
            };

            // Storing the crypto3::math::expression class in a flat way, 
            // to be able to use it in marshalling. We put different types of nodes
            // into different vectors, and use indexes instead of pointers.
            template<typename VariableType>
            class flat_expression {
            public:
                    
                // The opposite operation of flattening, returns normal tree-structured expression.
                math::expression<VariableType> to_expression() {
                    return to_expression(root_type, root_index);
                }

                math::expression<VariableType> to_expression(
                        flat_node_type type, int node_index) {
                    switch (type) {
                        case flat_node_type::TERM:
                            return terms[node_index];
                        case flat_node_type::POWER: {
                            const auto& pow_op = pow_operations[node_index];
                            return math::pow_operation<VariableType>(
                                to_expression(pow_op.type, pow_op.child_index),
                                pow_op.power);
                        }
                        case flat_node_type::BINARY_ARITHMETIC: {
                            const auto& bin_op = binary_operations[node_index];
                            return math::binary_arithmetic_operation<VariableType>(
                                to_expression(bin_op.left_type, bin_op.left_index), 
                                to_expression(bin_op.right_type, bin_op.right_index), 
                                bin_op.op);
                        }
                    }
                }

                std::vector<math::term<VariableType>> terms;
                std::vector<flat_pow_operation> pow_operations;
                std::vector<flat_binary_arithmetic_operation> binary_operations;

                // Type of the base expression.
                flat_node_type root_type;
                    
                // Index in corresponding array.
                // if type == TERM, then this is index in array 'terms'.
                std::uint32_t root_index;

            };
    
            // Class for creating a flat_expression from expression. 
            template<typename VariableType>
            class expression_flattener : public boost::static_visitor<void> {
            public:
                expression_flattener(const math::expression<VariableType>& expr) {
                    boost::apply_visitor(*this, expr.expr);
                }

                const flat_expression<VariableType>& get_result() const {
                    return result;
                }
    
                void operator()(const math::term<VariableType>& term) {
                    result.terms.push_back(term);

                    result.root_type = flat_node_type::TERM;
                    result.root_index = result.terms.size() - 1;
                }

                void operator()(
                        const math::pow_operation<VariableType>& pow) {
                    boost::apply_visitor(*this, pow.expr.expr);
                    result.pow_operations.push_back({pow.power, result.root_type, result.root_index});

                    result.root_type = flat_node_type::POWER;
                    result.root_index = result.pow_operations.size() - 1;
                }

                void operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    flat_binary_arithmetic_operation flat_op;
                    flat_op.op = op.op;

                    boost::apply_visitor(*this, op.expr_left.expr);
                    flat_op.left_type = result.root_type;
                    flat_op.left_index = result.root_index; 

                    boost::apply_visitor(*this, op.expr_right.expr);
                    flat_op.right_type = result.root_type;
                    flat_op.right_index = result.root_index; 

                    result.binary_operations.push_back(flat_op);

                    result.root_type = flat_node_type::BINARY_ARITHMETIC;
                    result.root_index = result.binary_operations.size() - 1;
                }

            private:
                flat_expression<VariableType> result;
            };

        }        // namespace math
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_MATH_FLAT_EXPRESSION_HPP
