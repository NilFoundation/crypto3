//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_ZK_MATH_EXPRESSION_EVALUATOR_HPP
#define CRYPTO3_ZK_MATH_EXPRESSION_EVALUATOR_HPP

#include <vector>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/non_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {

            // ValueType is usually either VariableType::assignment_type or 
            // math::polynomial_dfs<typename VariableType::assignment_type>.
            template<typename VariableType, typename ValueType>
            class expression_evaluator : public boost::static_visitor<ValueType> {
            public:
                /** \Brief Later this class can optimize the given expression 
                           before starting the evaluation.
                 * @param expr - the expression that will be evaluated.
                 *  @param get_var_value - A function which can return the value for a given variable.
                 */
                expression_evaluator(
                    const math::expression<VariableType>& expr,
                    std::function<ValueType(const VariableType&)> get_var_value,
                    std::function<ValueType(const typename VariableType::assignment_type&)> convert_to_value_type = [](const typename VariableType::assignment_type& coeff) {return coeff;})
                        : expr(expr)
                        , get_var_value(get_var_value)
                        , convert_to_value_type(convert_to_value_type) {
                }

                ValueType evaluate() {
                    return boost::apply_visitor(*this, expr.expr);
                }

                ValueType operator()(const math::term<VariableType>& term) {
                    ValueType result = convert_to_value_type(term.coeff);
                    for (const VariableType& var : term.vars) {
                        result *= get_var_value(var);
                    }
                    return result;
                }

                ValueType operator()(
                        const math::pow_operation<VariableType>& pow) {
                    ValueType result = boost::apply_visitor(*this, pow.expr.expr);
                    return result.pow(pow.power);
                }

                ValueType operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    ValueType left = boost::apply_visitor(*this, op.expr_left.expr);
                    ValueType right = boost::apply_visitor(*this, op.expr_right.expr);
                    switch (op.op) {
                        case ArithmeticOperator::ADD:
                            return left + right;
                        case ArithmeticOperator::SUB:
                            return left - right;
                        case ArithmeticOperator::MULT:
                            return left * right;
                    }
                }

            private:
                const math::expression<VariableType>& expr;

                // A function used to retrieve the value of a variable.
                std::function<ValueType(const VariableType &var)> get_var_value;

                // Used to convert the coefficients from VariableType::assignment_type to 
                // math::polynomial_dfs<typename VariableType::assignment_type> if needed.
                std::function<ValueType(const typename VariableType::assignment_type&)> convert_to_value_type;
            };

            // Used for counting max degree of an expression.
            template<typename VariableType>
            class expression_max_degree_visitor : public boost::static_visitor<std::uint32_t> {
            public:
                expression_max_degree_visitor() {}

                std::uint32_t compute_max_degree(const math::expression<VariableType>& expr) {
                    return boost::apply_visitor(*this, expr.expr);
                }

                std::uint32_t operator()(const math::term<VariableType>& term) {
                    return term.vars.size();
                }

                std::uint32_t operator()(
                        const math::pow_operation<VariableType>& pow) {
                    std::uint32_t result = boost::apply_visitor(*this, pow.expr.expr);
                    return result * pow.power;
                }

                std::uint32_t operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    std::uint32_t left = boost::apply_visitor(*this, op.expr_left.expr);
                    std::uint32_t right = boost::apply_visitor(*this, op.expr_right.expr);
                    switch (op.op) {
                        case ArithmeticOperator::ADD:
                        case ArithmeticOperator::SUB:
                            return std::max(left, right);
                        case ArithmeticOperator::MULT:
                            return left + right;
                    }
                }
            };

            // Runs over the variables of an expression, calling the given callback function
            // for each variable. If a given variable is used multiple times,
            // the callback is called multiple times.
            template<typename VariableType>
            class expression_for_each_variable_visitor : public boost::static_visitor<void> {
            public:
                expression_for_each_variable_visitor(
                        std::function<void(const VariableType&)> callback)
                    : callback(callback) {}

                void visit(const math::expression<VariableType>& expr) {
                    boost::apply_visitor(*this, expr.expr);
                }

                void operator()(const math::term<VariableType>& term) {
                    for (const auto& var: term.vars) {
                        callback(var);
                    }                    
                }

                void operator()(
                        const math::pow_operation<VariableType>& pow) {
                    boost::apply_visitor(*this, pow.expr.expr);
                }

                void operator()(const math::binary_arithmetic_operation<VariableType>& op) {
                    boost::apply_visitor(*this, op.expr_left.expr);
                    boost::apply_visitor(*this, op.expr_right.expr);
                }

                private:
                    std::function<void(const VariableType&)> callback;
            };

            // Converts tree-structured expression to flat one, a vector of terms.
            // Used for generating solidity code for constraints, because we want 
            // to use minimal number of variables in the stack.
            template<typename VariableType>
            class expression_to_non_linear_combination_visitor 
                : public boost::static_visitor<math::non_linear_combination<VariableType>> {
            public:
                expression_to_non_linear_combination_visitor() {}

                math::non_linear_combination<VariableType> convert(
                        const math::expression<VariableType>& expr) {
                    return boost::apply_visitor(*this, expr.expr);
                }

                math::non_linear_combination<VariableType> operator()(
                        const math::term<VariableType>& term) {
                    return math::non_linear_combination<VariableType>(term);
                }

                math::non_linear_combination<VariableType> operator()(
                        const math::pow_operation<VariableType>& pow) {
                    math::non_linear_combination<VariableType> base = boost::apply_visitor(
                        *this, pow.expr.expr);
                    math::non_linear_combination<VariableType> result = base;

                    // It does not matter how we compute power here.
                    for (int i = 1; i < pow.power; ++i)
                    {
                        result = result * base;
                    }
                    return result;
                }

                math::non_linear_combination<VariableType> operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    math::non_linear_combination<VariableType> left =
                        boost::apply_visitor(*this, op.expr_left.expr);
                    math::non_linear_combination<VariableType> right =
                        boost::apply_visitor(*this, op.expr_right.expr);
                    switch (op.op) {
                        case ArithmeticOperator::ADD:
                            return left + right;
                        case ArithmeticOperator::SUB:
                            return left - right;
                        case ArithmeticOperator::MULT:
                            return left * right;
                    }
                }
            };
        }    // namespace math
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MATH_EXPRESSION_EVALUATOR_HPP
