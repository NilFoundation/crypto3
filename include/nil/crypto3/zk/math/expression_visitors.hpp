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

            template<typename VariableType>
            class expression_evaluator : public boost::static_visitor<typename VariableType::assignment_type> {
            public:
                using ValueType = typename VariableType::assignment_type;

                /** \Brief Later this class can optimize the given expression 
                           before starting the evaluation.
                 * @param expr - the expression that will be evaluated.
                 *  @param get_var_value - A function which can return the value for a given variable.
                 */
                expression_evaluator(
                    const math::expression<VariableType>& expr,
                    std::function<ValueType(const VariableType&)> get_var_value)
                        : expr(expr)
                        , get_var_value(get_var_value) {
                }

                ValueType evaluate() {
                    return boost::apply_visitor(*this, expr.expr);
                }

                ValueType operator()(const math::term<VariableType>& term) {
                    ValueType result = term.coeff;
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
                    
                    ValueType result = boost::apply_visitor(*this, op.expr_left.expr);
                    switch (op.op) {
                        case ArithmeticOperator::ADD:
                            result += boost::apply_visitor(*this, op.expr_right.expr);
                            break;
                        case ArithmeticOperator::SUB:
                            result -= boost::apply_visitor(*this, op.expr_right.expr);
                            break;
                        case ArithmeticOperator::MULT:
                            result *= boost::apply_visitor(*this, op.expr_right.expr);
                            break;
                    }
                    return result;
                }

            private:
                const math::expression<VariableType>& expr;

                // A function used to retrieve the value of a variable.
                std::function<ValueType(const VariableType &var)> get_var_value;
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
                    math::non_linear_combination<VariableType> result = 
                        boost::apply_visitor(*this, expr.expr);
                    result.merge_equal_terms();
                    return result;
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


            // Changes the underlying variable type of an expression. This is useful, when
            // we have a constraint with variable type plonk_variable<AssignmentType>
            // but we need a constraint of variable type 
            // plonk_variable<math::polynomial_dfs<typename FieldType::value_type>>.
            // You can convert between types if the coefficient types are convertable.
            template<typename SourceVariableType, typename DestinationVariableType>
            class expression_variable_type_converter
                : public boost::static_visitor<math::expression<DestinationVariableType>> {
            public:
                /*
                 * @param convert_coefficient - A function that can convert a coefficient of Source Type, into a coefficient 
                                                of the destination type.
                 */
                expression_variable_type_converter(
                    std::function<typename DestinationVariableType::assignment_type(
                        const typename SourceVariableType::assignment_type&)> convert_coefficient = 
                            [](const typename SourceVariableType::assignment_type& coeff) {return coeff;})
                    : _convert_coefficient(convert_coefficient) {
                }

                math::expression<DestinationVariableType> convert(
                        const math::expression<SourceVariableType>& expr) {
                    return boost::apply_visitor(*this, expr.expr);
                }

                math::expression<DestinationVariableType> operator()(
                        const math::term<SourceVariableType>& term) {
                    math::term<DestinationVariableType> result;
                    result.coeff = _convert_coefficient(term.coeff);
                    for (const auto& var: term.vars) {
                        result.vars.emplace_back(
                            var.index, var.rotation, var.relative,
                            static_cast<typename DestinationVariableType::column_type>(static_cast<std::uint8_t>(var.type)));
                    }
                    return result;
                }

                math::expression<DestinationVariableType> operator()(
                        const math::pow_operation<SourceVariableType>& pow) {
                    math::expression<DestinationVariableType> base = boost::apply_visitor(
                        *this, pow.expr.expr);
                    return math::pow_operation<DestinationVariableType>(base, pow.power);
                }

                math::expression<DestinationVariableType> operator()(
                        const math::binary_arithmetic_operation<SourceVariableType>& op) {
                    math::expression<DestinationVariableType> left =
                        boost::apply_visitor(*this, op.expr_left.expr);
                    math::expression<DestinationVariableType> right =
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
            private:
                std::function<typename DestinationVariableType::assignment_type(
                    const typename SourceVariableType::assignment_type&)> _convert_coefficient;

            };
        }    // namespace math
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MATH_EXPRESSION_EVALUATOR_HPP
