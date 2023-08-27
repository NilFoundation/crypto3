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

#ifndef CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP
#define CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP

#include <vector>
#include <boost/variant/static_visitor.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/non_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace math {
            // Used for counting max degree of an expression.
            template<typename VariableType>
            class expression_max_degree_visitor : public boost::static_visitor<std::uint32_t> {
            public:
                expression_max_degree_visitor() {}

                std::uint32_t compute_max_degree(const math::expression<VariableType>& expr) {
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                std::uint32_t operator()(const math::term<VariableType>& term) {
                    return term.get_vars().size();
                }

                std::uint32_t operator()(
                        const math::pow_operation<VariableType>& pow) {
                    std::uint32_t result = boost::apply_visitor(*this, pow.get_expr().get_expr());
                    return result * pow.get_power();
                }

                std::uint32_t operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    std::uint32_t left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    std::uint32_t right = boost::apply_visitor(*this, op.get_expr_right().get_expr());
                    switch (op.get_op()) {
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
                    boost::apply_visitor(*this, expr.get_expr());
                }

                void operator()(const math::term<VariableType>& term) {
                    for (const auto& var: term.get_vars()) {
                        callback(var);
                    }                    
                }

                void operator()(
                        const math::pow_operation<VariableType>& pow) {
                    boost::apply_visitor(*this, pow.get_expr().get_expr());
                }

                void operator()(const math::binary_arithmetic_operation<VariableType>& op) {
                    boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    boost::apply_visitor(*this, op.get_expr_right().get_expr());
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
                        boost::apply_visitor(*this, expr.get_expr());
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
                        *this, pow.get_expr().get_expr());
                    math::non_linear_combination<VariableType> result = base;

                    // It does not matter how we compute power here.
                    for (int i = 1; i < pow.get_power(); ++i)
                    {
                        result = result * base;
                    }
                    return result;
                }

                math::non_linear_combination<VariableType> operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    math::non_linear_combination<VariableType> left =
                        boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    math::non_linear_combination<VariableType> right =
                        boost::apply_visitor(*this, op.get_expr_right().get_expr());
                    switch (op.get_op()) {
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
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                math::expression<DestinationVariableType> operator()(
                        const math::term<SourceVariableType>& term) {
                    std::vector<DestinationVariableType> vars;
                    for (const auto& var: term.get_vars()) {
                        vars.emplace_back(
                            var.index, var.rotation, var.relative,
                            static_cast<typename DestinationVariableType::column_type>(static_cast<std::uint8_t>(var.type)));
                    }
                    return math::term<DestinationVariableType>(std::move(vars), _convert_coefficient(term.get_coeff()));
                }

                math::expression<DestinationVariableType> operator()(
                        const math::pow_operation<SourceVariableType>& pow) {
                    math::expression<DestinationVariableType> base = boost::apply_visitor(
                        *this, pow.get_expr().get_expr());
                    return math::pow_operation<DestinationVariableType>(base, pow.get_power());
                }

                math::expression<DestinationVariableType> operator()(
                        const math::binary_arithmetic_operation<SourceVariableType>& op) {
                    math::expression<DestinationVariableType> left =
                        boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    math::expression<DestinationVariableType> right =
                        boost::apply_visitor(*this, op.get_expr_right().get_expr());
                    switch (op.get_op()) {
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

            // If a given expression is a multiplication of multiple subexpressions, 
            // returns a vector of those multiplier expressions. 
            template<typename VariableType>
            class expression_multipliers_visitor 
                : public boost::static_visitor<std::vector<math::expression<VariableType>>> {
            public:
                expression_multipliers_visitor() {}

                std::vector<math::expression<VariableType>> visit(
                        const math::expression<VariableType>& expr) {
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                std::vector<math::expression<VariableType>> operator()(
                        const math::term<VariableType>& term) {
                    std::vector<math::expression<VariableType>> result;
                    std::vector<VariableType> vars = term.get_vars();
                    if (vars.size() <= 1) {
                        result.push_back(term);
                    } else {
                        // Divide the term into separate expressions for each variable.
                        result.push_back(math::term<VariableType>({vars[0]}, term.get_coeff()));
                        for (size_t i = 1; i < vars.size(); ++i) {
                            result.push_back(math::term<VariableType>(vars[i]));
                        }
                    }
                    return result;
                }

                std::vector<math::expression<VariableType>> operator()(
                        const math::pow_operation<VariableType>& pow) {
                    // We may consider changing this, but not now.
                    return {pow};
                }

                std::vector<math::expression<VariableType>> operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                   switch (op.get_op()) {
                        case ArithmeticOperator::ADD:
                        case ArithmeticOperator::SUB:
                            return {op};
                        case ArithmeticOperator::MULT:
                            std::vector<math::expression<VariableType>> left =
                                boost::apply_visitor(*this, op.get_expr_left().get_expr());
                            std::vector<math::expression<VariableType>> right =
                                boost::apply_visitor(*this, op.get_expr_right().get_expr());
                            left.insert(left.end(), std::make_move_iterator(right.begin()),
                                std::make_move_iterator(right.end()));
                            return left;
                    }
                }
            };


            // Balances the degrees of subexpressions of an expression as much as possible.
            // for example (x1 * (x2 * (x3 * (x4 * (x5 + x6))))) is more balanced as (x1 * (x2 * x3)) * (x4 * (x5 + x6))))).
            template<typename VariableType>
            class expression_balancing_visitor
                : public boost::static_visitor<math::expression<VariableType>> {
            public:
                expression_balancing_visitor() {}

                math::expression<VariableType> balance(
                        const math::expression<VariableType>& expr) {
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                math::expression<VariableType> operator()(
                        const math::term<VariableType>& term) {
                    // Divide the term into multiple multiplications.
                    if (term.get_vars().size() < 4) {
                        return term;
                    }
                    std::vector<VariableType> vars = term.get_vars();
                    math::term<VariableType> left(
                        std::vector<VariableType>(vars.begin(), vars.begin() + vars.size() / 2),
                        term.get_coeff());
                    math::term<VariableType> right(
                        std::vector<VariableType>(vars.begin() + vars.size() / 2, vars.end()));
                    return math::binary_arithmetic_operation<VariableType>(
                        this->operator()(left), this->operator()(right),
                        ArithmeticOperator::MULT);
                }

                math::expression<VariableType> operator()(
                        const math::pow_operation<VariableType>& pow) {
                    // We may consider changing this, but not now. Most of the time it's just one variable inside.
                    return math::pow_operation<VariableType>(
                        boost::apply_visitor(*this, pow.get_expr().get_expr()), pow.get_power());
                }

                // Divides the multipliers into 2 subsets, with close to equal degrees, then 
                // recursively does the same for the subsets.
                math::expression<VariableType> balanced_product(
                    const std::vector<math::expression<VariableType>>& multipliers) {
                    // If it's 1 or 2 multipliers, we can't balance anything, just return the product.
                    if (multipliers.size() <= 2) {
                        math::expression<VariableType> result = multipliers[0];
                        for (int i = 1; i < multipliers.size(); ++i)
                            result *= multipliers[i];
                        return result;
                    }
                    // Divide multipliers into 2 subsets. 
                    std::vector<uint32_t> degrees;
                    expression_max_degree_visitor<VariableType> degree_vis;
                    for (const auto& expr: multipliers) {
                        degrees.push_back(degree_vis.compute_max_degree(expr));
                    } 
                    uint32_t total_degree = std::accumulate(degrees.begin(), degrees.end(), 0);

                    // Run a knapsack algorithm to split degrees in half.
                    std::vector<std::vector<bool>> d(multipliers.size());
                    d[0].resize(total_degree / 2 + 1);
                    d[0][0] = true;
                    if (degrees[0] <= total_degree / 2) {
                        d[0][degrees[0]] = true;
                    }
                    for (int i = 1; i < multipliers.size(); ++i) {
                        d[i] = d[i-1];
                        for (int j = degrees[i]; j <= total_degree / 2; ++j) {
                            if (d[i-1][j - degrees[i]])
                                d[i][j] = true;
                        }
                    }
                    std::vector<math::expression<VariableType>> left, right;
                    int j = total_degree / 2;
                    for (; j >= 0; --j) {
                        if (d[multipliers.size() - 1][j])
                            break;
                    }
                    for (int i = multipliers.size() - 1; i >= 0; --i) {
                        if (i == 0) {
                            left.push_back(multipliers[0]);
                        } else if (j == 0) {
                            right.push_back(multipliers[i]);
                        } else {
                            if (degrees[i] >= j && d[i-1][j - degrees[i]]) {
                                j -= degrees[i];
                                left.push_back(multipliers[i]);
                            } else {
                                right.push_back(multipliers[i]);
                            }
                        }
                    }
                    return balanced_product(left) * balanced_product(right);
                }

                math::expression<VariableType> operator()(
                        const math::binary_arithmetic_operation<VariableType>& op) {
                    // We still need to make the calls for left and right, to balance those
                    // subexpressions inside them.
                    math::expression<VariableType> left =
                        boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    math::expression<VariableType> right =
                        boost::apply_visitor(*this, op.get_expr_right().get_expr());
                    switch (op.get_op()) {
                        case ArithmeticOperator::ADD:
                            return left + right;
                        case ArithmeticOperator::SUB:
                            return left - right;
                        case ArithmeticOperator::MULT:
                            // Get all the multipliers going down the tree.
                            expression_multipliers_visitor<VariableType> multipliers_visitor;
                            std::vector<math::expression<VariableType>> multipliers = 
                                multipliers_visitor.visit(left);
                            std::vector<math::expression<VariableType>> right_multipliers = 
                                multipliers_visitor.visit(right);
                            multipliers.insert(multipliers.end(), std::make_move_iterator(right_multipliers.begin()),
                                std::make_move_iterator(right_multipliers.end()));
                            return balanced_product(multipliers);
                    }
                }
            };

        }    // namespace math
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MATH_EXPRESSION_VISITORS_HPP
