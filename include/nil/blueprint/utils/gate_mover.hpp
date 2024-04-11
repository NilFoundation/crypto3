//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#pragma once

#include <functional>

#include <boost/variant/static_visitor.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/math/expression.hpp>

namespace nil {
    namespace blueprint {
        template<typename BlueprintFieldType>
        class gate_mover : public boost::static_visitor<
                nil::crypto3::math::expression<nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>>> {

            using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            std::function<var(var)> var_mover;
        public:
            using expression = nil::crypto3::math::expression<var>;
            using term_type = nil::crypto3::math::term<var>;
            using pow_operation = nil::crypto3::math::pow_operation<var>;
            using binary_arithmetic_operation = nil::crypto3::math::binary_arithmetic_operation<var>;

            gate_mover(std::function<var(var)> var_mover_) : var_mover(var_mover_) {}

            expression visit(const expression& expr) {
                return boost::apply_visitor(*this, expr.get_expr());
            }

            expression operator()(const term_type& term) {
                std::vector<var> vars;
                auto coeff = term.get_coeff();
                for (const auto& var: term.get_vars()) {
                    vars.emplace_back(var_mover(var));
                }
                term_type result(vars, coeff);
                return result;
            }

            expression operator()(const pow_operation& pow) {
                expression base = boost::apply_visitor(
                    *this, pow.get_expr().get_expr());
                return pow_operation(base, pow.get_power());
            }

            expression operator()(
                    const binary_arithmetic_operation& op) {
                expression left =
                    boost::apply_visitor(*this, op.get_expr_left().get_expr());
                expression right =
                    boost::apply_visitor(*this, op.get_expr_right().get_expr());
                switch (op.get_op()) {
                    case nil::crypto3::math::ArithmeticOperator::ADD:
                        return left + right;
                    case nil::crypto3::math::ArithmeticOperator::SUB:
                        return left - right;
                    case nil::crypto3::math::ArithmeticOperator::MULT:
                        return left * right;
                    default:
                        __builtin_unreachable();
                }
            }
        };
    }    // namespace blueprint
}    // namespace nil