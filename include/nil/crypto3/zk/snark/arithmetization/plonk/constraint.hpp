//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_CONSTRAINT_HPP
#define CRYPTO3_ZK_PLONK_CONSTRAINT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename VariableType>
                    using plonk_evaluation_map =
                        std::map<std::tuple<std::size_t, int, typename VariableType::column_type>,
                                 typename VariableType::assignment_type>;

                }    // namespace detail

                /************************* PLONK constraint ***********************************/

                template<typename FieldType, typename VariableType = plonk_variable<typename FieldType::value_type>>
                class plonk_constraint : public math::expression<VariableType> {
                public:
                    typedef FieldType field_type;
                    typedef VariableType variable_type;
                    typedef math::expression<VariableType> base_type;

                    plonk_constraint()
                        : math::expression<VariableType>(VariableType::assignment_type::zero()) {
                    };

                    plonk_constraint(const VariableType &var) : math::expression<VariableType>(var) {
                    }

                    plonk_constraint(const math::expression<VariableType> &nlc) :
                        math::expression<VariableType>(nlc) {
                    }

                    plonk_constraint(const math::term<VariableType> &nlt) :
                        math::expression<VariableType>(nlt) {
                    }

                    plonk_constraint(const std::vector<math::term<VariableType>> &terms) :
                        math::expression<VariableType>(VariableType::assignment_type::zero()) {
                        for (const auto& term : terms) {
                            (*this) += term;
                        }
                    }

                    typename VariableType::assignment_type
                        evaluate(std::size_t row_index,
                                 const plonk_assignment_table<FieldType> &assignments) const {
                        math::expression_evaluator<VariableType> evaluator(
                            *this,
                            [&assignments, row_index](const VariableType &var) {
                                switch (var.type) {
                                    case VariableType::column_type::witness:
                                        return assignments.witness(var.index)[row_index + var.rotation];
                                    case VariableType::column_type::public_input:
                                        return assignments.public_input(var.index)[row_index + var.rotation];
                                    case VariableType::column_type::constant:
                                        return assignments.constant(var.index)[row_index + var.rotation];
                                    case VariableType::column_type::selector:
                                        return assignments.selector(var.index)[row_index + var.rotation];
                                    default:
                                        BOOST_ASSERT_MSG(false, "Invalid column type");
                                        return VariableType::assignment_type::zero();
                                }
                            });

                        return evaluator.evaluate();
                    }

                    math::polynomial<typename VariableType::assignment_type>
                       evaluate(const plonk_polynomial_table<FieldType> &assignments,
                                std::shared_ptr<math::evaluation_domain<FieldType>>
                                    domain) const {
                       using polynomial_type = math::polynomial<typename VariableType::assignment_type>;
                       using polynomial_variable_type = plonk_variable<polynomial_type>;
                       math::expression_variable_type_converter<VariableType, polynomial_variable_type> converter;

                       math::expression_evaluator<polynomial_variable_type> evaluator(
                           converter.convert(*this),
                           [&domain, &assignments](const VariableType &var) {
                                polynomial_type assignment;
                                switch (var.type) {
                                    case VariableType::column_type::witness:
                                        assignment = assignments.witness(var.index);
                                        break;
                                    case VariableType::column_type::public_input:
                                        assignment = assignments.public_input(var.index);
                                        break;
                                    case VariableType::column_type::constant:
                                        assignment = assignments.constant(var.index);
                                        break;
                                    case VariableType::column_type::selector:
                                        assignment = assignments.selector(var.index);
                                        break;
                                }

                                if (var.rotation != 0) {
                                    assignment =
                                        math::polynomial_shift(assignment, domain->get_domain_element(var.rotation));
                                }
                                return assignment;
                            });
                        return evaluator.evaluate();
                    }

                    math::polynomial_dfs<typename VariableType::assignment_type>
                        evaluate(const plonk_polynomial_dfs_table<FieldType> &assignments,
                                 std::shared_ptr<math::evaluation_domain<FieldType>> domain) const {
                        using polynomial_dfs_type = math::polynomial_dfs<typename VariableType::assignment_type>;
                        using polynomial_dfs_variable_type = plonk_variable<polynomial_dfs_type>;

                        math::expression_variable_type_converter<variable_type, polynomial_dfs_variable_type> converter(
                            [&assignments](const typename VariableType::assignment_type& coeff) {
                                polynomial_dfs_type(0, assignments.rows_amount(), coeff);
                            });
                        math::expression_evaluator<polynomial_dfs_variable_type> evaluator(
                            converter.convert(*this),
                            [&domain, &assignments](const polynomial_dfs_variable_type &var) {
                                polynomial_dfs_type assignment;
                                switch (var.type) {
                                    case VariableType::column_type::witness:
                                        assignment = assignments.witness(var.index);
                                        break;
                                    case VariableType::column_type::public_input:
                                        assignment = assignments.public_input(var.index);
                                        break;
                                    case VariableType::column_type::constant:
                                        assignment = assignments.constant(var.index);
                                        break;
                                    case VariableType::column_type::selector:
                                        assignment = assignments.selector(var.index);
                                        break;
                                }

                                if (var.rotation != 0) {
                                    assignment = math::polynomial_shift(assignment, var.rotation, domain->m);
                                }
                                return assignment;
                            }
                        );

                        return evaluator.evaluate();
                    }

                    typename VariableType::assignment_type
                        evaluate(detail::plonk_evaluation_map<VariableType> &assignments) const {
                        math::expression_evaluator<VariableType> evaluator(
                            *this,
                            [&assignments](const VariableType &var) {
                                std::tuple<std::size_t, int, typename VariableType::column_type> key =
                                    std::make_tuple(var.index, var.rotation, var.type);

                                BOOST_ASSERT(assignments.count(key) > 0);
                                return assignments[key];
                            });

                        return evaluator.evaluate();
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_CONSTRAINT_HPP
