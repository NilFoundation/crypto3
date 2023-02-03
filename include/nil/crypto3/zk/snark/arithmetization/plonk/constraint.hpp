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
#include <nil/crypto3/zk/math/non_linear_combination.hpp>

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

                template<typename FieldType, typename VariableType = plonk_variable<FieldType>>
                class plonk_constraint : public math::non_linear_combination<VariableType> {
                public:
                    typedef FieldType field_type;
                    typedef VariableType variable_type;
                    typedef math::non_linear_combination<VariableType> base_type;

                    plonk_constraint() : math::non_linear_combination<VariableType>() {};

                    plonk_constraint(const VariableType &var) : math::non_linear_combination<VariableType>(var) {
                    }

                    plonk_constraint(const math::non_linear_combination<VariableType> &nlc) :
                        math::non_linear_combination<VariableType>(nlc) {
                    }

                    plonk_constraint(const math::non_linear_term<VariableType> &nlt) :
                        math::non_linear_combination<VariableType>(nlt) {
                    }

                    plonk_constraint(const std::vector<math::non_linear_term<VariableType>> &terms) :
                        math::non_linear_combination<VariableType>(terms) {
                    }

                    template<typename ArithmetizationParams>
                    typename VariableType::assignment_type
                        evaluate(std::size_t row_index,
                                 const plonk_assignment_table<FieldType, ArithmetizationParams> &assignments) const {
                        typename VariableType::assignment_type acc = VariableType::assignment_type::zero();
                        for (const math::non_linear_term<VariableType> &nlt : this->terms) {
                            typename VariableType::assignment_type term_value = nlt.coeff;

                            for (const VariableType &var : nlt.vars) {

                                typename VariableType::assignment_type assignment;
                                switch (var.type) {
                                    case VariableType::column_type::witness:
                                        assignment = assignments.witness(var.index)[row_index + var.rotation];
                                        break;
                                    case VariableType::column_type::public_input:
                                        assignment = assignments.public_input(var.index)[row_index + var.rotation];
                                        break;
                                    case VariableType::column_type::constant:
                                        assignment = assignments.constant(var.index)[row_index + var.rotation];
                                        break;
                                    case VariableType::column_type::selector:
                                        assignment = assignments.selector(var.index)[row_index + var.rotation];
                                        break;
                                }

                                term_value = term_value * assignment;
                            }
                            acc = acc + term_value;
                        }
                        return acc;
                    }

                    template<typename ArithmetizationParams>
                    math::polynomial<typename VariableType::assignment_type>
                        evaluate(const plonk_polynomial_table<FieldType, ArithmetizationParams> &assignments,
                                 std::shared_ptr<math::evaluation_domain<FieldType>>
                                     domain) const {
                        math::polynomial<typename VariableType::assignment_type> acc = {0};
                        for (const math::non_linear_term<VariableType> &nlt : this->terms) {
                            math::polynomial<typename VariableType::assignment_type> term_value = {nlt.coeff};

                            for (const VariableType &var : nlt.vars) {

                                math::polynomial<typename VariableType::assignment_type> assignment;
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

                                term_value = term_value * assignment;
                            }
                            acc = acc + term_value;
                        }
                        return acc;
                    }

                    template<typename ArithmetizationParams>
                    math::polynomial_dfs<typename VariableType::assignment_type>
                        evaluate(const plonk_polynomial_dfs_table<FieldType, ArithmetizationParams> &assignments,
                                 std::shared_ptr<math::evaluation_domain<FieldType>>
                                     domain) const {
                        math::polynomial_dfs<typename VariableType::assignment_type> acc(
                            0, assignments.rows_amount(), FieldType::value_type::zero());
                        for (const math::non_linear_term<VariableType> &nlt : this->terms) {
                            math::polynomial_dfs<typename VariableType::assignment_type> term_value(
                                0, assignments.rows_amount(), nlt.coeff);

                            for (const VariableType &var : nlt.vars) {

                                math::polynomial_dfs<typename VariableType::assignment_type> assignment;
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

                                term_value = term_value * assignment;
                            }
                            acc = acc + term_value;
                        }
                        return acc;
                    }

                    typename VariableType::assignment_type
                        evaluate(detail::plonk_evaluation_map<VariableType> &assignments) const {
                        typename VariableType::assignment_type acc = VariableType::assignment_type::zero();
                        for (const math::non_linear_term<VariableType> &nlt : this->terms) {
                            typename VariableType::assignment_type term_value = nlt.coeff;

                            for (const VariableType &var : nlt.vars) {
                                std::tuple<std::size_t, int, typename VariableType::column_type> key =
                                    std::make_tuple(var.index, var.rotation, var.type);

                                BOOST_ASSERT(assignments.count(key) > 0);
                                term_value = term_value * assignments[key];
                            }
                            acc = acc + term_value;
                        }
                        return acc;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_CONSTRAINT_HPP
