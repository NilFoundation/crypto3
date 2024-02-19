//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP

#include <unordered_map>
#include <iostream>
#include <memory>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ParamsType, std::size_t ArgumentSize = 1>
                struct placeholder_gates_argument;

                template<typename FieldType, typename ParamsType>
                struct placeholder_gates_argument<FieldType, ParamsType, 1> {

                    typedef typename ParamsType::transcript_hash_type transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using polynomial_dfs_type = math::polynomial_dfs<typename FieldType::value_type>;
                    using variable_type = plonk_variable<typename FieldType::value_type>;
                    using polynomial_dfs_variable_type = plonk_variable<polynomial_dfs_type>;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                    constexpr static const std::size_t argument_size = 1;

                    static inline void build_variable_value_map(
                        const math::expression<polynomial_dfs_variable_type>& expr,
                        const plonk_polynomial_dfs_table<FieldType> &assignments,
                        std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                        std::size_t extended_domain_size,
                        std::unordered_map<polynomial_dfs_variable_type, polynomial_dfs_type>& variable_values_out) {

                        std::unordered_map<polynomial_dfs_variable_type, size_t> variable_counts;

                        math::expression_for_each_variable_visitor<polynomial_dfs_variable_type> visitor(
                            [&variable_counts](const polynomial_dfs_variable_type& var) {
                                variable_counts[var]++;
                        });
                        std::shared_ptr<math::evaluation_domain<FieldType>> extended_domain =
                            math::make_evaluation_domain<FieldType>(extended_domain_size);
                        visitor.visit(expr);
                        for (const auto& [var, count]: variable_counts) {
                            // We may have variable values in required sizes in some cases.
                            if (variable_values_out.find(var) != variable_values_out.end())
                                continue;
                            polynomial_dfs_type assignment;
                            switch (var.type) {
                                case polynomial_dfs_variable_type::column_type::witness:
                                    assignment = assignments.witness(var.index);
                                    break;
                                case polynomial_dfs_variable_type::column_type::public_input:
                                    assignment = assignments.public_input(var.index);
                                    break;
                                case polynomial_dfs_variable_type::column_type::constant:
                                    assignment = assignments.constant(var.index);
                                    break;
                                case polynomial_dfs_variable_type::column_type::selector:
                                    assignment = assignments.selector(var.index);
                                    break;
                            }

                            if (var.rotation != 0) {
                                assignment = math::polynomial_shift(assignment, var.rotation, domain->m);
                            }
                            if (count > 1) {
                                assignment.resize(extended_domain_size, domain, extended_domain);
                            }
                            variable_values_out[var] = assignment;
                        }
                    }

                    static inline std::array<polynomial_dfs_type, argument_size>
                        prove_eval(
                            const typename policy_type::constraint_system_type &constraint_system,
                            const plonk_polynomial_dfs_table<FieldType>
                                &column_polynomials,
                            std::shared_ptr<math::evaluation_domain<FieldType>> original_domain,
                            std::uint32_t max_gates_degree,
                            const polynomial_dfs_type &mask_polynomial,
                            transcript_type& transcript) {
                        PROFILE_PLACEHOLDER_SCOPE("gate_argument_time");

                        // max_gates_degree that comes from the outside does not take into account multiplication
                        // by selector.
                        ++max_gates_degree;
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        auto value_type_to_polynomial_dfs = [](
                            const typename variable_type::assignment_type& coeff) {
                                return polynomial_dfs_type(0, 1, coeff);
                            };

                        std::vector<std::uint32_t> extended_domain_sizes;
                        std::vector<std::uint32_t> degree_limits;
                        std::uint32_t max_degree = std::pow(2, ceil(std::log2(max_gates_degree)));
                        std::uint32_t max_domain_size = original_domain->m * max_degree;

                        degree_limits.push_back(max_degree);
                        extended_domain_sizes.push_back(max_domain_size);
                        degree_limits.push_back(max_degree / 2);
                        extended_domain_sizes.push_back(max_domain_size / 2);

                        std::vector<math::expression<polynomial_dfs_variable_type>> expressions(extended_domain_sizes.size());

                        auto theta_acc = FieldType::value_type::one();

                        // Every constraint has variable type 'variable_type', but we want it to use
                        // 'polynomial_dfs_variable_type' instead. The only difference is the coefficient type
                        // inside a term. We want the coefficients to be dfs polynomials here.
                        math::expression_variable_type_converter<variable_type, polynomial_dfs_variable_type> converter(
                            value_type_to_polynomial_dfs);

                        math::expression_max_degree_visitor<variable_type> visitor;

                        const auto& gates = constraint_system.gates();

                        for (const auto& gate: gates) {
                            std::vector<math::expression<polynomial_dfs_variable_type>> gate_results(extended_domain_sizes.size());

                            for (const auto& constraint : gate.constraints) {
                                auto next_term = converter.convert(constraint) * value_type_to_polynomial_dfs(theta_acc);

                                theta_acc *= theta;
                                // +1 stands for the selector multiplication.
                                size_t constraint_degree = visitor.compute_max_degree(constraint) + 1;
                                for (int i = extended_domain_sizes.size() - 1; i >= 0; --i) {
                                    // Whatever the degree of term is, add it to the maximal degree expression.
                                    if (degree_limits[i] >= constraint_degree || i == 0) {
                                        gate_results[i] += next_term;
                                        break;
                                    }
                                }
                            }

                            auto selector = polynomial_dfs_variable_type(
                                gate.selector_index, 0, false, polynomial_dfs_variable_type::column_type::selector);

                            for (size_t i = 0; i < extended_domain_sizes.size(); ++i) {
                                gate_results[i] *= selector;
                                expressions[i] += gate_results[i];
                            }
                        }

                        std::unordered_map<polynomial_dfs_variable_type, polynomial_dfs_type> variable_values;
                        std::array<polynomial_dfs_type, argument_size> F;

                        for (size_t i = 0; i < extended_domain_sizes.size(); ++i) {
                            if (i != 0 && extended_domain_sizes[i] != extended_domain_sizes[i-1]) {
                                variable_values.clear();
                            }
                            build_variable_value_map(expressions[i], column_polynomials, original_domain,
                                extended_domain_sizes[i], variable_values);

                            math::cached_expression_evaluator<polynomial_dfs_variable_type> evaluator(
                                expressions[i], [&assignments=variable_values, domain_size=extended_domain_sizes[i]](const polynomial_dfs_variable_type &var) {
                                return assignments[var];
                            });

                            F[0] += evaluator.evaluate();
                        }

                        F[0] *= mask_polynomial;
                        return F;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size>
                        verify_eval(const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> &gates,
                                    typename policy_type::evaluation_map &evaluations,
                                    const typename FieldType::value_type &challenge,
                                    typename FieldType::value_type mask_value,
                                    transcript_type &transcript) {
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<typename FieldType::value_type, argument_size> F;

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        for (const auto& gate: gates) {
                            typename FieldType::value_type gate_result = {0};

                            for (const auto& constraint : gate.constraints) {
                                gate_result += constraint.evaluate(evaluations) * theta_acc;
                                theta_acc *= theta;
                            }

                            std::tuple<std::size_t, int, typename plonk_variable<typename FieldType::value_type>::column_type> selector_key =
                                std::make_tuple(gate.selector_index, 0,
                                                plonk_variable<typename FieldType::value_type>::column_type::selector);

                            gate_result *= evaluations[selector_key];

                            F[0] += gate_result;
                        }

                        F[0] *= mask_value;
                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
