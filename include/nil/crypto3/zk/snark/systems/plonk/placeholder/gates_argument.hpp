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

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename ArithmetizationParams>
                plonk_polynomial_dfs_table<FieldType, ArithmetizationParams>
                    resize(const plonk_polynomial_dfs_table<FieldType, ArithmetizationParams> &table,
                                            std::uint32_t new_size) {

                    auto public_inputs = table.public_table().public_inputs();
                    for (auto& public_input : public_inputs) {
                        public_input.resize(new_size);
                    }

                    auto constants = table.public_table().constants();
                    for (auto& constant : constants) {
                        constant.resize(new_size);
                    }

                    auto selectors = table.public_table().selectors();
                    for (auto& selector : selectors) {
                        selector.resize(new_size);
                    }

                    auto witnesses = table.private_table().witnesses();
                    for (auto& witness : witnesses) {
                        witness.resize(new_size);
                    }

                    return plonk_polynomial_dfs_table<FieldType, ArithmetizationParams>(
                        plonk_private_polynomial_dfs_table<FieldType, ArithmetizationParams>(
                            std::move(witnesses)),
                        plonk_public_polynomial_dfs_table<FieldType, ArithmetizationParams>(
                            std::move(public_inputs), std::move(constants), std::move(selectors)));
                }

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

                    static inline std::array<polynomial_dfs_type, argument_size>
                        prove_eval(
                            const typename policy_type::constraint_system_type &constraint_system,
                            const plonk_polynomial_dfs_table<FieldType, typename ParamsType::arithmetization_params>
                                &column_polynomials,
                            std::shared_ptr<math::evaluation_domain<FieldType>>
                                original_domain,
                            std::uint32_t max_gates_degree,
                            transcript_type& transcript) {
                        PROFILE_PLACEHOLDER_SCOPE("gate_argument_time");

                        std::uint32_t extended_domain_size = original_domain->m * 
                            std::pow(2, ceil(std::log2(max_gates_degree)));
                        
                        const plonk_polynomial_dfs_table<FieldType, typename ParamsType::arithmetization_params>
                            extended_column_polynomials = resize(column_polynomials, extended_domain_size);

                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        auto value_type_to_polynomial_dfs = [&assignments=extended_column_polynomials](
                            const typename variable_type::assignment_type& coeff) {
                                return polynomial_dfs_type(0, assignments.rows_amount(), coeff);
                            };
                        math::expression<polynomial_dfs_variable_type> expr = 
                            value_type_to_polynomial_dfs(FieldType::value_type::zero());

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        // Every constraint has variable type 'variable_type', but we want it to use
                        // 'polynomial_dfs_variable_type' instead. The only difference is the coefficient type
                        // inside a term. We want the coefficients to be dfs polynomials here.
                        math::expression_variable_type_converter<variable_type, polynomial_dfs_variable_type> converter(
                            value_type_to_polynomial_dfs);

                        const auto& gates = constraint_system.gates();
                        for (const auto& gate: gates) {
                            math::expression<polynomial_dfs_variable_type> gate_result = 
                                polynomial_dfs_type(0, extended_column_polynomials.rows_amount(), FieldType::value_type::zero());

                            for (const auto& constraint : gate.constraints) {
                                gate_result += converter.convert(constraint) * value_type_to_polynomial_dfs(theta_acc);
                                theta_acc *= theta;
                            }

                            gate_result *= polynomial_dfs_variable_type(
                                gate.selector_index, 0, false, polynomial_dfs_variable_type::column_type::selector);

                            expr += gate_result;
                        }

                        auto get_var_value = [
                            &domain=original_domain, &assignments=extended_column_polynomials]
                            (const polynomial_dfs_variable_type &var) {
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
                                return assignment;
                            };

                        math::expression_evaluator<polynomial_dfs_variable_type> evaluator(
                            expr, get_var_value);

                        std::array<polynomial_dfs_type, argument_size> F;
                        F[0] = evaluator.evaluate();

                        return F;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size>
                        verify_eval(const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> &gates,
                                    typename policy_type::evaluation_map &evaluations,
                                    const typename FieldType::value_type &challenge,
                                    transcript_type &transcript) {
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<typename FieldType::value_type, argument_size> F;

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        for (const auto& gate: gates) {
                            typename FieldType::value_type gate_result = {0};

                            for (const auto& constraint : gate.constraints) {
                                gate_result = gate_result + constraint.evaluate(evaluations) * theta_acc;
                                theta_acc *= theta;
                            }

                            std::tuple<std::size_t, int, typename plonk_variable<typename FieldType::value_type>::column_type> selector_key =
                                std::make_tuple(gate.selector_index, 0,
                                                plonk_variable<typename FieldType::value_type>::column_type::selector);

                            gate_result = gate_result * evaluations[selector_key];

                            F[0] += gate_result;
                        }

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
