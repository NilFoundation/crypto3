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

                    typename plonk_public_polynomial_dfs_table<FieldType,
                            ArithmetizationParams>::public_input_container_type public_inputs=
                            table.public_table().public_inputs();

                    for (std::size_t pi_index = 0; pi_index < table.public_inputs_amount(); pi_index++) {
                        public_inputs[pi_index].resize(new_size);
                    }

                    typename plonk_public_polynomial_dfs_table<FieldType,
                        ArithmetizationParams>::constant_container_type constants=
                        table.public_table().constants();

                    for (std::size_t cst_index = 0; cst_index < table.constants_amount(); cst_index++) {
                        constants[cst_index].resize(new_size);
                    }

                    typename plonk_public_polynomial_dfs_table<FieldType,
                        ArithmetizationParams>::selector_container_type selectors=
                        table.public_table().selectors();

                    for (std::size_t sel_index = 0; sel_index < table.selectors_amount(); sel_index++) {
                        selectors[sel_index].resize(new_size);
                    }

                    typename plonk_private_polynomial_dfs_table<FieldType,
                        ArithmetizationParams>::witnesses_container_type witnesses=
                        table.private_table().witnesses();

                    for (std::size_t wts_index = 0; wts_index < table.witnesses_amount(); wts_index++) {
                        witnesses[wts_index].resize(new_size);
                    }

                    return
                        plonk_polynomial_dfs_table<FieldType, ArithmetizationParams>(
                            plonk_private_polynomial_dfs_table<FieldType, ArithmetizationParams>(
                                                                witnesses),
                            plonk_public_polynomial_dfs_table<FieldType, ArithmetizationParams>(
                                                                public_inputs, constants, selectors));

                }

                template<typename FieldType, typename ParamsType, std::size_t ArgumentSize = 1>
                struct placeholder_gates_argument;

                template<typename FieldType, typename ParamsType>
                struct placeholder_gates_argument<FieldType, ParamsType, 1> {

                    typedef typename ParamsType::transcript_hash_type transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                    constexpr static const std::size_t argument_size = 1;

                    static inline std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size>
                        prove_eval(
                            typename policy_type::constraint_system_type &constraint_system,
                            const plonk_polynomial_dfs_table<FieldType, typename ParamsType::arithmetization_params>
                                &column_polynomials,
                            std::shared_ptr<math::evaluation_domain<FieldType>>
                                original_domain,
                            std::uint32_t max_gates_degree,
                            transcript_type &transcript = transcript_type()) {

                        std::uint32_t extended_domain_size = original_domain->m * std::pow(2, ceil(std::log2(max_gates_degree)));
                        
                        const plonk_polynomial_dfs_table<FieldType, typename ParamsType::arithmetization_params>
                            extended_column_polynomials = resize(column_polynomials, extended_domain_size);

                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size> F;
                        F[0] = math::polynomial_dfs<typename FieldType::value_type>(0, extended_domain_size, FieldType::value_type::zero());

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> gates =
                            constraint_system.gates();

                        for (std::size_t i = 0; i < gates.size(); i++) {
                            math::polynomial_dfs<typename FieldType::value_type> gate_result(
                                0, extended_domain_size, FieldType::value_type::zero());

                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                gate_result = gate_result +
                                              gates[i].constraints[j].evaluate(extended_column_polynomials, original_domain) * theta_acc;
                                theta_acc *= theta;
                            }

                            gate_result = gate_result * extended_column_polynomials.selector(gates[i].selector_index);

                            F[0] = F[0] + gate_result;
                        }

                        return F;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size>
                        verify_eval(const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> &gates,
                                    typename policy_type::evaluation_map &evaluations,
                                    const typename FieldType::value_type &challenge,
                                    transcript_type &transcript = transcript_type()) {
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<typename FieldType::value_type, argument_size> F;

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        for (std::size_t i = 0; i < gates.size(); i++) {
                            typename FieldType::value_type gate_result = {0};

                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                gate_result = gate_result + gates[i].constraints[j].evaluate(evaluations) * theta_acc;
                                theta_acc *= theta;
                            }

                            std::tuple<std::size_t, int, typename plonk_variable<FieldType>::column_type> selector_key =
                                std::make_tuple(gates[i].selector_index, 0,
                                                plonk_variable<FieldType>::column_type::selector);

                            gate_result = gate_result * evaluations[selector_key];

                            F[0] = F[0] + gate_result;
                        }

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_GATES_ARGUMENT_HPP
