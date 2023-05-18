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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_LOOKUP_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_LOOKUP_ARGUMENT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename CommitmentSchemeTypePermutation, typename ParamsType>
                class placeholder_lookup_argument {
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;
                    using VariableType = plonk_variable<FieldType>;

                    static constexpr std::size_t argument_size = 5;

                    typedef detail::placeholder_policy<FieldType, ParamsType> policy_type;

                public:
                    static math::polynomial_dfs<typename FieldType::value_type> reduce_dfs_polynomial_domain(
                        const math::polynomial_dfs<typename FieldType::value_type> &polynomial,
                        std::size_t &new_domain_size
                    ) {
                        math::polynomial_dfs<typename FieldType::value_type> reduced(new_domain_size - 1, new_domain_size, FieldType::value_type::zero());
                        BOOST_ASSERT(new_domain_size <= polynomial.size());
                        if(polynomial.size() == new_domain_size){
                            reduced = polynomial;
                        } else {
                            BOOST_ASSERT(polynomial.size() % new_domain_size == 0);
                        
                            std::size_t step = polynomial.size() / new_domain_size;
                            for( std::size_t i = 0; i < new_domain_size; i ++){
                                reduced[i] = polynomial[i*step];
                            }
                        }
                        return reduced;
                    };

                    struct prover_lookup_result {
                        std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size> F_dfs;
                        math::polynomial_dfs<typename FieldType::value_type> input_polynomial;
                        math::polynomial_dfs<typename FieldType::value_type> value_polynomial;
                        math::polynomial_dfs<typename FieldType::value_type> V_L_polynomial;
                        typename CommitmentSchemeTypePermutation::precommitment_type lookup_precommitment;
                    };
                    static inline prover_lookup_result prove_eval(
                        plonk_constraint_system<FieldType, typename ParamsType::arithmetization_params>
                            &constraint_system,
                        const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type
                            &preprocessed_data,
                        const plonk_polynomial_dfs_table<FieldType, typename ParamsType::arithmetization_params>
                            &plonk_columns,
                        typename CommitmentSchemeTypePermutation::params_type fri_params,
                        transcript_type &transcript = transcript_type()
                    ) {
                        prover_lookup_result result;
                        
                        // $/theta = \challenge$
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();
                        
                        // Construct lookup gates
                        const std::vector<plonk_gate<FieldType, plonk_lookup_constraint<FieldType>>> lookup_gates =
                            constraint_system.lookup_gates();

                        std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain =
                            preprocessed_data.common_data.basic_domain;

                        std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size> F_dfs;

                        math::polynomial_dfs<typename FieldType::value_type> F_compr_input(0, basic_domain->m, FieldType::value_type::zero());
                        math::polynomial_dfs<typename FieldType::value_type> F_compr_value(0, basic_domain->m, FieldType::value_type::zero());

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                         // Construct the input lookup compression and table compression values
                        // TODO: change to new form
                        for (std::size_t i = 0; i < lookup_gates.size(); i++) {
                            for (std::size_t j = 0; j < lookup_gates[i].constraints.size(); j++) {
                                for (std::size_t k = 0; k < lookup_gates[i].constraints[j].lookup_input.size(); k++) {
                                    const math::expression<VariableType>& lookup = lookup_gates[i].constraints[j].lookup_input[k];

                                    math::polynomial_dfs<typename FieldType::value_type> input_assignment;
                                    math::polynomial_dfs<typename FieldType::value_type> value_assignment;

                                    input_assignment = lookup_gates[i].constraints[j].lookup_input[k].evaluate(plonk_columns, basic_domain);

                                    switch (lookup_gates[i].constraints[j].lookup_value[k].type) {
                                        case VariableType::column_type::witness:
                                            value_assignment = plonk_columns.witness(
                                                lookup_gates[i].constraints[j].lookup_value[k].index);
                                            break;
                                        case VariableType::column_type::public_input:
                                            value_assignment = plonk_columns.public_input(
                                                lookup_gates[i].constraints[j].lookup_value[k].index);
                                            break;
                                        case VariableType::column_type::constant:
                                            value_assignment = plonk_columns.constant(
                                                lookup_gates[i].constraints[j].lookup_value[k].index);
                                            break;
                                        case VariableType::column_type::selector:
                                            break;
                                    }
                                    

                                    // This can have degree more than basic_domain->m
                                    // It's extremely important.
                                    // We should reduce 
                                    F_compr_input += theta_acc * input_assignment 
                                        * plonk_columns.selector(lookup_gates[i].selector_index);
                                    F_compr_value += theta_acc * value_assignment;
                                    theta_acc = theta * theta_acc;
                                }
                            }
                        }


                        auto reduced_input = reduce_dfs_polynomial_domain(F_compr_input, basic_domain->m);

                        // Produce the permutation polynomials $S_{\texttt{perm}}(X)$ and $A_{\texttt{perm}}(X)$
                        math::polynomial_dfs<typename FieldType::value_type> F_perm_input = reduced_input;
                        std::sort(F_perm_input.begin(), F_perm_input.end());
                        std::reverse(F_perm_input.begin(), F_perm_input.end());

                        // TODO:!!! better sort for F_perm_value
                        math::polynomial_dfs<typename FieldType::value_type> F_perm_value = F_compr_value;
                        for (std::size_t i = 0; i < preprocessed_data.common_data.usable_rows_amount; i++) {
                            if( i == 0 || F_perm_input[i] != F_perm_input[i - 1]){
                                for (std::size_t j = 0; j < preprocessed_data.common_data.usable_rows_amount; j++) {
                                    if( F_perm_value[j] == F_perm_input[i] ){
                                        auto tmp = F_perm_value[i];
                                        F_perm_value[i] = F_perm_value[j];
                                        F_perm_value[j] = tmp;
                                        break;
                                    }
                                }
                            }
                        }

                        // TODO permutation over F_perm_value[1..m-1]
                        // TODO think about polynomial_dfs copying
                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> perm_polys_batch;
                        perm_polys_batch.resize(2);
                        perm_polys_batch[0] = F_perm_input;
                        perm_polys_batch[1] = F_perm_value;

                        typename CommitmentSchemeTypePermutation::precommitment_type lookup_precommitment =
                            algorithms::precommit<CommitmentSchemeTypePermutation>(perm_polys_batch, fri_params.D[0],
                                                                                   fri_params.step_list.front());
                        transcript(algorithms::commit<CommitmentSchemeTypePermutation>(lookup_precommitment));

                        // Compute $V_L(X)$
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        math::polynomial_dfs<typename FieldType::value_type> V_L(basic_domain->m - 1, basic_domain->m);

                        V_L[0] = FieldType::value_type::one();
                       
                        for (std::size_t j = 1; j < basic_domain->m; j++) {
                            BOOST_ASSERT(reduced_input[j-1] == F_compr_input.evaluate(basic_domain->get_domain_element(j - 1)));
                            V_L[j] = V_L[j - 1];
                            V_L[j] *= (reduced_input[j - 1] + beta) * (F_compr_value[j - 1] + gamma);
                            V_L[j] *= ((F_perm_input[j - 1] + beta) * (F_perm_value[j - 1] + gamma)).inversed();
                        }

                        math::polynomial_dfs<typename FieldType::value_type> V_L_copy = V_L;

                        // Calculate lookup-related numerators of the quotinent polynomial
                        math::polynomial_dfs<typename FieldType::value_type> g =
                            (F_compr_input + beta) * (F_compr_value + gamma);
                        math::polynomial_dfs<typename FieldType::value_type> h =
                            (F_perm_input + beta) * (F_perm_value + gamma);
                        math::polynomial_dfs<typename FieldType::value_type> one_polynomial(
                            basic_domain->m - 1, basic_domain->m, FieldType::value_type::one());

                        math::polynomial_dfs<typename FieldType::value_type> V_L_shifted =
                            math::polynomial_shift(V_L, 1, basic_domain->m);

                        math::polynomial_dfs<typename FieldType::value_type> F_perm_input_shifted =
                            math::polynomial_shift(F_perm_input, -1, basic_domain->m);

                        F_dfs[0] = (one_polynomial - (preprocessed_data.q_last + preprocessed_data.q_blind)) *
                                   (F_perm_input - F_perm_value) * (F_perm_input - F_perm_input_shifted);
                        F_dfs[1] = preprocessed_data.common_data.lagrange_0 * (F_perm_input - F_perm_value);
                        F_dfs[2] = (one_polynomial - (preprocessed_data.q_last + preprocessed_data.q_blind)) *
                                   (V_L_shifted * h - V_L * g);
                        F_dfs[3] = preprocessed_data.common_data.lagrange_0 * (one_polynomial - V_L);
                        F_dfs[4] = preprocessed_data.q_last * ( V_L * V_L - V_L );

                        return {F_dfs,
                                F_perm_input,
                                F_perm_value,
                                V_L,
                                lookup_precommitment
                        };
                    }

                    static inline std::array<typename FieldType::value_type, argument_size> verify_eval(
                        const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type &preprocessed_data,
                        const std::vector<plonk_gate<FieldType, plonk_lookup_constraint<FieldType>>> &lookup_gates,
                        // y
                        const typename FieldType::value_type &challenge,
                        typename policy_type::evaluation_map &evaluations,
                        // A_perm(y):
                        const typename FieldType::value_type &F_perm_input_polynomial_value,
                        // A_perm(y * omega ^ {-1}):
                        const typename FieldType::value_type &F_perm_input_shifted_polynomial_value,
                        // L_perm(y):
                        const typename FieldType::value_type &F_perm_value_polynomial_value,
                        // V_L(y):
                        const typename FieldType::value_type &V_L_polynomial_value,
                        // V_P(omega * y):
                        const typename FieldType::value_type &V_L_polynomial_shifted_value,
                        const typename CommitmentSchemeTypePermutation::commitment_type &lookup_commitment,
                        transcript_type &transcript = transcript_type()
                    ) {
                       // 1. Get theta
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        // 2. Add commitments to transcript
                        transcript(lookup_commitment);

                        // 3. Calculate input_lookup and value_lookup compression at challenge point
                        typename FieldType::value_type F_input_compr = FieldType::value_type::zero();
                        typename FieldType::value_type F_value_compr = FieldType::value_type::zero();

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();                        

                        for (std::size_t i = 0; i < lookup_gates.size(); i++) {
                            for (std::size_t j = 0; j < lookup_gates[i].constraints.size(); j++) {
                                for( std::size_t k = 0; k < lookup_gates[i].constraints[j].lookup_input.size(); k++ ) {
                                    std::tuple<std::size_t, int, typename VariableType::column_type> value_key =
                                        std::make_tuple(lookup_gates[i].constraints[j].lookup_value[k].index,
                                                        lookup_gates[i].constraints[j].lookup_value[k].rotation,
                                                        lookup_gates[i].constraints[j].lookup_value[k].type);

                                    std::tuple<std::size_t, int, typename plonk_variable<FieldType>::column_type>
                                        selector_key =
                                            std::make_tuple(lookup_gates[i].selector_index, 0,
                                                            plonk_variable<FieldType>::column_type::selector);
                    
                                    F_input_compr = F_input_compr +  theta_acc * evaluations[selector_key] * lookup_gates[i].constraints[j].lookup_input[k].evaluate(evaluations);
                                    F_value_compr += theta_acc * evaluations[value_key];

                                    theta_acc = theta * theta_acc;
                                }
                            }
                        }

                        // 4. Denote g and h
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        typename FieldType::value_type g = (F_input_compr + beta) * (F_value_compr + gamma);
                        typename FieldType::value_type h =
                            (F_perm_input_polynomial_value + beta) * (F_perm_value_polynomial_value + gamma);

                        std::array<typename FieldType::value_type, argument_size> F;
                        typename FieldType::value_type one = FieldType::value_type::one();

                        F[0] = (one - preprocessed_data.q_last.evaluate(challenge) -
                                preprocessed_data.q_blind.evaluate(challenge)) *
                               (F_perm_input_polynomial_value - F_perm_value_polynomial_value) *
                               (F_perm_input_polynomial_value - F_perm_input_shifted_polynomial_value);
                        F[1] = preprocessed_data.common_data.lagrange_0.evaluate(challenge) *
                               (F_perm_input_polynomial_value - F_perm_value_polynomial_value);
                        F[2] = (V_L_polynomial_shifted_value * h - V_L_polynomial_value * g);
                        F[2] *= (one - (preprocessed_data.q_last.evaluate(challenge) + preprocessed_data.q_blind.evaluate(challenge)));
                        F[3] =  preprocessed_data.common_data.lagrange_0.evaluate(challenge) * (one - V_L_polynomial_value);
                        F[4] = preprocessed_data.q_last.evaluate(challenge) *
                               (V_L_polynomial_value * V_L_polynomial_value - V_L_polynomial_value);

                        return F;
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // #ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PERMUTATION_ARGUMENT_HPP