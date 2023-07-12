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

                    static constexpr std::size_t argument_size = 6;

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

                    static math::polynomial_dfs<typename FieldType::value_type> get_constraint_tag_from_gate_tag_column(
                        math::polynomial_dfs<typename FieldType::value_type> tag_column, 
                        std::size_t constraints_num,
                        std::size_t constraint_id, 
                        std::size_t table_id
                    ){
                        math::polynomial_dfs<typename FieldType::value_type> result = tag_column;
                        for( std::size_t i = 1; i <= constraints_num; i++ ){
                            if( i != constraint_id ){
                                auto tmp = tag_column - typename FieldType::value_type(i);
                                tmp *= FieldType::value_type::one() / (typename FieldType::value_type(constraint_id) - typename FieldType::value_type(i)); 
                                result *= tmp;
                            }
                        }
                        result *= FieldType::value_type::one() / constraint_id;
                        result *= table_id;
                        return result;
                    }

                    static typename FieldType::value_type get_constraint_tag_value_from_gate_tag_value(
                        typename FieldType::value_type tag_value, 
                        std::size_t constraints_num,
                        std::size_t constraint_id, 
                        std::size_t table_id
                    ){
                        typename FieldType::value_type result = tag_value;
                        for( std::size_t i = 1; i <= constraints_num; i++ ){
                            if( i != constraint_id ){
                                auto tmp = tag_value - typename FieldType::value_type(i);
                                tmp *= FieldType::value_type::one() / (typename FieldType::value_type(constraint_id) - typename FieldType::value_type(i)); 
                                result *= tmp;
                            }
                        }
                        result *= FieldType::value_type::one() / constraint_id;
                        result *= table_id;
                        return result;
                    }

                    struct prover_lookup_result {
                        std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size> F_dfs;
                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> sorted_batch;
                        std::array<math::polynomial_dfs<typename FieldType::value_type>,2> V_polynomials;
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
                        typename FieldType::value_type challenge(7);
                        prover_lookup_result result;
                        
                        // $/theta = \challenge$
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();
                        
                        // Construct lookup gates
                        const std::vector<plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>>> &lookup_gates =
                            constraint_system.lookup_gates();

                        const plonk_lookup_table<FieldType> &lookup_table =
                            constraint_system.lookup_table();

                        std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain =
                            preprocessed_data.common_data.basic_domain;

                        std::array<math::polynomial_dfs<typename FieldType::value_type>, argument_size> F_dfs;


                        typename FieldType::value_type theta_acc = FieldType::value_type::one();
                        math::polynomial_dfs<typename FieldType::value_type> one_polynomial(
                            0, basic_domain->m, FieldType::value_type::one());
                        math::polynomial_dfs<typename FieldType::value_type> zero_polynomial(
                            0, basic_domain->m, FieldType::value_type::zero());

                        math::polynomial_dfs<typename FieldType::value_type> mask_assignment = 
                            one_polynomial -  preprocessed_data.q_last - preprocessed_data.q_blind;

                        // Construct the input lookup compression and table compression values
                        // TODO: change to new form

                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> lookup_input(lookup_gates.size());
                        math::polynomial_dfs<typename FieldType::value_type> lookup_tag;
                        if( lookup_table.lookup_columns.size() != 0 ){
                            lookup_tag = plonk_columns.selector(lookup_table.tag_index);
                        } else {
                            lookup_tag = zero_polynomial;
                        }
                        math::polynomial_dfs<typename FieldType::value_type> lookup_value = lookup_tag;

                        theta_acc = theta;
                        for( std::size_t i = 0; i < lookup_table.lookup_columns.size(); i++ ){
                            lookup_value += theta_acc * lookup_tag * plonk_columns.constant(lookup_table.lookup_columns[i].index);
                            theta_acc *= theta;
                        }
                        lookup_value *= mask_assignment;

                        // Compile gate constraints into one input
                        for (std::size_t i = 0; i < lookup_gates.size(); i++) {
                            auto tag_column = plonk_columns.selector(lookup_gates[i].tag_index);
                            lookup_input[i] = math::polynomial_dfs<typename FieldType::value_type>(basic_domain->m - 1, basic_domain->m, FieldType::value_type::zero());
                            for (std::size_t j = 0; j < lookup_gates[i].constraints.size(); j++) {
                                const plonk_lookup_constraint<FieldType> &constraint = lookup_gates[i].constraints[j];
                                auto constraint_tag = get_constraint_tag_from_gate_tag_column(
                                    tag_column, lookup_gates[i].constraints.size(), j+1, constraint.table_id
                                );
                                lookup_input[i] += constraint_tag;
                                theta_acc = theta;
                                for( std::size_t k = 0; k < constraint.lookup_input.size(); k++){
                                    lookup_input[i] += theta_acc * constraint_tag * constraint.lookup_input[k].evaluate(plonk_columns, basic_domain);
                                    theta_acc *= theta;
                                }
                            }
                        }

                        // Lookup_input and lookup_value are ready
                        // Now sort them!

                        //  1. Sort lookup_value.
                        math::polynomial_dfs sorted_lookup_value = reduce_dfs_polynomial_domain(lookup_value, basic_domain->m);
                        std::sort(sorted_lookup_value.rbegin(), sorted_lookup_value.rend());

                        // 2. Count number of times for each value.
                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> sorted_lookup_input;
                        for( std::size_t i = 0; i < lookup_input.size(); i++ ){
                            sorted_lookup_input.push_back(reduce_dfs_polynomial_domain(lookup_input[i], basic_domain->m));
                        }
                        sorted_lookup_input.push_back(sorted_lookup_value);
                        
                        std::map<typename FieldType::value_type, std::size_t> sorting_map;
                        for( std::size_t k = 0; k < preprocessed_data.common_data.usable_rows_amount; k++){
                            for( std::size_t i = 0; i < sorted_lookup_input.size(); i++){
                                if(sorting_map.find(sorted_lookup_input[i][k]) != sorting_map.end()) 
                                    sorting_map[sorted_lookup_input[i][k]]++; 
                                else 
                                    sorting_map[sorted_lookup_input[i][k]] = 1;
                            }
                        }

                        // 3. Fill sorted columns
                        std::size_t k = 0;
                        std::size_t i = 0;
                        for(auto it = sorting_map.rbegin(); it != sorting_map.rend(); it++){
                            for(std::size_t j = 0; j < it->second; j++){
                                if( k == preprocessed_data.common_data.usable_rows_amount ){
                                    sorted_lookup_input[i][k] = it->first;
                                    i++;
                                    k = 0;
                                }
                                sorted_lookup_input[i][k] = it->first;
                                k++;
                                if( k == preprocessed_data.common_data.usable_rows_amount ){
                                    if( j == it->second - 1) continue;
                                    sorted_lookup_input[i][k] = it->first;
                                    i++;
                                    k = 0;
                                }
                            }
                        }

                        // 4. Precommit sorted value and sorted input
                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> sorted_batch;
                        for( std::size_t i = 0; i < sorted_lookup_input.size(); i++ ){
                            sorted_batch.push_back(sorted_lookup_input[i]);
                        }
                        sorted_batch.push_back(sorted_lookup_value);

                        typename CommitmentSchemeTypePermutation::precommitment_type lookup_precommitment =
                            algorithms::precommit<CommitmentSchemeTypePermutation>(
                                sorted_batch, fri_params.D[0], fri_params.step_list.front());
                        transcript(algorithms::commit<CommitmentSchemeTypePermutation>(lookup_precommitment));

                        //5. Compute V_L polynomial.
                        typename FieldType::value_type beta  = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        math::polynomial_dfs<typename FieldType::value_type> V_L(basic_domain->m - 1, basic_domain->m);
                        math::polynomial_dfs<typename FieldType::value_type> V_S(basic_domain->m - 1, basic_domain->m);
                        V_L[0] = FieldType::value_type::one();
                        V_S[0] = FieldType::value_type::one();
                        auto one = FieldType::value_type::one();

                        auto reduced_lookup_input = lookup_input;
                        for (std::size_t i = 0; i < reduced_lookup_input.size(); i++ ){
                            reduced_lookup_input[i] = reduce_dfs_polynomial_domain(reduced_lookup_input[i], basic_domain->m);
                        }
                       
                        auto reduced_lookup_value = reduce_dfs_polynomial_domain(lookup_value, basic_domain->m);
                        for (std::size_t k = 1; k <= preprocessed_data.common_data.usable_rows_amount; k++) {
                            V_S[k] = V_S[k-1];
                            V_S[k] *=  beta * sorted_lookup_value[k-1] + gamma;
                            V_S[k] *=  (beta * reduced_lookup_value[k-1] + gamma).inversed(); 

                            V_L[k] = V_L[k-1];
                            auto g_tmp = ((one+beta)*gamma + sorted_lookup_value[k-1] + beta*sorted_lookup_value[k]); 
                            for( std::size_t i = 0; i < reduced_lookup_input.size(); i++){
                                g_tmp *= (one+beta)*(gamma + reduced_lookup_input[i][k-1]);
                            }
                            V_L[k] *= g_tmp;

                            typename FieldType::value_type h_tmp(1);
                            for( std::size_t i = 0; i <= reduced_lookup_input.size(); i++){
                                h_tmp *= ((one+beta)*gamma + sorted_lookup_input[i][k-1] + beta * sorted_lookup_input[i][k]);
                            }
                            V_L[k] *= h_tmp.inversed();
                        }
                        BOOST_CHECK(V_L[preprocessed_data.common_data.usable_rows_amount] ==  FieldType::value_type::one());
                        BOOST_CHECK(V_S[preprocessed_data.common_data.usable_rows_amount] ==  FieldType::value_type::one());

                        auto sorted_lookup_value_shifted = math::polynomial_shift(sorted_lookup_value, 1, basic_domain->m);
                        math::polynomial_dfs<typename FieldType::value_type> g = (one+beta) * gamma + sorted_lookup_value + beta*sorted_lookup_value_shifted;
                        for( std::size_t i = 0; i < lookup_input.size(); i++){
                            g *= (one+beta)*(gamma + lookup_input[i]);
                        }

                        math::polynomial_dfs<typename FieldType::value_type> h = math::polynomial_dfs<typename FieldType::value_type>::one();
                        for( std::size_t i = 0; i < sorted_lookup_input.size(); i++){
                            auto sorted_lookup_input_shifted = math::polynomial_shift(sorted_lookup_input[i], 1, basic_domain->m);
                            h *= (one+beta) * gamma + sorted_lookup_input[i] + beta * sorted_lookup_input_shifted;
                        }

                        math::polynomial_dfs<typename FieldType::value_type> V_L_shifted =
                            math::polynomial_shift(V_L, 1, basic_domain->m);
                        math::polynomial_dfs<typename FieldType::value_type> V_S_shifted =
                            math::polynomial_shift(V_S, 1, basic_domain->m);

                        math::polynomial_dfs<typename FieldType::value_type> g1 = beta * sorted_lookup_value + gamma;
                        math::polynomial_dfs<typename FieldType::value_type> h1 = beta * lookup_value + gamma;

                        F_dfs[0] = preprocessed_data.common_data.lagrange_0 * (one_polynomial - V_L);
                        F_dfs[1] = preprocessed_data.q_last * ( V_L * V_L - V_L );
                        F_dfs[2] = (one_polynomial - (preprocessed_data.q_last + preprocessed_data.q_blind)) *
                                   (V_L_shifted * h - V_L * g);
                        F_dfs[3] = preprocessed_data.common_data.lagrange_0 * (one_polynomial - V_S);
                        F_dfs[4] = preprocessed_data.q_last * ( V_S * V_S - V_S );
                        F_dfs[5] = (one_polynomial - (preprocessed_data.q_last + preprocessed_data.q_blind)) *
                            (V_S_shifted * h1 - V_S * g1);

                        return {
                            F_dfs,
                            sorted_batch,
                            {V_L, V_S},
                            lookup_precommitment
                        };
                    }

                    static inline std::array<typename FieldType::value_type, argument_size> verify_eval(
                        const typename placeholder_public_preprocessor<FieldType, ParamsType>::preprocessed_data_type &preprocessed_data,
                        const std::vector<plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>>> &lookup_gates,
                        const plonk_lookup_table<FieldType> &lookup_table,
                        // y
                        const typename FieldType::value_type &challenge,
                        typename policy_type::evaluation_map &evaluations,
                        // sorted_batch_values. Pair value/shifted_value
                        const std::vector<std::vector<typename FieldType::value_type>> &sorted_batch_values,
                        // V_L(y), V_L(omega* Y)
                        std::vector<typename FieldType::value_type> V_L_values,
                        // V_S(y), V_S(omega* Y)
                        std::vector<typename FieldType::value_type> V_S_values,
                        // Commitment
                        const typename CommitmentSchemeTypePermutation::commitment_type &lookup_commitment,
                        transcript_type &transcript = transcript_type()
                    ) {
                       // 1. Get theta
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        // 2. Add commitments to transcript
                        transcript(lookup_commitment);

                        // 3. Calculate lookup_value compression compression at challenge point
                        auto tag_value = evaluations[std::tuple(lookup_table.tag_index, 0, plonk_variable<FieldType>::column_type::selector)];
                        typename FieldType::value_type lookup_value;
                        if( lookup_table.lookup_columns.size() != 0){
                            lookup_value = tag_value;
                        } else {
                            lookup_value = FieldType::value_type::zero();
                        }
                        auto theta_acc = theta;
                        for(auto lookup_column: lookup_table.lookup_columns){
                            lookup_value += theta_acc * tag_value * evaluations[std::tuple(lookup_column.index,lookup_column.rotation, lookup_column.type)];
                            theta_acc *= theta;
                        }
                        lookup_value *= (FieldType::value_type::one() - preprocessed_data.q_last.evaluate(challenge) - preprocessed_data.q_blind.evaluate(challenge));

                        auto sorted_value = sorted_batch_values[sorted_batch_values.size() - 1][0];
                        auto sorted_value_shifted = sorted_batch_values[sorted_batch_values.size() - 1][1];

                        // Check V_S
                        auto V_S_value = V_S_values[0];
                        auto V_S_shifted = V_S_values[1];
                        
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();
                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        typename FieldType::value_type one = FieldType::value_type::one();

                        auto g1 = beta * sorted_value + gamma;
                        auto h1 = beta * lookup_value + gamma;

                        std::array<typename FieldType::value_type, argument_size> F;
                        F[3] = preprocessed_data.common_data.lagrange_0.evaluate(challenge) * (one - V_S_value);
                        F[4] = preprocessed_data.q_last.evaluate(challenge) * (V_S_value * V_S_value - V_S_value);
                        F[5] = (one - (preprocessed_data.q_last.evaluate(challenge) + preprocessed_data.q_blind.evaluate(challenge))) *
                            (V_S_shifted * h1 - V_S_value * g1);

                        // Check V_L
                        // Compute lookup_input
                        std::vector<typename FieldType::value_type> lookup_input;
                        lookup_input.resize(lookup_gates.size());
                        for( std::size_t i = 0; i < lookup_gates.size(); i++ ){
                            lookup_input[i] = FieldType::value_type::zero();
                            auto gate_tag_value = evaluations[std::tuple(lookup_gates[i].tag_index, 0, plonk_variable<FieldType>::column_type::selector)];
                            for( std::size_t j = 0; j < lookup_gates[i].constraints.size(); j++ ){
                                const plonk_lookup_constraint<FieldType> &constraint = lookup_gates[i].constraints[j];
                                auto constraint_tag_value = get_constraint_tag_value_from_gate_tag_value(
                                    gate_tag_value, lookup_gates[i].constraints.size(),
                                    j + 1, constraint.table_id
                                );                                

                                lookup_input[i] += constraint_tag_value;
                                theta_acc = theta;
                                for( std::size_t k = 0; k < constraint.lookup_input.size(); k++ ) {
                                    lookup_input[i] += constraint_tag_value * theta_acc * constraint.lookup_input[k].evaluate(evaluations);
                                    theta_acc *= theta;
                                }
                            }
                        }

                        // Compute g and h
                        auto g = (one+beta)*gamma + sorted_value + beta * sorted_value_shifted;
                        for( std::size_t i = 0; i < lookup_input.size(); i++){
                            g *= (one+beta)*(gamma + lookup_input[i]);
                        }

                        auto h = one;
                        for( std::size_t i = 0; i < sorted_batch_values.size() - 1; i++){
                            auto sorted_lookup_input = sorted_batch_values[i][0];
                            auto sorted_lookup_input_shifted = sorted_batch_values[i][1];
                            h *= (one+beta) * gamma + sorted_lookup_input + beta * sorted_lookup_input_shifted;
                        }

                        auto V_L_value = V_L_values[0];
                        auto V_L_shifted = V_L_values[1];

                        F[0] = preprocessed_data.common_data.lagrange_0.evaluate(challenge) * (one - V_L_value);
                        F[1] = preprocessed_data.q_last.evaluate(challenge) * (V_L_value * V_L_value - V_L_value);
                        F[2] = (one - (preprocessed_data.q_last.evaluate(challenge) + preprocessed_data.q_blind.evaluate(challenge))) *
                                   (V_L_shifted * h - V_L_value * g);

                        return F;
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // #ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PERMUTATION_ARGUMENT_HPP