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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PROVER_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PROVER_HPP

#include <chrono>
#include <set>

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/gates_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {
                    template<typename FieldType>
                    static inline std::vector<math::polynomial<typename FieldType::value_type>>
                        split_polynomial(const math::polynomial<typename FieldType::value_type> &f,
                                         std::size_t max_degree) {
                        std::size_t parts = ((f.size() - 1) / (max_degree + 1)) + 1;
                        std::vector<math::polynomial<typename FieldType::value_type>> f_splitted;

                        std::size_t chunk_size = max_degree + 1;    // polynomial contains max_degree + 1 coeffs
                        for (size_t i = 0; i < f.size(); i += chunk_size) {
                            auto last = std::min(f.size(), i + chunk_size);
                            f_splitted.emplace_back(f.begin() + i, f.begin() + last);
                        }
                        return f_splitted;
                    }
                }    // namespace detail

                template<typename FieldType, typename ParamsType>
                class placeholder_prover {

                    constexpr static const std::size_t witness_columns = ParamsType::witness_columns;
                    constexpr static const std::size_t public_columns = ParamsType::public_columns;
                    constexpr static const std::size_t public_input_columns = ParamsType::public_input_columns;
                    constexpr static const std::size_t constant_columns = ParamsType::constant_columns;
                    using merkle_hash_type = typename ParamsType::merkle_hash_type;
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;

                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;

                    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

                    constexpr static const std::size_t lambda = ParamsType::commitment_params_type::lambda;
                    constexpr static const std::size_t r = ParamsType::commitment_params_type::r;
                    constexpr static const std::size_t m = ParamsType::commitment_params_type::m;

                    using commitment_scheme_type =
                        typename ParamsType::runtime_size_commitment_scheme_type;

                    using public_preprocessor_type = placeholder_public_preprocessor<FieldType, ParamsType>;
                    using private_preprocessor_type = placeholder_private_preprocessor<FieldType, ParamsType>;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t f_parts = 9;

                    static inline math::polynomial<typename FieldType::value_type> quotient_polynomial(
                        const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data,
                        const std::array<math::polynomial_dfs<typename FieldType::value_type>, f_parts> &F_dfs,
                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> &transcript) {

                        // 7.1. Get $\alpha_0, \dots, \alpha_8 \in \mathbb{F}$ from $hash(\text{transcript})$
                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();

                        // 7.2. Compute F_consolidated
                        math::polynomial_dfs<typename FieldType::value_type> F_consolidated_dfs(0, F_dfs[0].size(), FieldType::value_type::zero());
                        for (std::size_t i = 0; i < f_parts; i++) {
                            if (F_dfs[i].is_zero()){
                                continue;
                            }
                            F_consolidated_dfs += alphas[i] * F_dfs[i];
                        }

//                        std::cout << "Basic domain size = " << preprocessed_public_data.common_data.basic_domain->size() << std::endl;
                        for (std::size_t i = 0; i < f_parts; i++) {
                            for (std::size_t j = 0; j < preprocessed_public_data.common_data.basic_domain->size(); j++) {
                                if (F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(
                                        j)) != FieldType::value_type::zero()) {
                                }
                            }
                        }

                        math::polynomial<typename FieldType::value_type> F_consolidated_normal(F_consolidated_dfs.coefficients());
                        math::polynomial<typename FieldType::value_type> T_consolidated =
                            F_consolidated_normal / preprocessed_public_data.common_data.Z;

                        return T_consolidated;
                    }

                public:
                    static inline placeholder_proof<FieldType, ParamsType> process(
                        const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data,
                        const typename private_preprocessor_type::preprocessed_data_type &preprocessed_private_data,
                        const plonk_table_description<FieldType, typename ParamsType::arithmetization_params>
                            &table_description,
                        plonk_constraint_system<FieldType, typename ParamsType::arithmetization_params>
                            &constraint_system,
                        const typename policy_type::variable_assignment_type &assignments,
                        const typename ParamsType::commitment_params_type
                            &fri_params) { 
                        
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        auto begin = std::chrono::high_resolution_clock::now();
                        auto last = begin;
                        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
#endif
                        placeholder_proof<FieldType, ParamsType> proof;

                        plonk_polynomial_dfs_table<FieldType, typename ParamsType::arithmetization_params>
                            polynomial_table =
                                plonk_polynomial_dfs_table<FieldType, typename ParamsType::arithmetization_params>(
                                    preprocessed_private_data.private_polynomial_table,
                                    preprocessed_public_data.public_polynomial_table);
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "polynomial_table_generated_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                       // 1. Add circuit definition to transcript
                        // transcript(short_description); 
                        //TODO: circuit_short_description marshalling
                        std::vector<std::uint8_t> transcript_init {};
                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(transcript_init);

                        // 2. Commit witness columns and public_input columns

                        std::array<std::vector<math::polynomial_dfs<typename FieldType::value_type>>, 5> combined_poly;
                        
                        for (std::size_t i = 0; i < polynomial_table.witnesses_amount(); i++){
                            combined_poly[VARIABLE_VALUES_INDEX].push_back( polynomial_table.witness(i));
                        }

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        last = std::chrono::high_resolution_clock::now();
#endif
                        for (std::size_t i = 0; i < polynomial_table.public_inputs_amount(); i ++){
                            combined_poly[VARIABLE_VALUES_INDEX].push_back(polynomial_table.public_input(i));
                        }
                        typename commitment_scheme_type::precommitment_type variable_values_precommitment =
                            algorithms::precommit<commitment_scheme_type>(combined_poly[VARIABLE_VALUES_INDEX], fri_params.D[0],
                                                                                  fri_params.step_list.front());

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "witness_precommit_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        proof.variable_values_commitment =
                            algorithms::commit<commitment_scheme_type>(variable_values_precommitment);
                        transcript(proof.variable_values_commitment);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        last = std::chrono::high_resolution_clock::now();
#endif
                        // 4. permutation_argument
                        auto permutation_argument = placeholder_permutation_argument<FieldType, ParamsType>::prove_eval(
                            constraint_system,
                            preprocessed_public_data,
                            table_description,
                            polynomial_table,
                            fri_params,
                            transcript);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "permutation_argument_prove_eval_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        std::array<math::polynomial_dfs<typename FieldType::value_type>, f_parts> F_dfs;

                        F_dfs[0] = permutation_argument.F_dfs[0];
                        F_dfs[1] = permutation_argument.F_dfs[1];
                        F_dfs[2] = permutation_argument.F_dfs[2];

                        // 5. lookup_argument
                        typename placeholder_lookup_argument<FieldType, commitment_scheme_type, ParamsType>::prover_lookup_result lookup_argument;
                        lookup_argument = placeholder_lookup_argument<FieldType, commitment_scheme_type, ParamsType>::prove_eval(
                            constraint_system,
                            preprocessed_public_data,
                            polynomial_table,
                            fri_params,
                            transcript
                        );
                        F_dfs[3] = lookup_argument.F_dfs[0];
                        F_dfs[4] = lookup_argument.F_dfs[1];
                        F_dfs[5] = lookup_argument.F_dfs[2];
                        F_dfs[6] = lookup_argument.F_dfs[3];
                        F_dfs[7] = lookup_argument.F_dfs[4];

                        combined_poly[V_PERM_INDEX].resize(2);
                        combined_poly[V_PERM_INDEX][0] = permutation_argument.permutation_polynomial_dfs;
                        combined_poly[V_PERM_INDEX][1] = lookup_argument.V_L_polynomial;
                        auto permutation_polynomial_precommitment = algorithms::precommit<commitment_scheme_type>(
                            combined_poly[V_PERM_INDEX], fri_params.D[0], fri_params.step_list.front()
                        );
                        auto permutation_polynomial_commitment = algorithms::commit<commitment_scheme_type>(
                            permutation_polynomial_precommitment
                        );
                        proof.v_perm_commitment = permutation_polynomial_commitment;
                        transcript(permutation_polynomial_commitment);

                        // 6. circuit-satisfability
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        last = std::chrono::high_resolution_clock::now();
#endif
                        F_dfs[8] = placeholder_gates_argument<FieldType, ParamsType>::prove_eval(
                            constraint_system, polynomial_table, preprocessed_public_data.common_data.basic_domain,
                            preprocessed_public_data.common_data.max_gates_degree, transcript)[0];

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "gate_argument_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        /////TEST
#ifdef ZK_PLACEHOLDER_DEBUG_ENABLED
                        for (std::size_t i = 0; i < f_parts; i++) {
                            for (std::size_t j = 0; j < table_description.rows_amount; j++) {
                                if (F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(
                                        j)) != FieldType::value_type::zero()) {
                                    std::cout << "F[" << i << "] != 0 at j = " << j << std::endl;
                                }
                            }
                        }

                        const std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> gates =
                            constraint_system.gates();

                        for (std::size_t i = 0; i < gates.size(); i++) {
                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                math::polynomial_dfs<typename FieldType::value_type> constraint_result =
                                    gates[i].constraints[j].evaluate(
                                        polynomial_table, preprocessed_public_data.common_data.basic_domain) *
                                    polynomial_table.selector(gates[i].selector_index);
                            }
                        }
#endif

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        last = std::chrono::high_resolution_clock::now();
#endif

                        // 7. Aggregate quotient polynomial
                        math::polynomial<typename FieldType::value_type> T = quotient_polynomial(preprocessed_public_data, F_dfs, transcript);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "quotient_polynomial_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif

                        std::vector<math::polynomial<typename FieldType::value_type>> T_splitted =
                            detail::split_polynomial<FieldType>(T, fri_params.max_degree);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "split_polynomial_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> T_splitted_dfs;
                        for( std::size_t k = 0; k < T_splitted.size(); k++ ){
                            math::polynomial_dfs<typename FieldType::value_type> dfs(0, fri_params.D[0]->size());
                            dfs.from_coefficients(T_splitted[k]);
                            if( dfs.size() != fri_params.D[0]->size() ) dfs.resize(fri_params.D[0]->size());
                            T_splitted_dfs.push_back(dfs);
                        }

                        typename commitment_scheme_type::precommitment_type T_precommitment =
                            algorithms::precommit<commitment_scheme_type>(T_splitted_dfs, fri_params.D[0],  fri_params.step_list.front());
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "T_splitted_precommit_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        proof.T_commitment = algorithms::commit<commitment_scheme_type>(T_precommitment);
                        transcript(proof.T_commitment);


                        // 8. Run evaluation proofs
                        typename FieldType::value_type challenge = transcript.template challenge<FieldType>();

                        proof.eval_proof.challenge = challenge;
                        proof.eval_proof.lagrange_0 =
                            preprocessed_public_data.common_data.lagrange_0.evaluate(challenge);

                        typename FieldType::value_type omega =
                            preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

                        std::vector<std::vector<typename FieldType::value_type>>
                            variable_values_evaluation_points(witness_columns + public_input_columns);

                        // variable_values polynomials (table columns)
                        for (std::size_t variable_values_index = 0; variable_values_index < witness_columns + public_input_columns; variable_values_index++) {
                            std::set<int> variable_values_rotation =
                                preprocessed_public_data.common_data.columns_rotations[variable_values_index];

                            for (int rotation: variable_values_rotation) {
                                variable_values_evaluation_points[variable_values_index].push_back(
                                    challenge * omega.pow(rotation));
                            }
                        }
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "witness_evaluation_points_generated_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif

                        // permutation polynomial evaluation 
                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_v_p = {
                            {challenge, challenge * omega}, {challenge, challenge * omega}
                        };
                        math::polynomial_dfs<typename FieldType::value_type> perm_poly_dfs = permutation_argument.permutation_polynomial_dfs;
                        // lookup polynomials evaluation

                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_lookups;
                        evaluation_points_lookups.push_back({challenge, challenge * omega.inversed()}); // For the first
                        evaluation_points_lookups.push_back({challenge});

                        combined_poly[LOOKUP_INDEX].push_back(lookup_argument.input_polynomial);
                        combined_poly[LOOKUP_INDEX].push_back(lookup_argument.value_polynomial);

                        // quotient
                        std::vector<typename FieldType::value_type> challenge_point = {challenge};
                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_quotient = {challenge_point};
                        for (std::size_t k = 0; k < T_splitted.size(); k++) {
                            combined_poly[QUOTIENT_INDEX].push_back(T_splitted_dfs[k]);
                        }
                        // public
                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_public;

                        for (std::size_t k = 0; k < preprocessed_public_data.identity_polynomials.size(); k++) {
                            combined_poly[FIXED_VALUES_INDEX].push_back(preprocessed_public_data.identity_polynomials[k]);
                            evaluation_points_public.push_back(challenge_point);
                        }
                        
                        for (std::size_t k = 0; k < preprocessed_public_data.identity_polynomials.size(); k++) {
                            combined_poly[FIXED_VALUES_INDEX].push_back(preprocessed_public_data.permutation_polynomials[k]);
                            evaluation_points_public.push_back(challenge_point);
                        }

                        for (std::size_t k = 0; k < constant_columns; k ++){
                            combined_poly[FIXED_VALUES_INDEX].push_back(preprocessed_public_data.public_polynomial_table.constants()[k]);
                            std::set<int> rotations =
                                preprocessed_public_data.common_data.columns_rotations[witness_columns + public_input_columns + k];
                            std::vector<typename FieldType::value_type> point;

                            for (int rotation: rotations) {
                                point.push_back( challenge * omega.pow(rotation));
                            }
                            evaluation_points_public.push_back(point);
                        }
                        
                        for (std::size_t k = 0; k < preprocessed_public_data.public_polynomial_table.selectors().size(); k ++){
                            combined_poly[FIXED_VALUES_INDEX].push_back(preprocessed_public_data.public_polynomial_table.selectors()[k]);
                            std::set<int> rotations =
                                preprocessed_public_data.common_data.columns_rotations[witness_columns + public_input_columns + constant_columns + k];
                            std::vector<typename FieldType::value_type> point;

                            for (int rotation: rotations) {
                                point.push_back( challenge * omega.pow(rotation));
                            }
                            evaluation_points_public.push_back(point);
                        }

                        combined_poly[FIXED_VALUES_INDEX].push_back(preprocessed_public_data.q_last);
                        evaluation_points_public.push_back(challenge_point);
                        combined_poly[FIXED_VALUES_INDEX].push_back(preprocessed_public_data.q_blind);
                        evaluation_points_public.push_back(challenge_point);

                        std::array<std::vector<std::vector<typename FieldType::value_type>>, 5> evaluations_points;
                        evaluations_points[VARIABLE_VALUES_INDEX] = variable_values_evaluation_points;
                        evaluations_points[V_PERM_INDEX] = evaluation_points_v_p;
                        evaluations_points[QUOTIENT_INDEX] = evaluation_points_quotient;
                        evaluations_points[FIXED_VALUES_INDEX] = evaluation_points_public;
                        evaluations_points[LOOKUP_INDEX] = evaluation_points_lookups;

                        std::array<typename commitment_scheme_type::precommitment_type, 5> precommitments;
                        precommitments[VARIABLE_VALUES_INDEX] = typename commitment_scheme_type::precommitment_type(variable_values_precommitment);
                        precommitments[V_PERM_INDEX] = typename commitment_scheme_type::precommitment_type(permutation_polynomial_precommitment);
                        precommitments[QUOTIENT_INDEX] = typename commitment_scheme_type::precommitment_type(T_precommitment);
                        precommitments[FIXED_VALUES_INDEX] = typename commitment_scheme_type::precommitment_type(preprocessed_public_data.precommitments.fixed_values);
                        precommitments[LOOKUP_INDEX] = typename commitment_scheme_type::precommitment_type(lookup_argument.lookup_precommitment);

                        proof.fixed_values_commitment = preprocessed_public_data.common_data.commitments.fixed_values;
                        proof.lookup_commitment = algorithms::commit<commitment_scheme_type>(lookup_argument.lookup_precommitment);

                        proof.eval_proof.combined_value = algorithms::proof_eval<commitment_scheme_type>(
                                                    evaluations_points,
                                                    precommitments,
                                                    combined_poly, fri_params, transcript);

//#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
//                                                elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
//                                                    std::chrono::high_resolution_clock::now() - last);
//                                                std::cout << "fixed_values_proof_eval_time: " << std::fixed << std::setprecision(3)
//                                                        << elapsed.count() * 1e-6 << "ms" << std::endl;
//                                                last = std::chrono::high_resolution_clock::now();
//#endif

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        last = std::chrono::high_resolution_clock::now();
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - begin);
                        std::cout << "Placeholder prover, total time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
#endif
                        return proof;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PROVER_HPP
