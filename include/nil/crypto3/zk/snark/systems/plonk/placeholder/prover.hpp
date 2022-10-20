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
                    using merkle_hash_type = typename ParamsType::merkle_hash_type;
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;

                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;

                    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

                    constexpr static const std::size_t lambda = ParamsType::commitment_params_type::lambda;
                    constexpr static const std::size_t r = ParamsType::commitment_params_type::r;
                    constexpr static const std::size_t m = ParamsType::commitment_params_type::m;

                    using runtime_size_commitment_scheme_type =
                        typename ParamsType::runtime_size_commitment_scheme_type;
                    using fixed_values_commitment_scheme_type =
                        typename ParamsType::fixed_values_commitment_scheme_type;
                    using variable_values_commitment_scheme_type = typename ParamsType::variable_values_commitment_scheme_type;
                    using permutation_commitment_scheme_type = typename ParamsType::permutation_commitment_scheme_type;
                    using quotient_commitment_scheme_type = typename ParamsType::quotient_commitment_scheme_type;

                    using public_preprocessor_type = placeholder_public_preprocessor<FieldType, ParamsType>;
                    using private_preprocessor_type = placeholder_private_preprocessor<FieldType, ParamsType>;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t f_parts = 9;

                    static inline math::polynomial<typename FieldType::value_type> quotient_polynomial(
                        const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data,
                        const std::array<math::polynomial<typename FieldType::value_type>, f_parts> &F,
                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> &transcript) {

                        // 7.1. Get $\alpha_0, \dots, \alpha_8 \in \mathbb{F}$ from $hash(\text{transcript})$
                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();

                        // 7.2. Compute F_consolidated
                        math::polynomial<typename FieldType::value_type> F_consolidated = {0};
                        for (std::size_t i = 0; i < f_parts; i++) {
                            if (F[i].size() == 0)
                                continue;
                            F_consolidated = F_consolidated + alphas[i] * F[i];
                        }

                        math::polynomial<typename FieldType::value_type> T_consolidated =
                            F_consolidated / preprocessed_public_data.common_data.Z;

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
                            &fri_params) {    // TODO: fri_type are the same for each lpc_type here

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        auto begin = std::chrono::high_resolution_clock::now();
                        auto last = begin;
                        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "Placeholder prover:" << std::endl;
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
                        // transcript(short_description); //TODO: circuit_short_description marshalling
                        std::vector<std::uint8_t> transcript_init {};
                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(transcript_init);

                        // 2. Commit witness columns and public_input columns

                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> variable_polys;
                        
                        for (std::size_t i = 0; i < preprocessed_private_data.private_polynomial_table.witnesses().size(); i++){
                            variable_polys.push_back(preprocessed_private_data.private_polynomial_table.witnesses()[i]);
                        }

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        last = std::chrono::high_resolution_clock::now();
#endif
                        for (std::size_t i = 0; i < preprocessed_public_data.public_polynomial_table.public_inputs().size(); i ++){
                            variable_polys.push_back(preprocessed_public_data.public_polynomial_table.public_inputs()[i]);
                        }
                        
                        typename variable_values_commitment_scheme_type::precommitment_type variable_values_precommitment =
                            algorithms::precommit<variable_values_commitment_scheme_type>(variable_polys, fri_params.D[0],
                                                                                  fri_params.step_list.front());

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "witness_precommit_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        proof.variable_values_commitment =
                            algorithms::commit<variable_values_commitment_scheme_type>(variable_values_precommitment);
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
                        proof.v_perm_commitment = permutation_argument.permutation_poly_precommitment.root();

                        std::array<math::polynomial<typename FieldType::value_type>, f_parts> F;

                        F[0] = permutation_argument.F[0];
                        F[1] = permutation_argument.F[1];
                        F[2] = permutation_argument.F[2];

                        // 5. lookup_argument
                        bool is_lookup_enabled = constraint_system.lookup_gates().size() > 0;
                        typename placeholder_lookup_argument<FieldType, permutation_commitment_scheme_type,
                                                             ParamsType>::prover_lookup_result lookup_argument;
                        if (is_lookup_enabled) {

                            lookup_argument =
                                placeholder_lookup_argument<FieldType, permutation_commitment_scheme_type,
                                                            ParamsType>::prove_eval(constraint_system,
                                                                                    preprocessed_public_data,
                                                                                    assignments,
                                                                                    fri_params,
                                                                                    transcript);
                        } else {

                            for (std::size_t i = 0; i < lookup_argument.F.size(); i++) {
                                lookup_argument.F[i] = {0};
                            }
                        }

                        F[3] = lookup_argument.F[0];
                        F[4] = lookup_argument.F[1];
                        F[5] = lookup_argument.F[2];
                        F[6] = lookup_argument.F[3];
                        F[7] = lookup_argument.F[4];
                        if (is_lookup_enabled) {
                            proof.input_perm_commitment = lookup_argument.input_precommitment.root();
                            proof.value_perm_commitment = lookup_argument.value_precommitment.root();
                            proof.v_l_perm_commitment = lookup_argument.V_L_precommitment.root();
                        }
                        // 6. circuit-satisfability
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        last = std::chrono::high_resolution_clock::now();
#endif
                        F[8] = placeholder_gates_argument<FieldType, ParamsType>::prove_eval(
                            constraint_system, polynomial_table, preprocessed_public_data.common_data.basic_domain,
                            transcript)[0];
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
                                if (F[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(
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
                                // for (std::size_t k = 0; k < table_description.rows_amount; k++) {
                                if (constraint_result.evaluate(
                                        preprocessed_public_data.common_data.basic_domain->get_domain_element(253)) !=
                                    FieldType::value_type::zero()) {
                                    std::cout << "constraint " << j << " from gate " << i << "on row " << std::endl;
                                }
                                //}
                            }
                        }
#endif

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        last = std::chrono::high_resolution_clock::now();
#endif
                        ///// TODO Bug is here
                        // 7. Aggregate quotient polynomial
                        math::polynomial<typename FieldType::value_type> T =
                            quotient_polynomial(preprocessed_public_data, F, transcript);

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
                        typename runtime_size_commitment_scheme_type::precommitment_type T_precommitment =
                            algorithms::precommit<runtime_size_commitment_scheme_type>(T_splitted, fri_params.D[0],
                                                                                       fri_params.step_list.front());

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "T_splitted_precommit_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        proof.T_commitment = algorithms::commit<runtime_size_commitment_scheme_type>(T_precommitment);
                        transcript(proof.T_commitment);

                        // 8. Run evaluation proofs
                        typename FieldType::value_type challenge = transcript.template challenge<FieldType>();
                        proof.eval_proof.challenge = challenge;
                        proof.eval_proof.lagrange_0 =
                            preprocessed_public_data.common_data.lagrange_0.evaluate(challenge);

                        typename FieldType::value_type omega =
                            preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

                        std::array<std::vector<typename FieldType::value_type>, witness_columns + public_input_columns>
                            variable_values_evaluation_points;

                        // variable_values polynomials (table columns)
                        for (std::size_t variable_values_index = 0; variable_values_index < witness_columns; variable_values_index++) {

                            std::vector<int> variable_values_rotation =
                                preprocessed_public_data.common_data.columns_rotations[variable_values_index];

                            for (std::size_t rotation_index = 0; rotation_index < variable_values_rotation.size();
                                 rotation_index++) {
                                variable_values_evaluation_points[variable_values_index].push_back(
                                    challenge * omega.pow(variable_values_rotation[rotation_index]));
                            }
                        }
                        for (std::size_t i = witness_columns; i < witness_columns + public_input_columns; i ++) {
                            variable_values_evaluation_points[i].push_back(challenge);
                        }
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "witness_evaluation_points_generated_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif

                        proof.eval_proof.variable_values = algorithms::proof_eval<variable_values_commitment_scheme_type>(
                                                    variable_values_evaluation_points, variable_values_precommitment,
                                                    variable_polys, fri_params, transcript);
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "variable_values proof_eval, time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        // permutation polynomial evaluation
                        std::vector<typename FieldType::value_type> evaluation_points_v_p = {challenge,
                                                                                             challenge * omega};
                        proof.eval_proof.permutation = algorithms::proof_eval<permutation_commitment_scheme_type>(
                            evaluation_points_v_p,
                            permutation_argument.permutation_poly_precommitment,
                            permutation_argument.permutation_polynomial,
                            fri_params,
                            transcript);
#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "permutation_proof_eval_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif

                        // lookup polynomials evaluation
                        if (is_lookup_enabled) {
                            std::vector<typename FieldType::value_type> evaluation_points_v_l = {challenge,
                                                                                                 challenge * omega};
                            typename permutation_commitment_scheme_type::proof_type v_l_evaluation =
                                algorithms::proof_eval<permutation_commitment_scheme_type>(
                                    evaluation_points_v_l,
                                    lookup_argument.V_L_precommitment,
                                    lookup_argument.V_L_polynomial,
                                    fri_params,
                                    transcript);
                            proof.eval_proof.lookups.push_back(v_l_evaluation);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                            elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::high_resolution_clock::now() - last);
                            std::cout << "v_l_evaluation proof_eval, time: " << std::fixed << std::setprecision(3)
                                      << elapsed.count() * 1e-6 << "ms" << std::endl;
                            last = std::chrono::high_resolution_clock::now();
#endif
                            std::vector<typename FieldType::value_type> evaluation_points_input = {
                                challenge, challenge * omega.inversed()};
                            typename permutation_commitment_scheme_type::proof_type input_evaluation =
                                algorithms::proof_eval<permutation_commitment_scheme_type>(
                                    evaluation_points_input,
                                    lookup_argument.input_precommitment,
                                    lookup_argument.input_polynomial,
                                    fri_params,
                                    transcript);
                            proof.eval_proof.lookups.push_back(input_evaluation);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                            elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::high_resolution_clock::now() - last);
                            std::cout << "input_evaluation proof_eval, time: " << std::fixed << std::setprecision(3)
                                      << elapsed.count() * 1e-6 << "ms" << std::endl;
                            last = std::chrono::high_resolution_clock::now();
#endif
                            std::vector<typename FieldType::value_type> evaluation_points_value = {challenge};
                            typename permutation_commitment_scheme_type::proof_type value_evaluation =
                                algorithms::proof_eval<permutation_commitment_scheme_type>(
                                    evaluation_points_value,
                                    lookup_argument.value_precommitment,
                                    lookup_argument.value_polynomial,
                                    fri_params,
                                    transcript);
                            proof.eval_proof.lookups.push_back(value_evaluation);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                            elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                std::chrono::high_resolution_clock::now() - last);
                            std::cout << "value_evaluation proof_eval, time: " << std::fixed << std::setprecision(3)
                                      << elapsed.count() * 1e-6 << "ms" << std::endl;
                            last = std::chrono::high_resolution_clock::now();
#endif
                        }

                        // quotient
                        std::vector<typename FieldType::value_type> evaluation_points_quotient = {challenge};
                        proof.eval_proof.quotient = algorithms::proof_eval<runtime_size_commitment_scheme_type>(
                            {challenge}, T_precommitment, T_splitted, fri_params, transcript);

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                        elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::high_resolution_clock::now() - last);
                        std::cout << "quotient_proof_eval_time: " << std::fixed << std::setprecision(3)
                                  << elapsed.count() * 1e-6 << "ms" << std::endl;
                        last = std::chrono::high_resolution_clock::now();
#endif
                        // public
                        std::vector<typename FieldType::value_type> &evaluation_points_public =
                            evaluation_points_quotient;

                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> fixed_polys;
                        fixed_polys.insert( fixed_polys.end(), preprocessed_public_data.identity_polynomials.begin(), preprocessed_public_data.identity_polynomials.end() );
                        fixed_polys.insert( fixed_polys.end(), preprocessed_public_data.permutation_polynomials.begin(), preprocessed_public_data.permutation_polynomials.end() );
                        
                        for (std::size_t i = 0; i < preprocessed_public_data.public_polynomial_table.constants().size(); i ++){
                            fixed_polys.push_back(preprocessed_public_data.public_polynomial_table.constants()[i]);
                        }
                        for (std::size_t i = 0; i < preprocessed_public_data.public_polynomial_table.selectors().size(); i ++){
                            fixed_polys.push_back(preprocessed_public_data.public_polynomial_table.selectors()[i]);
                        }
                        
                        fixed_polys.push_back(preprocessed_public_data.q_last);
                        fixed_polys.push_back(preprocessed_public_data.q_blind);

                        proof.eval_proof.fixed_values = algorithms::proof_eval<fixed_values_commitment_scheme_type>(
                                                    evaluation_points_public, preprocessed_public_data.precommitments.fixed_values,
                                                    fixed_polys, fri_params, transcript);

/*#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                                                elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                    std::chrono::high_resolution_clock::now() - last);
                                                std::cout << "fixed_values_proof_eval_time: " << std::fixed << std::setprecision(3)
                                                        << elapsed.count() * 1e-6 << "ms" << std::endl;
                                                last = std::chrono::high_resolution_clock::now();
#endif*/

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
