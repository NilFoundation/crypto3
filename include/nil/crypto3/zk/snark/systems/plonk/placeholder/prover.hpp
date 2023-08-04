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
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_scoped_profiler.hpp>
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
                        PROFILE_PLACEHOLDER_SCOPE("split_polynomial_time");

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
                    typedef typename math::polynomial<typename FieldType::value_type> polynomial_type;
                    typedef typename math::polynomial_dfs<typename FieldType::value_type> polynomial_dfs_type;

                    constexpr static const std::size_t lambda = ParamsType::commitment_params_type::lambda;
                    constexpr static const std::size_t r = ParamsType::commitment_params_type::r;
                    constexpr static const std::size_t m = ParamsType::commitment_params_type::m;

                    using commitment_scheme_type =
                        typename ParamsType::runtime_size_commitment_scheme_type;

                    using public_preprocessor_type = placeholder_public_preprocessor<FieldType, ParamsType>;
                    using private_preprocessor_type = placeholder_private_preprocessor<FieldType, ParamsType>;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t lookup_parts = 6;
                    constexpr static const std::size_t f_parts = 10;

              public:

                    static inline placeholder_proof<FieldType, ParamsType> process(
                        const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data,
                        const typename private_preprocessor_type::preprocessed_data_type &preprocessed_private_data,
                        const plonk_table_description<FieldType, typename ParamsType::arithmetization_params>
                            &table_description,
                        const plonk_constraint_system<FieldType, typename ParamsType::arithmetization_params>
                            &constraint_system,
                        const typename policy_type::variable_assignment_type &assignments,
                        const typename ParamsType::commitment_params_type &fri_params) { 

                        auto prover = placeholder_prover<FieldType, ParamsType>(
                            preprocessed_public_data, preprocessed_private_data, table_description,
                            constraint_system, assignments, fri_params);
                        return prover.process();
                    }

                    placeholder_prover(
                        const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data,
                        const typename private_preprocessor_type::preprocessed_data_type &preprocessed_private_data,
                        const plonk_table_description<FieldType, typename ParamsType::arithmetization_params> &table_description,
                        const plonk_constraint_system<FieldType, typename ParamsType::arithmetization_params> &constraint_system,
                        const typename policy_type::variable_assignment_type &assignments,
                        const typename ParamsType::commitment_params_type &fri_params) 
                            : preprocessed_public_data(preprocessed_public_data)
                            , preprocessed_private_data(preprocessed_private_data)
                            , table_description(table_description)
                            , constraint_system(constraint_system)
                            , assignments(assignments)
                            , fri_params(fri_params)
                            , _polynomial_table(preprocessed_private_data.private_polynomial_table,
                                                preprocessed_public_data.public_polynomial_table) 
                            , _is_lookup_enabled(constraint_system.lookup_gates().size() > 0)
                            , transcript(std::vector<std::uint8_t>())
                    {
                        // 1. Add circuit definition to transcript
                        // transcript(short_description); 
                        //TODO: circuit_short_description marshalling
                    }

                    placeholder_proof<FieldType, ParamsType> process() {
                        PROFILE_PLACEHOLDER_SCOPE("Placeholder prover, total time:");

                        // 2. Commit witness columns and public_input columns

                        for (std::size_t i = 0; i < _polynomial_table.witnesses_amount(); i++){
                            _combined_poly[VARIABLE_VALUES_BATCH].push_back( _polynomial_table.witness(i));
                        }

                        for (std::size_t i = 0; i < _polynomial_table.public_inputs_amount(); i++){
                            _combined_poly[VARIABLE_VALUES_BATCH].push_back(_polynomial_table.public_input(i));
                        }

                        auto variable_values_precommitment = precommit_witness();

                        _proof.variable_values_commitment =
                            algorithms::commit<commitment_scheme_type>(variable_values_precommitment);
                        transcript(_proof.variable_values_commitment);

                        // 4. permutation_argument
                        auto permutation_argument = placeholder_permutation_argument<FieldType, ParamsType>::prove_eval(
                            constraint_system,
                            preprocessed_public_data,
                            table_description,
                            _polynomial_table,
                            fri_params,
                            transcript);
                        _combined_poly[PERMUTATION_BATCH].push_back(std::move(permutation_argument.permutation_polynomial_dfs));

                        _F_dfs[0] = std::move(permutation_argument.F_dfs[0]);
                        _F_dfs[1] = std::move(permutation_argument.F_dfs[1]);
                        _F_dfs[2] = std::move(permutation_argument.F_dfs[2]);

                        // 5. lookup_argument
                        auto lookup_argument_result = lookup_argument();
                        _combined_poly[LOOKUP_BATCH] = lookup_argument_result.sorted_batch;
                        _proof.lookup_commitment = lookup_argument_result.lookup_precommitment.root();
                        _F_dfs[3] = std::move(lookup_argument_result.F_dfs[0]);
                        _F_dfs[4] = std::move(lookup_argument_result.F_dfs[1]);
                        _F_dfs[5] = std::move(lookup_argument_result.F_dfs[2]);
                        _F_dfs[6] = std::move(lookup_argument_result.F_dfs[3]);
                        _F_dfs[7] = std::move(lookup_argument_result.F_dfs[4]);
                        _F_dfs[8] = std::move(lookup_argument_result.F_dfs[5]);

                        _combined_poly[PERMUTATION_BATCH].push_back(std::move(lookup_argument_result.V_polynomials[0]));
                        _combined_poly[PERMUTATION_BATCH].push_back(std::move(lookup_argument_result.V_polynomials[1]));

                        auto permutation_poly_precommitment = precommit_permutations();
                        _proof.v_perm_commitment = permutation_poly_precommitment.root();
                        transcript(_proof.v_perm_commitment);

                        // 6. circuit-satisfability
                        _F_dfs[9] = placeholder_gates_argument<FieldType, ParamsType>::prove_eval(
                            constraint_system, _polynomial_table,
                            preprocessed_public_data.common_data.basic_domain,
                            preprocessed_public_data.common_data.max_gates_degree,
                            transcript)[0];

                        /////TEST
#ifdef ZK_PLACEHOLDER_DEBUG_ENABLED
                        placeholder_debug_output();
#endif

                        // 7. Aggregate quotient polynomial
                        std::vector<polynomial_dfs_type> T_splitted_dfs = 
                            quotient_polynomial_split_dfs();

                        auto T_precommitment = T_precommit(T_splitted_dfs);
                        
                        commit_T(T_precommitment);

                        // 8. Run evaluation proofs
                        auto variable_values_evaluation_points = run_evaluation_proofs();

                        // permutation polynomial evaluation 
                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_v_p = 
                            {{_proof.eval_proof.challenge, _proof.eval_proof.challenge * _omega}};

                        // lookup polynomials evaluation

                        // quotient
                        _challenge_point = {_proof.eval_proof.challenge};

                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_quotient = {_challenge_point};
                        _combined_poly[QUOTIENT_BATCH].insert(
                            std::end(_combined_poly[QUOTIENT_BATCH]),
                            std::make_move_iterator(std::begin(T_splitted_dfs)),
                            std::make_move_iterator(std::end(T_splitted_dfs)));

                        // public
                        auto evaluation_points_public = compute_evaluation_points_public();

                        std::array<std::vector<std::vector<typename FieldType::value_type>>, 5> evaluation_points = {
                            variable_values_evaluation_points,
                            evaluation_points_v_p,
                            evaluation_points_v_p,
                            evaluation_points_quotient,
                            evaluation_points_public
                        };
                        std::array<typename commitment_scheme_type::precommitment_type, 5> precommitments = {
                            std::move(variable_values_precommitment),
                            std::move(lookup_argument_result.lookup_precommitment),
                            std::move(permutation_poly_precommitment),
                            std::move(T_precommitment),
                            preprocessed_public_data.precommitments.fixed_values
                        };

                        _proof.eval_proof.combined_value = compute_combined_value(
                            evaluation_points,
                            precommitments
                        );

                        _proof.fixed_values_commitment = preprocessed_public_data.common_data.commitments.fixed_values;
                        return std::move(_proof);
                    }

                private:
                    typename commitment_scheme_type::precommitment_type precommit_witness() {
                        PROFILE_PLACEHOLDER_SCOPE("witness_precommit_time");
                        return algorithms::precommit<commitment_scheme_type>(
                            _combined_poly[0], fri_params.D[0], fri_params.step_list.front());
                    }

                    typename commitment_scheme_type::precommitment_type precommit_permutations() {
                        PROFILE_PLACEHOLDER_SCOPE("permutations_precommit_time");
                        return algorithms::precommit<commitment_scheme_type>(
                            _combined_poly[PERMUTATION_BATCH], fri_params.D[0], fri_params.step_list.front());
                    }

                    std::vector<polynomial_dfs_type> quotient_polynomial_split_dfs() {
                        std::vector<polynomial_type> T_splitted = 
                            detail::split_polynomial<FieldType>(
                                quotient_polynomial(), fri_params.max_degree);

                        PROFILE_PLACEHOLDER_SCOPE("split_polynomial_dfs_conversion_time");

                        std::vector<polynomial_dfs_type> T_splitted_dfs(
                            T_splitted.size(), polynomial_dfs_type(0, fri_params.D[0]->size()));
                        for (std::size_t k = 0; k < T_splitted.size(); k++) {
                            T_splitted_dfs[k].from_coefficients(T_splitted[k]);
                            if (T_splitted_dfs[k].size() != fri_params.D[0]->size())
                                T_splitted_dfs[k].resize(fri_params.D[0]->size());
                        }
                        return T_splitted_dfs;
                    }

                    polynomial_type quotient_polynomial() {
                        PROFILE_PLACEHOLDER_SCOPE("quotient_polynomial_time");

                        // 7.1. Get $\alpha_0, \dots, \alpha_8 \in \mathbb{F}$ from $hash(\text{transcript})$
                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();

                        // 7.2. Compute F_consolidated
                        polynomial_dfs_type F_consolidated_dfs(
                            0, _F_dfs[0].size(), FieldType::value_type::zero());
                        for (std::size_t i = 0; i < f_parts; i++) {
                            if (_F_dfs[i].is_zero()) {
                                continue;
                            }
                            F_consolidated_dfs += alphas[i] * _F_dfs[i];
                        }

                        polynomial_type F_consolidated_normal(F_consolidated_dfs.coefficients());
                        polynomial_type T_consolidated =
                            F_consolidated_normal / preprocessed_public_data.common_data.Z;

                        return T_consolidated;
                    }
                    
                    typename placeholder_lookup_argument<
                        FieldType, commitment_scheme_type, ParamsType>::prover_lookup_result 
                    lookup_argument() {
                        PROFILE_PLACEHOLDER_SCOPE("lookup_argument_time");

                        typename placeholder_lookup_argument<
                            FieldType,
                            commitment_scheme_type,
                            ParamsType>::prover_lookup_result lookup_argument_result;

                        lookup_argument_result = placeholder_lookup_argument< FieldType,  commitment_scheme_type, ParamsType>::prove_eval(
                            constraint_system,
                            preprocessed_public_data,
                            _polynomial_table,
                            fri_params,
                            transcript
                        );


                        _proof.lookup_commitment = lookup_argument_result.lookup_precommitment.root();
                        return lookup_argument_result;
                    }

                    typename commitment_scheme_type::precommitment_type 
                    T_precommit(const std::vector<polynomial_dfs_type>& T_splitted_dfs) {
                        PROFILE_PLACEHOLDER_SCOPE("T_splitted_precommit_time");

                        return algorithms::precommit<commitment_scheme_type>(
                            T_splitted_dfs,
                            fri_params.D[0],
                            fri_params.step_list.front());
                    }
                
                    void commit_T(const typename commitment_scheme_type::precommitment_type& T_precommitment) {
                        PROFILE_PLACEHOLDER_SCOPE("T_splitted_commit_time");
                        _proof.T_commitment = algorithms::commit<commitment_scheme_type>(T_precommitment);
                        transcript(_proof.T_commitment);
                    }

                    void placeholder_debug_output() {
                        for (std::size_t i = 0; i < f_parts; i++) {
                            for (std::size_t j = 0; j < table_description.rows_amount; j++) {
                                if (_F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(
                                        j)) != FieldType::value_type::zero()) {
                                    std::cout << "F_dfs[" << i << "] != 0 at j = " << j << std::endl;
                                }
                            }
                        }

                        const auto& gates = constraint_system.gates();

                        for (std::size_t i = 0; i < gates.size(); i++) {
                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                polynomial_dfs_type constraint_result =
                                    gates[i].constraints[j].evaluate(
                                        _polynomial_table, preprocessed_public_data.common_data.basic_domain) *
                                    _polynomial_table.selector(gates[i].selector_index);
                                // for (std::size_t k = 0; k < table_description.rows_amount; k++) {
                                if (constraint_result.evaluate(
                                        preprocessed_public_data.common_data.basic_domain->get_domain_element(253)) !=
                                    FieldType::value_type::zero()) {
                                    std::cout << "constraint " << j << " from gate " << i << "on row " << std::endl;
                                }
                            }
                        }
                    }

                    std::vector<std::vector<typename FieldType::value_type>> run_evaluation_proofs() {
                        PROFILE_PLACEHOLDER_SCOPE("witness_evaluation_points_generated_time");

                        _proof.eval_proof.challenge = transcript.template challenge<FieldType>();
                        _proof.eval_proof.lagrange_0 =
                            preprocessed_public_data.common_data.lagrange_0.evaluate(_proof.eval_proof.challenge);

                        _omega = preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

                        std::vector<std::vector<typename FieldType::value_type>>
                            variable_values_evaluation_points(witness_columns + public_input_columns);

                        // variable_values polynomials (table columns)
                        for (std::size_t variable_values_index = 0; 
                             variable_values_index < witness_columns + public_input_columns;
                             variable_values_index++) {
                            const std::set<int>& variable_values_rotation =
                                preprocessed_public_data.common_data.columns_rotations[variable_values_index];

                            auto& evaluation_points = variable_values_evaluation_points[variable_values_index];
                            evaluation_points.reserve(variable_values_rotation.size());

                            for (int rotation: variable_values_rotation) {
                                evaluation_points.push_back(_proof.eval_proof.challenge * _omega.pow(rotation));
                            }
                        }
                        return variable_values_evaluation_points;
                    }

                    std::vector<std::vector<typename FieldType::value_type>> compute_evaluation_points_public() {
                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_public(
                            preprocessed_public_data.identity_polynomials.size() + 
                            preprocessed_public_data.permutation_polynomials.size(),
                            _challenge_point);

                        // TODO: Can't move the values from preprocessed_public_data, maybe change it later.
                        _combined_poly[FIXED_VALUES_BATCH].insert(
                            std::end(_combined_poly[FIXED_VALUES_BATCH]),
                            std::begin(preprocessed_public_data.identity_polynomials),
                            std::end(preprocessed_public_data.identity_polynomials));
                        _combined_poly[FIXED_VALUES_BATCH].insert(
                            std::end(_combined_poly[FIXED_VALUES_BATCH]),
                            std::begin(preprocessed_public_data.permutation_polynomials),
                            std::end(preprocessed_public_data.permutation_polynomials));
                        _combined_poly[FIXED_VALUES_BATCH].insert(
                            std::end(_combined_poly[FIXED_VALUES_BATCH]),
                            std::begin(preprocessed_public_data.public_polynomial_table.constants()),
                            std::end(preprocessed_public_data.public_polynomial_table.constants()));
                        _combined_poly[FIXED_VALUES_BATCH].insert(
                            std::end(_combined_poly[FIXED_VALUES_BATCH]),
                            std::begin(preprocessed_public_data.public_polynomial_table.selectors()),
                            std::end(preprocessed_public_data.public_polynomial_table.selectors()));

                        for (std::size_t k = 0, rotation_index = witness_columns + public_input_columns; k < constant_columns; k++, rotation_index++) {
                            const std::set<int>& rotations =
                                preprocessed_public_data.common_data.columns_rotations[rotation_index];
                            std::vector<typename FieldType::value_type> point;
                            point.reserve(rotations.size());

                            for (int rotation: rotations) {
                                // TODO: Maybe precompute values of _omega.pow(rotation)??? Rotation can be -1, causing computation
                                // of inverse element multiple times.
                                point.push_back( _proof.eval_proof.challenge * _omega.pow(rotation));
                            }
                            evaluation_points_public.push_back(std::move(point));
                        }
                        
                        for (std::size_t k = 0, rotation_index = witness_columns + public_input_columns + constant_columns; k < preprocessed_public_data.public_polynomial_table.selectors().size(); k++, rotation_index++) {
                            const std::set<int>& rotations =
                                preprocessed_public_data.common_data.columns_rotations[rotation_index];
                            std::vector<typename FieldType::value_type> point;
                            point.reserve(rotations.size());

                            for (int rotation: rotations) {
                                point.push_back( _proof.eval_proof.challenge * _omega.pow(rotation));
                            }
                            evaluation_points_public.push_back(std::move(point));
                        }

                        _combined_poly[FIXED_VALUES_BATCH].push_back(preprocessed_public_data.q_last);
                        evaluation_points_public.push_back(_challenge_point);
                        _combined_poly[FIXED_VALUES_BATCH].push_back(preprocessed_public_data.q_blind);
                        evaluation_points_public.push_back(_challenge_point);

                        return evaluation_points_public;
                    }

                    typename commitment_scheme_type::proof_type compute_combined_value(
                        std::array<std::vector<std::vector<typename FieldType::value_type>>, 5> evaluation_points,
                        std::array<typename commitment_scheme_type::precommitment_type, 5> precommitments
                    ) {
                        return algorithms::proof_eval<commitment_scheme_type>(
                             evaluation_points,
                             precommitments,
                             _combined_poly, 
                             fri_params, transcript
                        );
                    }

                private:
                    // Structures passed from outside by reference.
                    const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data;
                    const typename private_preprocessor_type::preprocessed_data_type &preprocessed_private_data;
                    const plonk_table_description<FieldType, typename ParamsType::arithmetization_params> &table_description;
                    const plonk_constraint_system<FieldType, typename ParamsType::arithmetization_params> &constraint_system;
                    const typename policy_type::variable_assignment_type &assignments;
                    const typename ParamsType::commitment_params_type &fri_params;
                    
                    // Members created during proof generation.
                    plonk_polynomial_dfs_table<FieldType, typename ParamsType::arithmetization_params> _polynomial_table;
                    placeholder_proof<FieldType, ParamsType> _proof;
                    std::array<std::vector<polynomial_dfs_type>, 5> _combined_poly;
                    std::array<polynomial_dfs_type, f_parts> _F_dfs;
                    transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript;
                    bool _is_lookup_enabled;
                    typename FieldType::value_type _omega;
                    std::vector<typename FieldType::value_type> _challenge_point;

                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PROVER_HPP
