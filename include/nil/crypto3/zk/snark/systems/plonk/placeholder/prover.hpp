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
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
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
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;

                    typedef typename math::polynomial<typename FieldType::value_type> polynomial_type;
                    typedef typename math::polynomial_dfs<typename FieldType::value_type> polynomial_dfs_type;

                    using commitment_scheme_type = typename ParamsType::commitment_scheme_type;
                    using commitment_type = typename commitment_scheme_type::commitment_type;

                    using public_preprocessor_type = placeholder_public_preprocessor<FieldType, ParamsType>;
                    using private_preprocessor_type = placeholder_private_preprocessor<FieldType, ParamsType>;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t lookup_parts = 6;
                    constexpr static const std::size_t f_parts = 8;
              public:

                    static inline placeholder_proof<FieldType, ParamsType> process(
                        const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data,
                        typename private_preprocessor_type::preprocessed_data_type preprocessed_private_data,
                        const plonk_table_description<FieldType> &table_description,
                        const plonk_constraint_system<FieldType> &constraint_system,
                        commitment_scheme_type commitment_scheme
                    ) {

                        auto prover = placeholder_prover<FieldType, ParamsType>(
                            preprocessed_public_data, std::move(preprocessed_private_data), table_description,
                            constraint_system, commitment_scheme);
                        return prover.process();
                    }

                    placeholder_prover(
                        const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data,
                        typename private_preprocessor_type::preprocessed_data_type preprocessed_private_data,
                        const plonk_table_description<FieldType> &table_description,
                        const plonk_constraint_system<FieldType> &constraint_system,
                        const commitment_scheme_type &commitment_scheme
                    )
                            : preprocessed_public_data(preprocessed_public_data)
                            , table_description(table_description)
                            , constraint_system(constraint_system)
                            , _polynomial_table(new plonk_polynomial_dfs_table<FieldType>(
                                std::move(preprocessed_private_data.private_polynomial_table),
                                preprocessed_public_data.public_polynomial_table))

                            , transcript(std::vector<std::uint8_t>({}))
                            , _is_lookup_enabled(constraint_system.lookup_gates().size() > 0)
                            , _commitment_scheme(commitment_scheme)
                    {
                        // Initialize transcript.
                        transcript(preprocessed_public_data.common_data.vk.constraint_system_with_params_hash);
                        transcript(preprocessed_public_data.common_data.vk.fixed_values_commitment);

                        // Setup commitment scheme. LPC adds an additional point here.
                        _commitment_scheme.setup(transcript, preprocessed_public_data.common_data.commitment_scheme_data);
                    }

                    placeholder_proof<FieldType, ParamsType> process() {
                        PROFILE_PLACEHOLDER_SCOPE("Placeholder prover, total time");

                        // 2. Commit witness columns and public_input columns
                        _commitment_scheme.append_to_batch(VARIABLE_VALUES_BATCH, _polynomial_table->witnesses());
                        _commitment_scheme.append_to_batch(VARIABLE_VALUES_BATCH, _polynomial_table->public_inputs());
                        {
                            PROFILE_PLACEHOLDER_SCOPE("variable_values_precommit_time");
                            _proof.commitments[VARIABLE_VALUES_BATCH] = _commitment_scheme.commit(VARIABLE_VALUES_BATCH);
                        }
                        transcript(_proof.commitments[VARIABLE_VALUES_BATCH]);

                        // 4. permutation_argument
                        {
                            auto permutation_argument = placeholder_permutation_argument<FieldType, ParamsType>::prove_eval(
                                constraint_system,
                                preprocessed_public_data,
                                table_description,
                                *_polynomial_table,
                                _commitment_scheme,
                                transcript);

                            _F_dfs[0] = std::move(permutation_argument.F_dfs[0]);
                            _F_dfs[1] = std::move(permutation_argument.F_dfs[1]);
                            _F_dfs[2] = std::move(permutation_argument.F_dfs[2]);
                        }

                        // 5. lookup_argument
                        {
                            auto lookup_argument_result = lookup_argument();
                            _F_dfs[3] = std::move(lookup_argument_result.F_dfs[0]);
                            _F_dfs[4] = std::move(lookup_argument_result.F_dfs[1]);
                            _F_dfs[5] = std::move(lookup_argument_result.F_dfs[2]);
                            _F_dfs[6] = std::move(lookup_argument_result.F_dfs[3]);
                        }

                        _proof.commitments[PERMUTATION_BATCH] = _commitment_scheme.commit(PERMUTATION_BATCH);
                        transcript(_proof.commitments[PERMUTATION_BATCH]);

                        // 6. circuit-satisfability

                        polynomial_dfs_type mask_polynomial(
                            0, preprocessed_public_data.common_data.basic_domain->m,
                            typename FieldType::value_type(1)
                        );
                        mask_polynomial -= preprocessed_public_data.q_last;
                        mask_polynomial -= preprocessed_public_data.q_blind;
                        _F_dfs[7] = placeholder_gates_argument<FieldType, ParamsType>::prove_eval(
                            constraint_system, *_polynomial_table,
                            preprocessed_public_data.common_data.basic_domain,
                            preprocessed_public_data.common_data.max_gates_degree,
                            mask_polynomial,
                            transcript
                        )[0];

                        /////TEST
#ifdef ZK_PLACEHOLDER_DEBUG_ENABLED
                        placeholder_debug_output();
#endif

                        // _polynomial_table not needed, clean its memory
                        _polynomial_table.reset(nullptr);

                        // 7. Aggregate quotient polynomial
                        {
                            std::vector<polynomial_dfs_type> T_splitted_dfs =
                                quotient_polynomial_split_dfs();

                            _proof.commitments[QUOTIENT_BATCH] = T_commit(T_splitted_dfs);
                        }
                        transcript(_proof.commitments[QUOTIENT_BATCH]);

                        // 8. Run evaluation proofs
                        _proof.eval_proof.challenge = transcript.template challenge<FieldType>();

                        generate_evaluation_points();

                        {
                            PROFILE_PLACEHOLDER_SCOPE("commitment scheme proof eval time");
                            _proof.eval_proof.eval_proof = _commitment_scheme.proof_eval(transcript);
                        }

                        return _proof;
                    }

                private:
                    std::vector<polynomial_dfs_type> quotient_polynomial_split_dfs() {
                        // TODO: pass max_degree parameter placeholder
                        std::vector<polynomial_type> T_splitted = detail::split_polynomial<FieldType>(
                            quotient_polynomial(), table_description.rows_amount - 1
                        );

                        PROFILE_PLACEHOLDER_SCOPE("split_polynomial_dfs_conversion_time");

                        std::size_t split_polynomial_size = std::max(
                            (preprocessed_public_data.identity_polynomials.size() + 2) * (preprocessed_public_data.common_data.rows_amount -1 ),
                            (constraint_system.lookup_poly_degree_bound() + 1) * (preprocessed_public_data.common_data.rows_amount -1 )//,
                        );
                        split_polynomial_size = std::max(
                            split_polynomial_size,
                            (preprocessed_public_data.common_data.max_gates_degree + 1) * (preprocessed_public_data.common_data.rows_amount -1)
                        );
                        split_polynomial_size = (split_polynomial_size % preprocessed_public_data.common_data.rows_amount != 0)?
                            (split_polynomial_size / preprocessed_public_data.common_data.rows_amount + 1):
                            (split_polynomial_size / preprocessed_public_data.common_data.rows_amount);

                        // We need split_polynomial_size computation because proof size shouldn't depend on public input size.
                        // we set this size as maximum of
                        //      F[2] (from permutation argument)
                        //      F[5] (from lookup argument)
                        //      F[7] (from gates argument)
                        // If some columns used in permutation or lookup argument are zero, real quotient polynomial degree
                        //      may be less than split_polynomial_size.
                        std::vector<polynomial_dfs_type> T_splitted_dfs(split_polynomial_size,
                            polynomial_dfs_type(0, _F_dfs[0].size(), FieldType::value_type::zero()));

                        for (std::size_t k = 0; k < T_splitted.size(); k++) {
                            T_splitted_dfs[k].from_coefficients(T_splitted[k]);
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

                    typename placeholder_lookup_argument_prover<FieldType, commitment_scheme_type, ParamsType>::prover_lookup_result
                        lookup_argument() {
                        PROFILE_PLACEHOLDER_SCOPE("lookup_argument_time");

                        typename placeholder_lookup_argument_prover<
                            FieldType,
                            commitment_scheme_type,
                            ParamsType>::prover_lookup_result lookup_argument_result;

                        lookup_argument_result.F_dfs[0] = polynomial_dfs_type(0, table_description.rows_amount, FieldType::value_type::zero());
                        lookup_argument_result.F_dfs[1] = polynomial_dfs_type(0, table_description.rows_amount, FieldType::value_type::zero());
                        lookup_argument_result.F_dfs[2] = polynomial_dfs_type(0, table_description.rows_amount, FieldType::value_type::zero());
                        lookup_argument_result.F_dfs[3] = polynomial_dfs_type(0, table_description.rows_amount, FieldType::value_type::zero());

                        if (_is_lookup_enabled) {
                            placeholder_lookup_argument_prover<FieldType, commitment_scheme_type, ParamsType> lookup_argument_prover(
                                constraint_system,
                                preprocessed_public_data,
                                *_polynomial_table,
                                _commitment_scheme,
                                transcript
                            );
;
                            lookup_argument_result = lookup_argument_prover.prove_eval();
                            _proof.commitments[LOOKUP_BATCH] = lookup_argument_result.lookup_commitment;
                        }
                        return lookup_argument_result;
                    }

                    commitment_type T_commit(const std::vector<polynomial_dfs_type>& T_splitted_dfs) {
                        PROFILE_PLACEHOLDER_SCOPE("T_splitted_precommit_time");
                        _commitment_scheme.append_to_batch(QUOTIENT_BATCH, T_splitted_dfs);
                        return _commitment_scheme.commit(QUOTIENT_BATCH);
                    }

                    void placeholder_debug_output() {
                        for (std::size_t i = 0; i < f_parts; i++) {
                            for (std::size_t j = 0; j < table_description.rows_amount; j++) {
                                if (_F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) != FieldType::value_type::zero()) {
                                    std::cout << "_F_dfs[" << i << "] on row " << j << " = " << _F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) << std::endl;
                                }
                            }
                        }

                        const auto& gates = constraint_system.gates();

                        for (std::size_t i = 0; i < gates.size(); i++) {
                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                polynomial_dfs_type constraint_result =
                                    gates[i].constraints[j].evaluate(
                                        *_polynomial_table, preprocessed_public_data.common_data.basic_domain) *
                                    _polynomial_table.selector(gates[i].selector_index);
                                // for (std::size_t k = 0; k < table_description.rows_amount; k++) {
                                if (constraint_result.evaluate(
                                        preprocessed_public_data.common_data.basic_domain->get_domain_element(253)) !=
                                    FieldType::value_type::zero()) {
                                }
                            }
                        }
                    }

                    void generate_evaluation_points() {
                        PROFILE_PLACEHOLDER_SCOPE("evaluation_points_generated_time");
                        _omega = preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

                        const std::size_t witness_columns = table_description.witness_columns;
                        const std::size_t public_input_columns = table_description.public_input_columns;
                        const std::size_t constant_columns = table_description.constant_columns;

                        // variable_values' rotations
                        for (std::size_t variable_values_index = 0;
                             variable_values_index < witness_columns + public_input_columns;
                             variable_values_index++
                        ) {
                            const std::set<int>& variable_values_rotation =
                                preprocessed_public_data.common_data.columns_rotations[variable_values_index];

                            for (int rotation: variable_values_rotation) {
                                _commitment_scheme.append_eval_point(
                                    VARIABLE_VALUES_BATCH,
                                    variable_values_index,
                                    _proof.eval_proof.challenge * _omega.pow(rotation)
                                );
                            }
                        }

                        _commitment_scheme.append_eval_point(PERMUTATION_BATCH, _proof.eval_proof.challenge);
                        _commitment_scheme.append_eval_point(PERMUTATION_BATCH, _proof.eval_proof.challenge * _omega);

                        if(_is_lookup_enabled){
                            _commitment_scheme.append_eval_point(LOOKUP_BATCH, _proof.eval_proof.challenge);
                            _commitment_scheme.append_eval_point(LOOKUP_BATCH, _proof.eval_proof.challenge * _omega);
                            _commitment_scheme.append_eval_point(LOOKUP_BATCH, _proof.eval_proof.challenge *
                                _omega.pow(preprocessed_public_data.common_data.usable_rows_amount));
                        }

                        _commitment_scheme.append_eval_point(QUOTIENT_BATCH, _proof.eval_proof.challenge);


                        // fixed values' rotations (table columns)
                        std::size_t i = 0;
                        std::size_t start_index = preprocessed_public_data.identity_polynomials.size() +
                            preprocessed_public_data.permutation_polynomials.size() + 2;

                        for( i = 0; i < start_index; i++){
                            _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, i, _proof.eval_proof.challenge);
                        }

                        // For special selectors
                        _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, start_index - 2, _proof.eval_proof.challenge * _omega);
                        _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, start_index - 1, _proof.eval_proof.challenge * _omega);

                        for (std::size_t ind = 0;
                            ind < constant_columns + preprocessed_public_data.public_polynomial_table.selectors().size();
                            ind++, i++
                        ) {
                            const std::set<int>& fixed_values_rotation =
                                preprocessed_public_data.common_data.columns_rotations[witness_columns + public_input_columns + ind];

                            for (int rotation: fixed_values_rotation) {
                                _commitment_scheme.append_eval_point(
                                    FIXED_VALUES_BATCH,
                                    start_index + ind,
                                    _proof.eval_proof.challenge * _omega.pow(rotation)
                                );
                            }
                        }
                    }

                    std::vector<std::vector<typename FieldType::value_type>> compute_evaluation_points_public() {
                        std::vector<std::vector<typename FieldType::value_type>> evaluation_points_public(
                            preprocessed_public_data.identity_polynomials.size() +
                            preprocessed_public_data.permutation_polynomials.size(),
                            _challenge_point);

                        const std::size_t witness_columns = table_description.witness_columns;
                        const std::size_t public_input_columns = table_description.public_input_columns;
                        const std::size_t constant_columns = table_description.constant_columns;

                        for (std::size_t k = 0, rotation_index = witness_columns + public_input_columns;
                                k < constant_columns; k++, rotation_index++) {

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

                        for (std::size_t k = 0, rotation_index = witness_columns + public_input_columns + constant_columns;
                                k < preprocessed_public_data.public_polynomial_table.selectors().size();
                                k++, rotation_index++) {

                            const std::set<int>& rotations =
                                preprocessed_public_data.common_data.columns_rotations[rotation_index];
                            std::vector<typename FieldType::value_type> point;
                            point.reserve(rotations.size());

                            for (int rotation: rotations) {
                                point.push_back( _proof.eval_proof.challenge * _omega.pow(rotation));
                            }
                            evaluation_points_public.push_back(std::move(point));
                        }

                        evaluation_points_public.push_back(_challenge_point);

                        return evaluation_points_public;
                    }

                private:
                    // Structures passed from outside by reference.
                    const typename public_preprocessor_type::preprocessed_data_type &preprocessed_public_data;
                    const plonk_table_description<FieldType> &table_description;
                    const plonk_constraint_system<FieldType> &constraint_system;

                    // Members created during proof generation.
                    std::unique_ptr<plonk_polynomial_dfs_table<FieldType>> _polynomial_table;
                    placeholder_proof<FieldType, ParamsType> _proof;
                    std::array<polynomial_dfs_type, f_parts> _F_dfs;
                    transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript;
                    bool _is_lookup_enabled;
                    typename FieldType::value_type _omega;
                    std::vector<typename FieldType::value_type> _challenge_point;
                    commitment_scheme_type _commitment_scheme;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PROVER_HPP
