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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_VERIFIER_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_VERIFIER_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/gates_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename ParamsType>
                class placeholder_verifier {
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;
                    using public_preprocessor_type = placeholder_public_preprocessor<FieldType, ParamsType>;

                    using commitment_scheme_type = typename ParamsType::commitment_scheme_type;
                    using commitment_type = typename commitment_scheme_type::commitment_type;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t lookup_parts = 4;
                    constexpr static const std::size_t f_parts = 8;

                public:
                    static void generate_evaluation_points(
                        commitment_scheme_type &_commitment_scheme,
                        const typename public_preprocessor_type::preprocessed_data_type::common_data_type &common_data,
                        const plonk_constraint_system<FieldType> &constraint_system,
                        const plonk_table_description<FieldType> &table_description,
                        typename FieldType::value_type challenge,
                        bool _is_lookup_enabled
                    ) {
                        PROFILE_PLACEHOLDER_SCOPE("evaluation_points_generated_time");

                        const std::size_t witness_columns = table_description.witness_columns;
                        const std::size_t public_input_columns = table_description.public_input_columns;
                        const std::size_t constant_columns = table_description.constant_columns;
                        const std::size_t selector_columns = table_description.selector_columns;

                        auto _omega = common_data.basic_domain->get_domain_element(1);

                        // variable_values' rotations
                        for (std::size_t variable_values_index = 0;
                             variable_values_index < witness_columns + public_input_columns;
                             variable_values_index++
                        ) {
                            const std::set<int>& variable_values_rotation =
                                common_data.columns_rotations[variable_values_index];

                            for (int rotation: variable_values_rotation) {
                                _commitment_scheme.append_eval_point(
                                    VARIABLE_VALUES_BATCH,
                                    variable_values_index,
                                    challenge * _omega.pow(rotation)
                                );
                            }
                        }

                        if( _is_lookup_enabled || constraint_system.copy_constraints().size() > 0){
                            _commitment_scheme.append_eval_point(PERMUTATION_BATCH, challenge);
                        }

                        if( constraint_system.copy_constraints().size() > 0 )
                            _commitment_scheme.append_eval_point(PERMUTATION_BATCH, 0 , challenge * _omega);

                        if (_is_lookup_enabled) {
                            _commitment_scheme.append_eval_point(PERMUTATION_BATCH, common_data.permutation_parts , challenge * _omega);
                            _commitment_scheme.append_eval_point(LOOKUP_BATCH, challenge);
                            _commitment_scheme.append_eval_point(LOOKUP_BATCH, challenge * _omega);
                            _commitment_scheme.append_eval_point(LOOKUP_BATCH, challenge * _omega.pow(common_data.desc.usable_rows_amount));
                        }

                        _commitment_scheme.append_eval_point(QUOTIENT_BATCH, challenge);


                        // fixed values' rotations (table columns)
                        std::size_t i = 0;
                        std::size_t start_index = common_data.permuted_columns.size() * 2 + 2;

                        for( i = 0; i < start_index; i++){
                            _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, i, challenge);
                        }

                        // for special selectors
                        _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, start_index - 2, challenge * _omega);
                        _commitment_scheme.append_eval_point(FIXED_VALUES_BATCH, start_index - 1, challenge * _omega);

                        for (std::size_t ind = 0;
                            ind < constant_columns + selector_columns;
                            ind++, i++
                        ) {
                            const std::set<int>& fixed_values_rotation =
                                common_data.columns_rotations[witness_columns + public_input_columns + ind];

                            for (int rotation: fixed_values_rotation) {
                                _commitment_scheme.append_eval_point(
                                    FIXED_VALUES_BATCH,
                                    start_index + ind,
                                    challenge * _omega.pow(rotation)
                                );
                            }
                        }
                    }

                    static inline bool process(
                        const typename public_preprocessor_type::preprocessed_data_type::common_data_type &common_data,
                        const placeholder_proof<FieldType, ParamsType> &proof,
                        const plonk_table_description<FieldType> &table_description,
                        const plonk_constraint_system<FieldType> &constraint_system,
                        commitment_scheme_type commitment_scheme,
                        const std::vector<std::vector<typename FieldType::value_type>> &public_input
                    ){
                        // TODO: process rotations for public input.
                        auto omega = common_data.basic_domain->get_domain_element(1);
                        auto challenge = proof.eval_proof.challenge;
                        auto numerator = challenge.pow(table_description.rows_amount) - FieldType::value_type::one();
                        numerator /= typename FieldType::value_type(table_description.rows_amount);

                        // If public input sizes are set, all of them should be set.
                        if(constraint_system.public_input_sizes_num() != 0 && constraint_system.public_input_sizes_num() != table_description.public_input_columns){
                            return false;
                        }

                        for( std::size_t i = 0; i < public_input.size(); ++i ){
                            typename FieldType::value_type value = FieldType::value_type::zero();
                            std::size_t max_size = public_input[i].size();
                            if (constraint_system.public_input_sizes_num() != 0)
                                max_size = std::min(max_size, constraint_system.public_input_size(i));
                            auto omega_pow = FieldType::value_type::one();
                            for( std::size_t j = 0; j < max_size; ++j ){
                                value += (public_input[i][j] * omega_pow) / (challenge - omega_pow);
                                omega_pow = omega_pow * omega;
                            }
                            value *= numerator;
                            if( value != proof.eval_proof.eval_proof.z.get(VARIABLE_VALUES_BATCH, table_description.witness_columns + i, 0) )
                            {
                                return false;
                            }
                        }
                        return process(common_data, proof, table_description, constraint_system, commitment_scheme);
                    }

                    static inline bool process(
                        const typename public_preprocessor_type::preprocessed_data_type::common_data_type &common_data,
                        const placeholder_proof<FieldType, ParamsType> &proof,
                        const plonk_table_description<FieldType> &table_description,
                        const plonk_constraint_system<FieldType> &constraint_system,
                        commitment_scheme_type commitment_scheme
                    ) {
                        const std::size_t witness_columns = table_description.witness_columns;
                        const std::size_t public_input_columns = table_description.public_input_columns;
                        const std::size_t constant_columns = table_description.constant_columns;
                        const std::size_t selector_columns = table_description.selector_columns;

                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(std::vector<std::uint8_t>({}));

                        transcript(common_data.vk.constraint_system_with_params_hash);
                        transcript(common_data.vk.fixed_values_commitment);

                        // Setup commitment scheme. LPC adds an additional point here.
                        commitment_scheme.setup(transcript, common_data.commitment_scheme_data);

                        // 3. append witness commitments to transcript
                        transcript(proof.commitments.at(VARIABLE_VALUES_BATCH));

                        std::vector<typename FieldType::value_type> special_selector_values(3);
                        special_selector_values[0] = common_data.lagrange_0.evaluate(proof.eval_proof.challenge);
                        special_selector_values[1] = proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, 2*common_data.permuted_columns.size(), 0);
                        special_selector_values[2] = proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, 2*common_data.permuted_columns.size() + 1, 0);

                        // 4. prepare evaluaitons of the polynomials that are copy-constrained
                        std::array<typename FieldType::value_type, f_parts> F;
                        std::size_t permutation_size = (proof.eval_proof.eval_proof.z.get_batch_size(FIXED_VALUES_BATCH) - 2 - constant_columns - selector_columns) / 2;
                        if( constraint_system.copy_constraints().size() > 0 ){
                            // Permutation polys
                            std::vector<std::size_t> permuted_polys_global_indices = common_data.permuted_columns;
                            std::vector<typename FieldType::value_type> f(permutation_size);
                            std::vector<typename FieldType::value_type> S_id;
                            std::vector<typename FieldType::value_type> S_sigma;

                            for (std::size_t perm_i = 0; perm_i < permutation_size; perm_i++) {
                                S_id.push_back(proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, perm_i, 0));
                                S_sigma.push_back(proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, permutation_size + perm_i, 0));

                                std::size_t i = permuted_polys_global_indices[perm_i];
                                std::size_t zero_index = 0;
                                for (int v: common_data.columns_rotations[i]) {
                                    if (v == 0){
                                        break;
                                    }
                                    zero_index++;
                                }
                                if (i < witness_columns + public_input_columns) {
                                    f[perm_i] = proof.eval_proof.eval_proof.z.get(VARIABLE_VALUES_BATCH,i,zero_index);
                                } else if (i >= witness_columns + public_input_columns ) {
                                    std::size_t idx = i - witness_columns - public_input_columns + permutation_size*2 + 2;
                                    f[perm_i] = proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH,idx,zero_index);
                                }
                            }

                            // 5. permutation argument
                            std::vector<typename FieldType::value_type> perm_partitions;
                            for( std::size_t i = 1; i < common_data.permutation_parts; i++ ){
                                perm_partitions.push_back(proof.eval_proof.eval_proof.z.get(PERMUTATION_BATCH, i, 0));
                            }
                            std::array<typename FieldType::value_type, permutation_parts> permutation_argument =
                                placeholder_permutation_argument<FieldType, ParamsType>::verify_eval(
                                    common_data,
                                    S_id, S_sigma, special_selector_values,
                                    proof.eval_proof.challenge, f,
                                    proof.eval_proof.eval_proof.z.get(PERMUTATION_BATCH, 0, 0),
                                    proof.eval_proof.eval_proof.z.get(PERMUTATION_BATCH, 0, 1),
                                    perm_partitions,
                                    transcript
                                );
                            F[0] = permutation_argument[0];
                            F[1] = permutation_argument[1];
                            F[2] = permutation_argument[2];
                        }

                        typename policy_type::evaluation_map columns_at_y;
                        for (std::size_t i = 0; i < witness_columns; i++) {
                            std::size_t i_global_index = i;
                            std::size_t j = 0;
                            for (int rotation: common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<typename FieldType::value_type>::column_type::witness);
                                columns_at_y[key] = proof.eval_proof.eval_proof.z.get(VARIABLE_VALUES_BATCH, i, j);
                                ++j;
                            }
                        }

                        for (std::size_t i = 0; i < public_input_columns; i++) {
                            std::size_t i_global_index = witness_columns + i;

                            std::size_t j = 0;
                            for (int rotation: common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<typename FieldType::value_type>::column_type::public_input);
                                columns_at_y[key] = proof.eval_proof.eval_proof.z.get(VARIABLE_VALUES_BATCH, witness_columns + i, j);
                                ++j;
                            }
                        }

                        for (std::size_t i = 0; i < 0 + constant_columns; i++) {
                            std::size_t i_global_index = witness_columns + public_input_columns + i;
                            std::size_t j = 0;
                            for (int rotation: common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<typename FieldType::value_type>::column_type::constant);
                                columns_at_y[key] = proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, i + permutation_size*2 + 2, j);
                                ++j;
                            }
                        }

                        for (std::size_t i = 0; i < selector_columns; i++) {
                            std::size_t i_global_index = witness_columns + constant_columns + public_input_columns + i;
                            std::size_t j = 0;
                            for (int rotation: common_data.columns_rotations[i_global_index]) {
                                auto key = std::make_tuple(
                                    i,
                                    rotation,
                                    plonk_variable<typename FieldType::value_type>::column_type::selector);
                                columns_at_y[key] = proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, i + permutation_size*2 + 2 + constant_columns, j);
                                ++j;
                            }
                        }

                        // 6. lookup argument
                        bool is_lookup_enabled = (constraint_system.lookup_gates().size() > 0);
                        std::array<typename FieldType::value_type, lookup_parts> lookup_argument;
                        if (is_lookup_enabled) {
                            std::vector<typename FieldType::value_type> special_selector_values_shifted(2);
                            special_selector_values_shifted[0] = proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, 2*common_data.permuted_columns.size(), 1);
                            special_selector_values_shifted[1] = proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, 2*common_data.permuted_columns.size() + 1, 1);

                            std::vector<typename FieldType::value_type> lookup_parts_values;
                            for( std::size_t i = common_data.permutation_parts + 1;
                                i < common_data.permutation_parts + common_data.lookup_parts;
                                i++
                            ) lookup_parts_values.push_back(proof.eval_proof.eval_proof.z.get(PERMUTATION_BATCH, i, 0));

                            placeholder_lookup_argument_verifier<FieldType, commitment_scheme_type, ParamsType> lookup_argument_verifier;
                            lookup_argument = lookup_argument_verifier.verify_eval(
                                common_data,
                                special_selector_values, special_selector_values_shifted,
                                constraint_system,
                                proof.eval_proof.challenge, columns_at_y,
                                proof.eval_proof.eval_proof.z.get(LOOKUP_BATCH),
                                proof.eval_proof.eval_proof.z.get(PERMUTATION_BATCH, common_data.permutation_parts),
                                lookup_parts_values,
                                proof.commitments.at(LOOKUP_BATCH), transcript
                            );
                        }
                        if( constraint_system.copy_constraints().size() > 0 || constraint_system.lookup_gates().size() > 0){
                            transcript(proof.commitments.at(PERMUTATION_BATCH));
                        }

                        // 7. gate argument
                        std::array<typename FieldType::value_type, 1> gate_argument =
                        placeholder_gates_argument<FieldType, ParamsType>::verify_eval(
                            constraint_system.gates(), columns_at_y, proof.eval_proof.challenge,
                            FieldType::value_type::one() -
                            proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, common_data.permuted_columns.size() * 2, 0) -
                            proof.eval_proof.eval_proof.z.get(FIXED_VALUES_BATCH, common_data.permuted_columns.size() * 2 + 1, 0),
                            transcript
                        );

                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();

                        // 9. Evaluation proof check
                        transcript(proof.commitments.at(QUOTIENT_BATCH));

                        auto challenge = transcript.template challenge<FieldType>();
                        BOOST_ASSERT(challenge == proof.eval_proof.challenge);

                        commitment_scheme.set_batch_size(VARIABLE_VALUES_BATCH, proof.eval_proof.eval_proof.z.get_batch_size(VARIABLE_VALUES_BATCH));
                        if( is_lookup_enabled || constraint_system.copy_constraints().size())
                            commitment_scheme.set_batch_size(PERMUTATION_BATCH, proof.eval_proof.eval_proof.z.get_batch_size(PERMUTATION_BATCH));
                        commitment_scheme.set_batch_size(QUOTIENT_BATCH, proof.eval_proof.eval_proof.z.get_batch_size(QUOTIENT_BATCH));
                        if (is_lookup_enabled)
                            commitment_scheme.set_batch_size(LOOKUP_BATCH, proof.eval_proof.eval_proof.z.get_batch_size(LOOKUP_BATCH));
                        generate_evaluation_points(commitment_scheme, common_data, constraint_system,
                                                   table_description, challenge, is_lookup_enabled);

                        std::map<std::size_t, typename commitment_scheme_type::commitment_type> commitments = proof.commitments;
                        commitments[FIXED_VALUES_BATCH] = common_data.commitments.fixed_values;
                        if (!commitment_scheme.verify_eval( proof.eval_proof.eval_proof, commitments, transcript )) {
                            return false;
                        }

                        // 10. final check
                        F[3] = lookup_argument[0];
                        F[4] = lookup_argument[1];
                        F[5] = lookup_argument[2];
                        F[6] = lookup_argument[3];
                        F[7] = gate_argument[0];

                        typename FieldType::value_type F_consolidated = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < f_parts; i++) {
                            F_consolidated += alphas[i] * F[i];
                        }

                        typename FieldType::value_type T_consolidated = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < proof.eval_proof.eval_proof.z.get_batch_size(QUOTIENT_BATCH); i++) {
                            T_consolidated += proof.eval_proof.eval_proof.z.get(QUOTIENT_BATCH, i, 0) *
                                challenge.pow((common_data.desc.rows_amount) * i);
                        }

                        // Z is polynomial -1, 0 ...., 0, 1
                        typename FieldType::value_type Z_at_challenge = common_data.Z.evaluate(challenge);
                        if (F_consolidated != Z_at_challenge * T_consolidated) {
                            return false;
                        }
                        return true;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_VERIFIER_HPP
