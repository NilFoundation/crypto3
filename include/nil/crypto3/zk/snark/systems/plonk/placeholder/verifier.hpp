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
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType, typename ParamsType>
                class placeholder_verifier {

                    constexpr static const std::size_t witness_columns = ParamsType::witness_columns;
                    constexpr static const std::size_t public_input_columns = ParamsType::public_input_columns;
                    constexpr static const std::size_t constant_columns = ParamsType::constant_columns;
                    constexpr static const std::size_t selector_columns = ParamsType::selector_columns;

                    using merkle_hash_type = typename ParamsType::merkle_hash_type;
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;

                    using policy_type = detail::placeholder_policy<FieldType, ParamsType>;

                    constexpr static const std::size_t lambda = ParamsType::commitment_params_type::lambda;
                    constexpr static const std::size_t r = ParamsType::commitment_params_type::r;
                    constexpr static const std::size_t m = ParamsType::commitment_params_type::m;

                    using runtime_size_commitment_scheme_type =
                        typename ParamsType::runtime_size_commitment_scheme_type;
                    using witness_commitment_scheme_type =
                        typename ParamsType::witness_commitment_scheme_type;
                    using public_input_commitment_scheme_type =
                        typename ParamsType::public_input_commitment_scheme_type;
                    using constant_commitment_scheme_type =
                        typename ParamsType::constant_commitment_scheme_type;
                    using selector_commitment_scheme_type =
                        typename ParamsType::selector_commitment_scheme_type;
                    using special_commitment_scheme_type =
                        typename ParamsType::special_commitment_scheme_type;
                    using permutation_commitment_scheme_type =
                        typename ParamsType::permutation_commitment_scheme_type;
                    using quotient_commitment_scheme_type =
                        typename ParamsType::quotient_commitment_scheme_type;

                    using public_preprocessor_type = placeholder_public_preprocessor<FieldType, ParamsType>;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t lookup_parts = 5;
                    constexpr static const std::size_t f_parts = 9;

                public:
                    static inline bool
                        process(const typename public_preprocessor_type::preprocessed_data_type preprocessed_public_data,
                                placeholder_proof<FieldType, ParamsType> &proof,
                                plonk_constraint_system<FieldType,
                                    typename ParamsType::arithmetization_params> &constraint_system,
                                const typename ParamsType::commitment_params_type &fri_params) {

                        // 1. Add circuit definition to transcript
                        // transcript(short_description);
                        std::vector<std::uint8_t> transcript_init {};
                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(transcript_init);

                        // 3. append witness commitments to transcript
                        transcript(proof.witness_commitment);

                        // 4. prepare evaluaitons of the polynomials that are copy-constrained
                        std::size_t permutation_size =
                            proof.eval_proof.id_permutation.z.size();
                        std::vector<typename FieldType::value_type> f(permutation_size);

                        for (std::size_t i = 0; i < 
                            permutation_size; i++) {
                            std::size_t zero_index = 0;
                            for (std::size_t j = 0;
                                 j < preprocessed_public_data.common_data.columns_rotations[i].size();
                                 j++) {

                                if (preprocessed_public_data.common_data.columns_rotations[i][j] == 0) {
                                    zero_index = j;
                                }
                            }
                            if (i < witness_columns) {
                                f[i] = proof.eval_proof.witness.z[i][zero_index];
                            } else if (i < witness_columns + public_input_columns) {
                                f[i] = proof.eval_proof.public_input.z[i - witness_columns][zero_index];
                            } else if (i < witness_columns + public_input_columns + constant_columns){
                                std::size_t idx = i - witness_columns - public_input_columns;
                                f[i] = proof.eval_proof.constant.z[idx][zero_index];
                            }
                        }
                        
                        // 5. permutation argument
                        if (preprocessed_public_data.common_data.lagrange_0.evaluate(proof.eval_proof.challenge) !=
                            proof.eval_proof.lagrange_0) {
                            return false;
                        }
                        std::array<typename FieldType::value_type, permutation_parts> permutation_argument =
                            placeholder_permutation_argument<FieldType, ParamsType>::
                                verify_eval(preprocessed_public_data,
                                            proof.eval_proof.challenge, f,
                                            proof.eval_proof.permutation.z[0][0],
                                            proof.eval_proof.permutation.z[0][1],
                                            proof.v_perm_commitment, transcript);

                        
                        typename policy_type::evaluation_map columns_at_y;
                        for (std::size_t i = 0; i < witness_columns; i++) {

                            std::size_t i_global_index = i;

                            for (std::size_t j = 0;
                                 j < preprocessed_public_data.common_data.columns_rotations[i_global_index].size();
                                 j++) {

                                auto key = std::make_tuple(
                                    i,
                                    preprocessed_public_data.common_data.columns_rotations[i_global_index][j],
                                    plonk_variable<FieldType>::column_type::witness);
                                columns_at_y[key] = proof.eval_proof.witness.z[i][j];
                            }
                        }
                        for (std::size_t i = 0; i < 0 + public_input_columns; i++) {
                            std::size_t i_global_index = witness_columns + i;

                            for (std::size_t j = 0;
                                 j < preprocessed_public_data.common_data.columns_rotations[i_global_index].size();
                                 j++) {

                                auto key = std::make_tuple(
                                    i,
                                    preprocessed_public_data.common_data.columns_rotations[i_global_index][j],
                                    plonk_variable<FieldType>::column_type::public_input);
                                columns_at_y[key] = proof.eval_proof.public_input.z[i][j];
                            }
                        }
                        for (std::size_t i = 0; i < 0 + constant_columns; i++) {
                            std::size_t i_global_index = witness_columns + constant_columns + i;
                            for (std::size_t j = 0;
                                 j < preprocessed_public_data.common_data.columns_rotations[i_global_index].size();
                                 j++) {

                                auto key = std::make_tuple(
                                    i,
                                    preprocessed_public_data.common_data.columns_rotations[i_global_index][j],
                                    plonk_variable<FieldType>::column_type::constant);
                                columns_at_y[key] = proof.eval_proof.constant.z[i][j];
                            }
                        }
                        for (std::size_t i = 0; i < selector_columns; i++) {

                            std::size_t i_global_index = witness_columns + constant_columns + public_input_columns + i;

                            for (std::size_t j = 0;
                                 j < preprocessed_public_data.common_data.columns_rotations[i_global_index].size();
                                 j++) {

                                auto key = std::make_tuple(
                                    i,
                                    preprocessed_public_data.common_data.columns_rotations[i_global_index][j],
                                    plonk_variable<FieldType>::column_type::selector);
                                columns_at_y[key] = proof.eval_proof.selector.z[i][j];
                            }
                        }

                        // 6. lookup argument
                        bool use_lookup = constraint_system.lookup_gates().size() > 0;
                        std::array<typename FieldType::value_type, lookup_parts> lookup_argument;
                        if (use_lookup) {
                            lookup_argument =
                                placeholder_lookup_argument<FieldType, public_input_commitment_scheme_type, ParamsType>::
                                    verify_eval(preprocessed_public_data, constraint_system.lookup_gates(),
                                                proof.eval_proof.challenge, columns_at_y,
                                                proof.eval_proof.lookups[1].z[0][0], proof.eval_proof.lookups[1].z[0][1],
                                                proof.eval_proof.lookups[2].z[0][0], proof.eval_proof.lookups[0].z[0][0],
                                                proof.eval_proof.lookups[0].z[0][1], proof.input_perm_commitment,
                                                proof.value_perm_commitment, proof.v_l_perm_commitment, transcript);
                        } else {
                            for (std::size_t i = 0; i < lookup_parts; i++) {
                                lookup_argument[i] = 0;
                            }
                        }

                        // 7. gate argument
                        std::array<typename FieldType::value_type, 1> gate_argument =
                            placeholder_gates_argument<FieldType, ParamsType>::verify_eval(
                                constraint_system.gates(), columns_at_y, proof.eval_proof.challenge, transcript);

                        // 8. alphas computations
                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();

                        // 9. Evaluation proof check
                        transcript(proof.T_commitment);

                        typename FieldType::value_type challenge = transcript.template challenge<FieldType>();

                        if (challenge != proof.eval_proof.challenge) {
                            return false;
                        }

                        typename FieldType::value_type omega =
                            preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

                        std::array<std::vector<typename FieldType::value_type>,
                            witness_columns> witness_evaluation_points;
                        // witnesses
                        for (std::size_t witness_index = 0; witness_index < witness_columns; witness_index++) {

                            std::vector<int> witness_rotation = preprocessed_public_data.common_data.columns_rotations[witness_index];

                            for (int & rotation_index : witness_rotation) {
                                witness_evaluation_points[witness_index].push_back(challenge * omega.pow(rotation_index));
                            }
                        }
                        if (!algorithms::verify_eval<witness_commitment_scheme_type>(
                                witness_evaluation_points, proof.eval_proof.witness, fri_params, transcript)) {
                            return false;
                        }
                        
                        // permutation
                        std::vector<typename FieldType::value_type> evaluation_points_permutation = {challenge,
                                                                                                     challenge * omega};
                        if (!algorithms::verify_eval<permutation_commitment_scheme_type>(evaluation_points_permutation,
                                                                                 proof.eval_proof.permutation,
                                                                                 fri_params,
                                                                                 transcript)) {
                            return false;
                        }

                        // lookup
                        if (use_lookup) {
                            std::vector<typename FieldType::value_type> evaluation_points_v_l = {challenge,
                                                                                                 challenge * omega};
                            if (!algorithms::verify_eval<permutation_commitment_scheme_type>(
                                    evaluation_points_v_l, proof.eval_proof.lookups[0], fri_params, transcript)) {
                                return false;
                            }

                            std::vector<typename FieldType::value_type> evaluation_points_input = {
                                challenge, challenge * omega.inversed()};
                            if (!algorithms::verify_eval<permutation_commitment_scheme_type>(
                                    evaluation_points_input, proof.eval_proof.lookups[1], fri_params, transcript)) {
                                return false;
                            }

                            std::vector<typename FieldType::value_type> evaluation_points_value = {challenge};
                            if (!algorithms::verify_eval<permutation_commitment_scheme_type>(
                                    evaluation_points_value, proof.eval_proof.lookups[2], fri_params, transcript)) {
                                return false;
                            }
                        }

                        // quotient
                        std::vector<typename FieldType::value_type> evaluation_points_quotient = {challenge};
                        if (!algorithms::verify_eval<runtime_size_commitment_scheme_type>(
                                evaluation_points_quotient, proof.eval_proof.quotient, fri_params, transcript)) {
                            return false;
                        }

                        // public data
                        std::vector<typename FieldType::value_type> &evaluation_points_public = evaluation_points_quotient;

                        if (!algorithms::verify_eval<runtime_size_commitment_scheme_type>(
                            evaluation_points_public, proof.eval_proof.id_permutation, fri_params, transcript)) {
                            return false;
                        }

                        if (!algorithms::verify_eval<runtime_size_commitment_scheme_type>(
                            evaluation_points_public, proof.eval_proof.sigma_permutation, fri_params, transcript)) {
                            return false;
                        }
                        
                        if (!algorithms::verify_eval<public_input_commitment_scheme_type>(
                                evaluation_points_public, proof.eval_proof.public_input, fri_params, transcript)) {
                            return false;
                        }

                        if (!algorithms::verify_eval<constant_commitment_scheme_type>(
                                evaluation_points_public, proof.eval_proof.constant, fri_params, transcript)) {
                            return false;
                        }
                        
                        if (!algorithms::verify_eval<selector_commitment_scheme_type>(
                                evaluation_points_public, proof.eval_proof.selector, fri_params, transcript)) {
                            return false;
                        }
                        
                        if (!algorithms::verify_eval<special_commitment_scheme_type>(
                                evaluation_points_public, proof.eval_proof.special_selectors, fri_params, transcript)) {
                            return false;
                        }

                        // 10. final check
                        std::array<typename FieldType::value_type, f_parts> F;
                        F[0] = permutation_argument[0];
                        F[1] = permutation_argument[1];
                        F[2] = permutation_argument[2];
                        F[3] = lookup_argument[0];
                        F[4] = lookup_argument[1];
                        F[5] = lookup_argument[2];
                        F[6] = lookup_argument[3];
                        F[7] = lookup_argument[4];
                        F[8] = gate_argument[0];

                        typename FieldType::value_type F_consolidated = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < f_parts; i++) {
                            F_consolidated = F_consolidated + alphas[i] * F[i];
                        }

                        typename FieldType::value_type T_consolidated = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < proof.eval_proof.quotient.z.size(); i++) {
                            T_consolidated = T_consolidated + proof.eval_proof.quotient.z[i][0] *
                                                                  challenge.pow((fri_params.max_degree + 1) * i);
                        }

                        typename FieldType::value_type Z_at_challenge =
                            preprocessed_public_data.common_data.Z.evaluate(challenge);

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
