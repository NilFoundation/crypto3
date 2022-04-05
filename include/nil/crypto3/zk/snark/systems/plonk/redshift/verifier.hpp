//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/detail/redshift_policy.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ParamsType>
                class redshift_verifier {

                    constexpr static const std::size_t witness_columns = ParamsType::witness_columns;
                    constexpr static const std::size_t public_input_columns = ParamsType::public_input_columns;
                    constexpr static const std::size_t constant_columns = ParamsType::constant_columns;
                    constexpr static const std::size_t selector_columns = ParamsType::selector_columns;

                    using merkle_hash_type = typename ParamsType::commitment_params_type::merkle_hash_type;
                    using transcript_hash_type = typename ParamsType::commitment_params_type::transcript_hash_type;

                    using policy_type = detail::redshift_policy<FieldType, ParamsType>;

                    constexpr static const std::size_t lambda = ParamsType::commitment_params_type::lambda;
                    constexpr static const std::size_t r = ParamsType::commitment_params_type::r;
                    constexpr static const std::size_t m = ParamsType::commitment_params_type::m;

                    typedef commitments::list_polynomial_commitment<
                        FieldType, typename ParamsType::commitment_params_type>
                        commitment_scheme_witness_type;
                    typedef commitments::list_polynomial_commitment<
                        FieldType, typename ParamsType::commitment_params_type>
                        commitment_scheme_permutation_type;
                    typedef commitments::list_polynomial_commitment<
                        FieldType, typename ParamsType::commitment_params_type>
                        commitment_scheme_quotient_type;

                    typedef commitments::list_polynomial_commitment<
                        FieldType, typename ParamsType::commitment_params_type>
                        commitment_scheme_public_input_type;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t lookup_parts = 5;
                    constexpr static const std::size_t f_parts = 9;

                public:
                    static inline bool process(const typename policy_type::preprocessed_public_data_type preprocessed_public_data,
                        typename policy_type::template proof_type<commitment_scheme_witness_type,
                                                                        commitment_scheme_permutation_type,
                                                                        commitment_scheme_quotient_type,
                                                                        commitment_scheme_public_input_type> &proof,
                        typename policy_type::constraint_system_type &constraint_system,
                        const typename commitment_scheme_witness_type::params_type
                                    &fri_params) {

                        // 1. Add circuit definition to transcript
                        // transcript(short_description);
                        std::vector<std::uint8_t> transcript_init {};
                        transcript::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(transcript_init);

                        // 3. append witness commitments to transcript
                        for (std::size_t i = 0; i < witness_columns; i++) {
                            transcript(proof.witness_commitments[i]);
                        }

                        // 4. prepare evaluaitons of the polynomials that are copy-constrained
                        std::vector<std::size_t> rotation_gates = {0};
                        std::size_t permutation_size = preprocessed_public_data.common_data.commitments.id_permutation.size();
                        std::vector<typename FieldType::value_type> f(permutation_size);

                        std::size_t witness_columns_amount = proof.eval_proof.witness.size();

                        for (std::size_t i = 0; i < permutation_size; i++) {
                            std::size_t zero_index = 0;
                            for (std::size_t j = 0; j < preprocessed_public_data.common_data.columns_rotations[i].size(); j++) {
                                if (preprocessed_public_data.common_data.columns_rotations[i][j] == 0) {
                                    zero_index = j;
                                }
                            }
                            if (i < witness_columns_amount) {
                                f[i] = proof.eval_proof.witness[i].z[zero_index]; // TODO: organize permutation evaluations inside the proof
                            } else if (i < witness_columns_amount + proof.eval_proof.public_input.size()) {
                                f[i] = proof.eval_proof.public_input[i - witness_columns_amount].z[zero_index];
                            } else {
                                std::size_t idx = i - witness_columns_amount - proof.eval_proof.public_input.size();
                                f[i] = proof.eval_proof.constant[idx].z[zero_index];
                            }
                        }
  
                        // 5. permutation argument
                        std::array<typename FieldType::value_type, permutation_parts> permutation_argument =
                            redshift_permutation_argument<FieldType, commitment_scheme_public_input_type,
                                                          commitment_scheme_permutation_type,
                                                          ParamsType>::verify_eval(preprocessed_public_data,
                                                                                   proof.eval_proof.challenge, f,
                                                                                   proof.eval_proof.permutation[0].z[0],
                                                                                   proof.eval_proof.permutation[0].z[1],
                                                                                   proof.v_perm_commitment, transcript);

                      typename policy_type::evaluation_map columns_at_y;
                        for (std::size_t i = 0; i < witness_columns; i++) {

                            std::size_t i_global_index = i;

                            for (std::size_t j = 0; j <
                                preprocessed_public_data.common_data.columns_rotations[i_global_index].size(); j++) {

                                auto key = std::make_tuple(i,
                                    preprocessed_public_data.common_data.columns_rotations[i_global_index][j],
                                                       plonk_variable<FieldType>::column_type::witness);
                                columns_at_y[key] = proof.eval_proof.witness[i].z[j];
                            }
                        }
                        for (std::size_t i = 0; i < 0 + public_input_columns; i++) {
                            std::size_t i_global_index = witness_columns + i;

                            for (std::size_t j = 0; j <
                                preprocessed_public_data.common_data.columns_rotations[i_global_index].size(); j++) {

                                auto key = std::make_tuple(i,
                                    preprocessed_public_data.common_data.columns_rotations[i_global_index][j],
                                                       plonk_variable<FieldType>::column_type::public_input);
                                std::size_t eval_idx = i - witness_columns;
                                columns_at_y[key] = proof.eval_proof.public_input[i].z[j];
                            }
                        }
                        for (std::size_t i = 0; i < 0 + constant_columns; i++) {
                            std::size_t i_global_index = witness_columns +
                                constant_columns + i;
                            for (std::size_t j = 0; j <
                                preprocessed_public_data.common_data.columns_rotations[i_global_index].size(); j++) {

                                auto key = std::make_tuple(i,
                                    preprocessed_public_data.common_data.columns_rotations[i_global_index][j],
                                                       plonk_variable<FieldType>::column_type::constant);
                                std::size_t eval_idx = i - witness_columns - public_input_columns;
                                columns_at_y[key] = proof.eval_proof.constant[i].z[j];
                            }
                        }
                        for (std::size_t i = 0;
                            i < selector_columns; i++) {

                            std::size_t i_global_index = witness_columns +
                                constant_columns +
                                public_input_columns + i;

                            for (std::size_t j = 0; j <
                                preprocessed_public_data.common_data.columns_rotations[i_global_index].size(); j++) {

                                auto key = std::make_tuple(i,
                                    preprocessed_public_data.common_data.columns_rotations[i_global_index][j],
                                                       plonk_variable<FieldType>::column_type::selector);
                                std::size_t eval_idx = i;
                                columns_at_y[key] = proof.eval_proof.selector[i].z[j];
                            }
                        }
                        //6. lookup argument
                        std::array<typename FieldType::value_type, lookup_parts> lookup_argument =
                        redshift_lookup_argument<FieldType, commitment_scheme_public_input_type,
                                                        ParamsType>::verify_eval(preprocessed_public_data,
                                                                                constraint_system.lookup_gates(),
                                                                                proof.eval_proof.challenge,
                                                                                columns_at_y,
                                                                                proof.eval_proof.lookups[1].z[0],
                                                                                proof.eval_proof.lookups[1].z[1],
                                                                                proof.eval_proof.lookups[2].z[0],
                                                                                proof.eval_proof.lookups[0].z[0],
                                                                                proof.eval_proof.lookups[0].z[1],
                                                                                proof.input_perm_commitment,
                                                                                proof.value_perm_commitment,
                                                                                proof.v_l_perm_commitment, transcript);

                        // 7. gate argument
                        

                        std::array<typename FieldType::value_type, 1> gate_argument =
                            redshift_gates_argument<FieldType, ParamsType>::verify_eval(
                                constraint_system.gates(),
                                columns_at_y,
                                proof.eval_proof.challenge,
                                transcript);

                        // 8. alphas computations
                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();

                        // 9. Evaluation proof check
                        for (std::size_t i = 0; i < proof.T_commitments.size(); i++) {
                            transcript(proof.T_commitments[i]);
                        }

                        typename FieldType::value_type challenge = transcript.template challenge<FieldType>();

                        if (challenge != proof.eval_proof.challenge) {
                            return false;
                        }

                        typename FieldType::value_type omega =
                            preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

                        // witnesses
                        for (std::size_t i = 0; i < proof.eval_proof.witness.size(); i++) {

                            std::vector<int> rotation_gates =
                                preprocessed_public_data.common_data.columns_rotations[i];

                            std::vector<typename FieldType::value_type>
                                evaluation_points_gates;
                            for (std::size_t j = 0; j < rotation_gates.size(); j++) {
                                evaluation_points_gates.push_back(challenge * omega.pow(rotation_gates[j]));
                            }
                            if (!commitment_scheme_witness_type::verify_eval(
                                    evaluation_points_gates, proof.eval_proof.witness[i], fri_params, transcript)) {
                                return false;
                            }
                        }

                        // permutation
                        std::vector<typename FieldType::value_type> evaluation_points_permutation = {
                            challenge, challenge * omega};
                        for (std::size_t i = 0; i < proof.eval_proof.permutation.size(); i++) {
                            if (!commitment_scheme_permutation_type::verify_eval(evaluation_points_permutation,
                                                                                 proof.eval_proof.permutation[i],
                                                                                 fri_params,
                                                                                 transcript)) {
                                return false;
                            }
                        }

                        // lookup
                        std::vector<typename FieldType::value_type> evaluation_points_v_l= {
                            challenge, challenge * omega};
                            if (!commitment_scheme_permutation_type::verify_eval(evaluation_points_v_l,
                                                                                 proof.eval_proof.lookups[0],
                                                                                 fri_params,
                                                                                 transcript)) {
                                return false;
                        }

                        std::vector<typename FieldType::value_type> evaluation_points_input= {
                            challenge, challenge * omega.inversed()};
                            if (!commitment_scheme_permutation_type::verify_eval(evaluation_points_input,
                                                                                 proof.eval_proof.lookups[1],
                                                                                 fri_params,
                                                                                 transcript)) {
                                return false;
                        }

                        std::vector<typename FieldType::value_type> evaluation_points_value= {
                            challenge};
                            if (!commitment_scheme_permutation_type::verify_eval(evaluation_points_value,
                                                                                 proof.eval_proof.lookups[2],
                                                                                 fri_params,
                                                                                 transcript)) {
                                return false;
                        }

                        // quotient
                        std::vector<typename FieldType::value_type> evaluation_points_quotient = {challenge};
                        for (std::size_t i = 0; i < proof.eval_proof.quotient.size(); i++) {
                            if (!commitment_scheme_quotient_type::verify_eval(evaluation_points_quotient,
                                    proof.eval_proof.quotient[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
                        }

                        // public data
                        std::vector<typename FieldType::value_type> evaluation_points_public = {challenge};
                        for (std::size_t i = 0; i < proof.eval_proof.id_permutation.size(); i++) {
                            if (!commitment_scheme_public_input_type::verify_eval(evaluation_points_public,
                                    proof.eval_proof.id_permutation[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
                        }
                        for (std::size_t i = 0; i < proof.eval_proof.sigma_permutation.size(); i++) {
                            if (!commitment_scheme_public_input_type::verify_eval(evaluation_points_public,
                                    proof.eval_proof.sigma_permutation[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
                        }
                        for (std::size_t i = 0; i < proof.eval_proof.public_input.size(); i++) {
                            if (!commitment_scheme_public_input_type::verify_eval(evaluation_points_public,
                                    proof.eval_proof.public_input[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
                        }
                        for (std::size_t i = 0; i < proof.eval_proof.constant.size(); i++) {
                            if (!commitment_scheme_public_input_type::verify_eval(evaluation_points_public,
                                    proof.eval_proof.constant[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
                        }
                        for (std::size_t i = 0; i < proof.eval_proof.selector.size(); i++) {
                            if (!commitment_scheme_public_input_type::verify_eval(evaluation_points_public,
                                    proof.eval_proof.selector[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
                        }
                        for (std::size_t i = 0; i < proof.eval_proof.special_selectors.size(); i++) {
                            if (!commitment_scheme_public_input_type::verify_eval(evaluation_points_public,
                                    proof.eval_proof.special_selectors[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
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
                        for (std::size_t i = 0; i < proof.eval_proof.quotient.size(); i++) {
                            T_consolidated = T_consolidated + proof.eval_proof.quotient[i].z[0] *
                                                                  challenge.pow((fri_params.max_degree + 1) * i);
                        }

                        typename FieldType::value_type Z_at_challenge = preprocessed_public_data.common_data.Z.evaluate(challenge);

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

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP
