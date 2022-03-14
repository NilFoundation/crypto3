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
#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>
#include "nil/crypto3/zk/snark/systems/plonk/redshift/detail/redshift_policy.hpp"
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ParamsType>
                class redshift_verifier {

                    constexpr static const std::size_t witness_columns = ParamsType::witness_columns;
                    constexpr static const std::size_t public_columns = ParamsType::public_columns;
                    using merkle_hash_type = typename ParamsType::commitment_params_type::merkle_hash_type;
                    using transcript_hash_type = typename ParamsType::commitment_params_type::transcript_hash_type;

                    using policy_type = detail::redshift_policy<FieldType, ParamsType>;

                    constexpr static const std::size_t lambda = ParamsType::commitment_params_type::lambda;
                    constexpr static const std::size_t r = ParamsType::commitment_params_type::r;
                    constexpr static const std::size_t m = ParamsType::commitment_params_type::m;

                    constexpr static const std::size_t opening_points_witness = 1;
                    constexpr static const std::size_t opening_points_v_p = 2;
                    constexpr static const std::size_t opening_points_t = 1;
                    constexpr static const std::size_t opening_points_public = 1;

                    typedef commitments::list_polynomial_commitment<FieldType,
                                                              typename ParamsType::commitment_params_type,
                                                              opening_points_witness>
                        commitment_scheme_witness_type;
                    typedef commitments::list_polynomial_commitment<FieldType,
                                                              typename ParamsType::commitment_params_type,
                                                              opening_points_v_p>
                        commitment_scheme_permutation_type;
                    typedef commitments::list_polynomial_commitment<FieldType,
                                                              typename ParamsType::commitment_params_type,
                                                              opening_points_t>
                        commitment_scheme_quotient_type;

                    typedef commitments::list_polynomial_commitment<FieldType,
                                                              typename ParamsType::commitment_params_type,
                                                              opening_points_public>
                        commitment_scheme_public_input_type;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t f_parts = 4;

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
                            if (i < witness_columns_amount) {
                                f[i] = proof.eval_proof.witness[i].z[0]; // TODO: organize permutation evaluations inside the proof
                            } else if (i < witness_columns_amount + proof.eval_proof.public_input.size()) {
                                f[i] = proof.eval_proof.public_input[i - witness_columns_amount].z[0];
                            } else {
                                std::size_t idx = i - witness_columns_amount - proof.eval_proof.public_input.size();
                                f[i] = proof.eval_proof.constant[idx].z[0];
                            }
                        }

                        // 5. permutation argument
                        std::array<typename FieldType::value_type, permutation_parts> permutation_argument =
                            redshift_permutation_argument<FieldType,
                                    commitment_scheme_public_input_type,
                                    commitment_scheme_permutation_type,
                                    ParamsType>::verify_eval(preprocessed_public_data, 
                                        proof.eval_proof.challenge,
                                        f, proof.eval_proof.permutation[0].z[0],
                                        proof.eval_proof.permutation[0].z[1],
                                        proof.v_perm_commitment,
                                        transcript);

                        // 7. gate argument
                        typename policy_type::evaluation_map columns_at_y;
                        for (std::size_t i = 0; i < proof.eval_proof.witness.size(); i++) {
                            auto key = std::make_tuple(i, plonk_variable<FieldType>::rotation_type::current,
                                                    plonk_variable<FieldType>::column_type::witness);
                            columns_at_y[key] =  proof.eval_proof.witness[i].z[0];
                        }

                        std::array<typename FieldType::value_type, 1> gate_argument =
                            redshift_gates_argument<FieldType, ParamsType>::verify_eval(constraint_system.gates(),
                                preprocessed_public_data.public_polynomial_table,
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
                            std::vector<std::size_t> rotation_gates = {0};    // TODO: Rotation
                            std::array<typename FieldType::value_type, 1>
                                evaluation_points_gates;    // TODO: array size with rotation
                            for (std::size_t i = 0; i < evaluation_points_gates.size(); i++) {
                                evaluation_points_gates[i] = challenge * omega.pow(rotation_gates[i]);
                            }
                            if (!commitment_scheme_witness_type::verify_eval(evaluation_points_gates,
                                    proof.eval_proof.witness[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
                        }

                        // permutation
                        std::array<typename FieldType::value_type, 2> evaluation_points_permutation = {challenge,
                                                                                               challenge * omega};
                        for (std::size_t i = 0; i < proof.eval_proof.permutation.size(); i++) {
                            if (!commitment_scheme_permutation_type::verify_eval(evaluation_points_permutation, 
                                    proof.eval_proof.permutation[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
                        }

                        // quotient
                        std::array<typename FieldType::value_type, 1> evaluation_points_quotient = {challenge};
                        for (std::size_t i = 0; i < proof.eval_proof.quotient.size(); i++) {
                            if (!commitment_scheme_quotient_type::verify_eval(evaluation_points_quotient,
                                    proof.eval_proof.quotient[i],
                                    fri_params,
                                    transcript)) {
                                return false;
                            }
                        }

                        // public data
                        std::array<typename FieldType::value_type, 1> evaluation_points_public = {challenge};
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
                        F[3] = gate_argument[0];
                        
                        typename FieldType::value_type F_consolidated = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < f_parts; i++) {
                            F_consolidated = F_consolidated + alphas[i] * F[i];
                        }

                        typename FieldType::value_type T_consolidated = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < proof.eval_proof.quotient.size(); i++) {
                            T_consolidated = T_consolidated + proof.eval_proof.quotient[i].z[0] * challenge.pow((fri_params.max_degree + 1) * i);
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
