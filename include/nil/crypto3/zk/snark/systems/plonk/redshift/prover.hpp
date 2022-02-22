//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/merkle/tree.hpp>

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/types.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/gates_argument.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType,
                         typename MerkleTreeHashType,
                         typename TranscriptHashType,
                         std::size_t witness_columns,
                         std::size_t public_columns,
                         std::size_t lambda,
                         std::size_t k,
                         std::size_t r,
                         std::size_t m = 2>
                class redshift_prover {

                    using types_policy = detail::redshift_types_policy<FieldType, witness_columns, public_columns>;

                    typedef typename containers::merkle_tree<MerkleTreeHashType, 2> merkle_tree_type;

                    typedef list_polynomial_commitment_scheme<FieldType, MerkleTreeHashType, TranscriptHashType, lambda, k, r, m> lpc;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t f_parts = 9;

                    static inline math::polynomial<typename FieldType::value_type> 
                        quotient_polynomial(const typename types_policy::template preprocessed_data_type<witness_columns> preprocessed_data,
                            std::array<math::polynomial<typename FieldType::value_type>, f_parts> F, 
                            fiat_shamir_heuristic_updated<TranscriptHashType> transcript) {
                            // 7.1. Get $\alpha_0, \dots, \alpha_8 \in \mathbb{F}$ from $hash(\text{transcript})$
                            std::array<typename FieldType::value_type, f_parts> alphas =
                                transcript.template challenges<FieldType, f_parts>();

                            // 7.2. Compute F_consolidated
                            math::polynomial<typename FieldType::value_type> F_consolidated = {0};
                            for (std::size_t i = 0; i < f_parts; i++) {
                                F_consolidated = F_consolidated + alphas[i] * F[i];
                            }

                            math::polynomial<typename FieldType::value_type> T_consolidated =
                                F_consolidated / preprocessed_data.Z;

                            return T_consolidated;
                    }

                    /*static inline std::vector<typename lpc::proof_type> 
                        evaluation_proof(typename FieldType::value_type challenge,
                            const typename types_policy::constraint_system_type &constraint_system
                            std::vector<math::polynomial<typename FieldType::value_type>> polynomials,
                            std::vector<merkle_tree_type> witness_commits,
                            const typename lpc::fri_type::params_type &fri_params) {

                            // witness polynomials (table columns)
                            for (std::size_t i = 0; i < witness_commits.size(); i++) {
                                std::vector<std::size_t> rotation_gates = {};
                                std::vector<FieldType::value_type> evaluation_points_gates(rotation_gates.size());
                                for (std::size_t i = 0; i < evaluation_points_gates.size(); i++) {
                                    evaluation_points_gates[i] = y * omega.pow(rotation_gates[i]);
                                }

                                lpc::proof_type proof = lpc::proof_eval(evaluation_points_gates, witness_commits, f, transcript, fri_params);
                            }

                            // permutation polynomials
                            std::vector<FieldType::value_type> evaluation_points_permutation = {y, y * omega};

                            lpc::proof_type proof = lpc::proof_eval(evaluation_points_permutation, tree, f, transcript, fri_params);

                            // quotient polynomial
                            std::vector<std::size_t> rotation_gates = {};
                            std::vector<FieldType::value_type> evaluation_points_quotient = {y};

                            lpc::proof_type proof = lpc::proof_eval(evaluation_points_quotient, tree, f, transcript, fri_params);

                            return proof;
                    }*/

                public:
                    static inline typename types_policy::template proof_type<lpc>
                        process(const typename types_policy::template preprocessed_data_type<witness_columns> preprocessed_data,
                                typename types_policy::constraint_system_type &constraint_system,
                                const typename types_policy::variable_assignment_type &assignments,
                                const typename types_policy::template circuit_short_description<lpc> &short_description,
                                const typename lpc::fri_type::params_type &fri_params) {
                        
                        typename types_policy::template proof_type<lpc> proof;
                        std::vector<std::uint8_t> tanscript_init = {};
                        fiat_shamir_heuristic_updated<TranscriptHashType> transcript(tanscript_init);

                        // 1. Add circuit definition to transctipt
                        //transcript(short_description); //TODO: circuit_short_description marshalling

                        // 2. Commit witness columns
                        std::array<math::polynomial<typename FieldType::value_type>, witness_columns> witness_poly;
                        for (std::size_t i = 0; i < witness_columns; i++) {
                            std::vector<typename FieldType::value_type> tmp;
                            std::copy(assignments[i].begin(), assignments[i].end(), std::back_inserter(tmp));
                            preprocessed_data.basic_domain->inverse_fft(tmp);
                            witness_poly[i] = tmp;
                        }
                        std::array<typename lpc::merkle_tree_type, witness_columns> witness_commitments =
                            lpc::template commit<witness_columns>(witness_poly, fri_params.D[0]);

                        proof.witness_commitments.resize(witness_columns);
                        for (std::size_t i = 0; i < witness_columns; i++) {
                            proof.witness_commitments[i] = witness_commitments[i].root();
                            //transcript(proof.witness_commitments[i]);
                        }

                        // 3. Prepare columns included into permuation argument
                        std::vector<math::polynomial<typename FieldType::value_type>> columns_for_permutation_argument(short_description.columns_with_copy_constraints.size());
                        for (std::size_t i = 0; i < short_description.columns_with_copy_constraints.size(); i++) {
                            std::size_t column_index = short_description.columns_with_copy_constraints[i];
                            if (column_index < witness_columns) { //TODO: for now, we suppose that witnesses are placed to the first witness_columns of the table
                                columns_for_permutation_argument[i] = witness_poly[column_index];
                            } else {
                                std::vector<typename FieldType::value_type> tmp;
                                std::copy(assignments[column_index].begin(), assignments[column_index].end(), std::back_inserter(tmp));
                                preprocessed_data.basic_domain->inverse_fft(tmp);
                                columns_for_permutation_argument[i] = tmp;
                            }
                        }

                        // 4. permutation_argument
                        auto permutation_argument = redshift_permutation_argument<FieldType, lpc, witness_columns, public_columns>::prove_eval(
                                transcript, preprocessed_data, short_description, columns_for_permutation_argument, fri_params);

                        proof.v_perm_commitment = permutation_argument.permutation_poly_commitment.root();

                        std::array<math::polynomial<typename FieldType::value_type>, f_parts> F;

                        F[0] = permutation_argument.F[0];
                        F[1] = permutation_argument.F[1];
                        F[2] = permutation_argument.F[2];

                        // 5. lookup_argument
                        // std::array<math::polynomial<typename FieldType::value_type>, 5>
                        //     lookup_argument = redshift_lookup_argument<FieldType>::prove_eval(transcript);

                        // 6. circuit-satisfability
                        std::vector<math::polynomial<typename FieldType::value_type>> columns_for_gate_argument(witness_columns + public_columns);
                        for (std::size_t i = 0; i < columns_for_gate_argument.size(); i++) {
                            if (i < witness_columns) { //TODO: for now, we suppose that witnesses are placed to the first witness_columns of the table
                                columns_for_gate_argument[i] = witness_poly[i];
                            } else {
                                std::vector<typename FieldType::value_type> tmp;
                                std::copy(assignments[i].begin(), assignments[i].end(), std::back_inserter(tmp));
                                preprocessed_data.basic_domain->inverse_fft(tmp);
                                columns_for_gate_argument[i] = tmp;
                            }
                        }

                        std::array<math::polynomial<typename FieldType::value_type>, gate_parts> prover_res =
                            redshift_gates_argument<FieldType, witness_columns, public_columns, TranscriptHashType>::prove_eval(
                                constraint_system, columns_for_gate_argument, transcript);

                        F[3] = prover_res[0];

                        // 7. Aggregate quotient polynomial
                        math::polynomial<typename FieldType::value_type> T = quotient_polynomial(preprocessed_data, F, transcript);
                        /*std::size_t N_T = short_description.columns_with_copy_constraints.size();// std::max(short_description.columns_with_copy_constraints.size(), GATE_MAX_DEGREE);
                        std::array<math::polynomial<typename FieldType::value_type>, N_T> T_splitted;
                        auto T_commitments = lpc::commit<witness_columns>(T_splitted, fri_params.D[0]);
                        transcript(T_commitments);

                        // 8. Run evaluation proofs
                        //typename FieldType::value_type challenge = transcript.template challenge<FieldType>();
                        //lpc::proof_type lpc_proof_witnesses = evaluation_proof(transcript, omega);

                        // std::array<typename FieldType::value_type, k> fT_evaluation_points = {upsilon};
                        // std::vector<typename lpc::proof_type> f_lpc_proofs(N_wires);

                        // for (std::size_t i = 0; i < N_wires; i++){
                        //     f_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, f_trees[i], f[i], D_0));
                        // }

                        // std::vector<typename lpc::proof_type> T_lpc_proofs(N_perm + 1);

                        // for (std::size_t i = 0; i < N_perm + 1; i++) {
                        //     T_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, T_trees[i], T[i], D_0));
                        // }*/

                            // = typename types_policy::proof_type(std::move(f_commitments), std::move(T_commitments),
                            //                               std::move(f_lpc_proofs), std::move(T_lpc_proofs));
                        // proof.T_lpc_proofs = T_lpc_proofs;
                        // proof.f_lpc_proofs = f_lpc_proofs;
                        // proof.T_commitments = T_commitments;

                        return proof;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP
