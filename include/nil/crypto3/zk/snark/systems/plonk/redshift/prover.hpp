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
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/merkle/tree.hpp>

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/types.hpp>
// #include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType,
                         std::size_t witness_columns,
                         std::size_t lambda,
                         std::size_t k,
                         std::size_t r,
                         std::size_t m = 2>
                class redshift_prover {

                    using types_policy = detail::redshift_types_policy<FieldType, witness_columns>;
                    using transcript_manifest =
                        typename types_policy::template prover_fiat_shamir_heuristic_manifest<8>;

                    typedef hashes::sha2<256> merkle_hash_type;
                    typedef hashes::sha2<256> transcript_hash_type;

                    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

                    typedef list_polynomial_commitment_scheme<FieldType, merkle_hash_type, lambda, k, r, m> lpc;

                    static inline math::polynomial<typename FieldType::value_type> 
                        quotient_polynomial() {
                            // 7.1. Get $\alpha_0, \dots, \alpha_8 \in \mathbb{F}$ from $hash(\text{transcript})$
                            std::array<typename FieldType::value_type, f_parts> alphas =
                                transcript.template challenges<transcript_manifest::challenges_ids::alpha, f_parts, FieldType>();

                            // 7.2. Compute F_consolidated
                            math::polynomial<typename FieldType::value_type> F_consolidated = {0};
                            for (std::size_t i = 0; i < f_parts; i++) {
                                F_consolidated = F_consolidated + alphas[i] * F[i];
                            }

                            math::polynomial<typename FieldType::value_type> T_consolidated =
                                F_consolidated / preprocessed_data.Z;
                    }

                    static inline std::vector<lpc::proof_type> 
                        evaluation_proof(fiat_shamir_heuristic_updated<TranscriptHashType> &transcript,
                            FieldType::value_type omega) {
                            typename FieldType::value_type y = transcript.template challenge<FieldType>(); //TODO: define challenge space

                            // witness polynomials (table columns)
                            std::vector<std::size_t> rotation_gates = {};
                            std::vector<FieldType::value_type> evaluation_points_gates(rotation_gates.size());
                            for (std::size_t i = 0; i < evaluation_points_gates.size(); i++) {
                                evaluation_points_gates[i] = y * omega.pow(rotation_gates[i]);
                            }

                            lpc::proof_type proof = lpc::proof_eval(evaluation_points_gates, tree, f, transcript, fri_params);

                            // permutation polynomials
                            std::vector<FieldType::value_type> evaluation_points_permutation = {y, y * omega};

                            lpc::proof_type proof = lpc::proof_eval(evaluation_points_permutation, tree, f, transcript, fri_params);

                            // quotient polynomial
                            std::vector<std::size_t> rotation_gates = {};
                            std::vector<FieldType::value_type> evaluation_points_quotient = {y};

                            lpc::proof_type proof = lpc::proof_eval(evaluation_points_quotient, tree, f, transcript, fri_params);

                            return proof;
                    }

                public:
                    static inline typename types_policy::template proof_type<lpc>
                        process(const typename types_policy::template preprocessed_data_type<k> preprocessed_data,
                                const typename types_policy::constraint_system_type &constraint_system,
                                const typename types_policy::variable_assignment_type &assignments,
                                const typename types_policy::public_input_type &PI) {

                        std::size_t N_rows = 0; // TODO: It should be in preprocessor
                        for (auto &wire_assignments : assignments) {
                            N_rows = std::max(N_rows, wire_assignments.size());
                        }

                        fiat_shamir_heuristic<transcript_manifest, transcript_hash_type> transcript;
                        // prepare a basic domain of the table size
                        std::shared_ptr<math::evaluation_domain<FieldType>> domain =
                                math::make_evaluation_domain<FieldType>(N_rows);
                        
                        // 1. Add circuit definition to transctipt
                        transcript(...);

                        // 2. Commit witness columns
                        std::array<math::polynomial<typename FieldType::value_type>, witness_columns> witness_poly = ;
                        auto witness_commitments = lpc::commit<witness_columns>(witness_poly, fri_params.D[0]);
                        transcript(witness_commitments);

                        // 3. Prepare columns included into permuation argument
                        std::vector<math::polynomial<typename FieldType::value_type>> f(N_perm + N_PI);
                        std::copy(w.begin(), w.end(), f.begin());

                        // 4. permutation_argument
                        constexpr const std::size_t permutation_parts = 3;
                        std::array<math::polynomial<typename FieldType::value_type>, permutation_parts>
                            permutation_argument = redshift_permutation_argument<FieldType>::prove_eval(transcript);

                        constexpr const std::size_t f_parts = 9;
                        std::array<math::polynomial<typename FieldType::value_type>, f_parts> F;

                        F[0] = permutation_argument[0];
                        F[1] = permutation_argument[1];
                        F[2] = permutation_argument[2];

                        // 5. lookup_argument
                        // std::array<math::polynomial<typename FieldType::value_type>, 5>
                        //     lookup_argument = redshift_lookup_argument<FieldType>::prove_eval(transcript);

                        // 6. circuit-satisfability
                        constexpr const std::size_t gate_parts = 1;
                        std::array<math::polynomial<typename FieldType::value_type>, 1> prover_res =
                            redshift_gates_argument<FieldType, lpc_type>::prove_eval(prover_transcript, circuit_rows,
                                                                                        permutation_size, domain, lagrange_0, S_id,
                                                                                        S_sigma, f, q_last, q_blind, fri_params);

                        F[3] = prover_res[0];

                        // 7. Aggregate quotient polynomial
                        math::polynomial<typename FieldType::value_type> T = quotient_polynomial();
                        std::size_t N_T = std::max(N_perm + N_PI, F[8].degree() - 1);
                        std::array<math::polynomial<typename FieldType::value_type>, N_T> T_splitted = ;
                        auto T_commitments = lpc::commit<witness_columns>(T_splitted, fri_params.D[0]);
                        transcript(T_commitments);    

                        // 8. Run evaluation proofs
                        lpc::proof_type lpc_proof_witnesses = evaluation_proof(transcript, omega);
                        lpc::proof_type lpc_proof_witnesses = evaluation_proof(transcript, omega);       

                        // 8.1 Get $y \in \mathbb{F}/H$ from $hash|_{\mathbb{F}/H}(\text{transcript})$
                        // typename FieldType::value_type upsilon =
                        //     transcript.template challenge<transcript_manifest::challenges_ids::upsilon, FieldType>();

                        // std::array<typename FieldType::value_type, k> fT_evaluation_points = {upsilon};
                        // std::vector<typename lpc::proof_type> f_lpc_proofs(N_wires);

                        // for (std::size_t i = 0; i < N_wires; i++){
                        //     f_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, f_trees[i], f[i], D_0));
                        // }

                        // std::vector<typename lpc::proof_type> T_lpc_proofs(N_perm + 1);

                        // for (std::size_t i = 0; i < N_perm + 1; i++) {
                        //     T_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, T_trees[i], T[i], D_0));
                        // }

                        typename types_policy::template proof_type<lpc> proof;
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
