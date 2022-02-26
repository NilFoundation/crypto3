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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

#include <nil/crypto3/zk/snark/commitments/lpc.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include "nil/crypto3/zk/snark/systems/plonk/redshift/detail/redshift_policy.hpp"
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/gates_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ParamsType>
                class redshift_prover {

                    constexpr static const std::size_t witness_columns = ParamsType::witness_columns;
                    constexpr static const std::size_t public_columns = ParamsType::public_columns;
                    using merkle_hash_type = typename ParamsType::commitment_params_type::merkle_hash_type;
                    using transcript_hash_type = typename ParamsType::commitment_params_type::transcript_hash_type;

                    using policy_type = detail::redshift_policy<FieldType, ParamsType>;

                    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

                    constexpr static const std::size_t lambda = ParamsType::commitment_params_type::lambda;
                    constexpr static const std::size_t r = ParamsType::commitment_params_type::r;
                    constexpr static const std::size_t m = ParamsType::commitment_params_type::m;

                    constexpr static const std::size_t opening_points_witness = 1;
                    constexpr static const std::size_t opening_points_v_p = 2;
                    constexpr static const std::size_t opening_points_t = 1;
                    constexpr static const std::size_t opening_points_public = 1;

                    typedef list_polynomial_commitment_scheme<FieldType,
                                                              typename ParamsType::commitment_params_type,
                                                              opening_points_witness>
                        commitment_scheme_witness_type;
                    typedef list_polynomial_commitment_scheme<FieldType,
                                                              typename ParamsType::commitment_params_type,
                                                              opening_points_v_p>
                        commitment_scheme_permutation_type;
                    typedef list_polynomial_commitment_scheme<FieldType,
                                                              typename ParamsType::commitment_params_type,
                                                              opening_points_t>
                        commitment_scheme_quotient_type;
                    typedef list_polynomial_commitment_scheme<FieldType,
                                                              typename ParamsType::commitment_params_type,
                                                              opening_points_public>
                        commitment_scheme_public_points_type;

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t f_parts = 9;

                    static inline math::polynomial<typename FieldType::value_type> quotient_polynomial(
                        const typename policy_type::preprocessed_public_data_type preprocessed_public_data,
                        std::array<math::polynomial<typename FieldType::value_type>, f_parts>
                            F,
                        fiat_shamir_heuristic_sequential<transcript_hash_type>
                            transcript) {
                        // 7.1. Get $\alpha_0, \dots, \alpha_8 \in \mathbb{F}$ from $hash(\text{transcript})$
                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<FieldType, f_parts>();

                        // 7.2. Compute F_consolidated
                        math::polynomial<typename FieldType::value_type> F_consolidated = {0};
                        for (std::size_t i = 0; i < f_parts; i++) {
                            F_consolidated = F_consolidated + alphas[i] * F[i];
                        }

                        math::polynomial<typename FieldType::value_type> T_consolidated =
                            F_consolidated / preprocessed_public_data.Z;

                        return T_consolidated;
                    }

                    static inline std::vector<math::polynomial<typename FieldType::value_type>>
                        split_polynomial(math::polynomial<typename FieldType::value_type> f, std::size_t max_degree) {
                        std::size_t parts = ((f.size() - 1) / (max_degree + 1)) + 1;
                        std::vector<math::polynomial<typename FieldType::value_type>> f_splitted(parts);

                        std::size_t chunk_size = max_degree + 1;    // polynomial contains max_degree + 1 coeffs
                        for (std::size_t i = 0; i < parts - 1; i++) {
                            std::copy(f.begin() + i * chunk_size,
                                      f.begin() + (i + 1) * chunk_size - 1,
                                      std::back_inserter(f_splitted[i]));
                        }
                        std::copy(
                            f.begin() + (parts - 1) * chunk_size, f.end(), std::back_inserter(f_splitted[parts - 1]));
                        return f_splitted;
                    }

                public:
                    static inline typename policy_type::template proof_type<commitment_scheme_witness_type,
                                                                            commitment_scheme_permutation_type,
                                                                            commitment_scheme_quotient_type>
                        process(const typename policy_type::preprocessed_public_data_type preprocessed_public_data,
                                const typename policy_type::preprocessed_private_data_type preprocessed_private_data,
                                typename policy_type::constraint_system_type &constraint_system,
                                const typename policy_type::variable_assignment_type &assignments,
                                const typename policy_type::template circuit_short_description<
                                    commitment_scheme_public_points_type> &short_description,
                                const typename commitment_scheme_witness_type::fri_type::params_type
                                    &fri_params) {    // TODO: fri_type are the same for each lpc_type here

                        typename policy_type::template proof_type<commitment_scheme_witness_type,
                                                                  commitment_scheme_permutation_type,
                                                                  commitment_scheme_quotient_type>
                            proof;
                        std::vector<std::uint8_t> transcript_init {};
                        fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(transcript_init);

                        plonk_polynomial_table<FieldType, ParamsType> polynomial_table =
                            plonk_polynomial_table<FieldType, ParamsType>(
                                preprocessed_private_data.private_polynomial_table,
                                preprocessed_public_data.public_polynomial_table);

                        // 1. Add circuit definition to transcript
                        // transcript(short_description); //TODO: circuit_short_description marshalling

                        // 2. Commit witness columns
                        std::array<math::polynomial<typename FieldType::value_type>, witness_columns> witness_poly =
                            preprocessed_private_data.private_polynomial_table.witnesses();

                        std::array<typename commitment_scheme_witness_type::merkle_tree_type, witness_columns>
                            witness_commitments = commitment_scheme_witness_type::template commit<witness_columns>(
                                witness_poly, fri_params.D[0]);

                        proof.witness_commitments.resize(witness_columns);
                        for (std::size_t i = 0; i < witness_columns; i++) {
                            proof.witness_commitments[i] = witness_commitments[i].root();
                            // transcript(proof.witness_commitments[i]);
                        }

                        // 4. permutation_argument
                        auto permutation_argument =
                            redshift_permutation_argument<FieldType,
                                                          commitment_scheme_public_points_type,
                                                          commitment_scheme_permutation_type,
                                                          ParamsType>::prove_eval(transcript,
                                                                                  preprocessed_public_data,
                                                                                  short_description,
                                                                                  polynomial_table,
                                                                                  fri_params);

                        proof.v_perm_commitment = permutation_argument.permutation_poly_commitment.root();

                        std::array<math::polynomial<typename FieldType::value_type>, f_parts> F;

                        F[0] = permutation_argument.F[0];
                        F[1] = permutation_argument.F[1];
                        F[2] = permutation_argument.F[2];

                        // 5. lookup_argument
                        // std::array<math::polynomial<typename FieldType::value_type>, 5>
                        //     lookup_argument = redshift_lookup_argument<FieldType>::prove_eval(transcript);

                        // 6. circuit-satisfability
                        std::array<math::polynomial<typename FieldType::value_type>, gate_parts> prover_res =
                            redshift_gates_argument<FieldType, ParamsType>::prove_eval(
                                constraint_system, polynomial_table, transcript);

                        F[3] = prover_res[0];

                        // 7. Aggregate quotient polynomial
                        math::polynomial<typename FieldType::value_type> T =
                            quotient_polynomial(preprocessed_public_data, F, transcript);
                        std::vector<math::polynomial<typename FieldType::value_type>> T_splitted =
                            split_polynomial(T, fri_params.max_degree);
                        std::vector<typename commitment_scheme_quotient_type::merkle_tree_type> T_commitments(
                            T_splitted.size());
                        for (std::size_t i = 0; i < T_splitted.size(); i++) {
                            T_commitments[i] = commitment_scheme_quotient_type::commit(T_splitted[i], fri_params.D[0]);
                            proof.T_commitments.push_back(T_commitments[i].root());
                        }

                        // transcript(T_commitments);

                        // 8. Run evaluation proofs
                        typename FieldType::value_type challenge = transcript.template challenge<FieldType>();

                        typename FieldType::value_type omega =
                            preprocessed_public_data.basic_domain->get_domain_element(1);

                        // witness polynomials (table columns)
                        std::array<typename commitment_scheme_witness_type::proof_type, witness_columns>
                            witnesses_evaluation;
                        for (std::size_t i = 0; i < witness_commitments.size(); i++) {
                            std::vector<std::size_t> rotation_gates = {0};    // TODO: Rotation
                            std::array<typename FieldType::value_type, 1>
                                evaluation_points_gates;    // TODO: array size with rotation
                            for (std::size_t i = 0; i < evaluation_points_gates.size(); i++) {
                                evaluation_points_gates[i] = challenge * omega.pow(rotation_gates[i]);
                            }

                            witnesses_evaluation[i] =
                                commitment_scheme_witness_type::proof_eval(evaluation_points_gates,
                                                                           witness_commitments[i],
                                                                           witness_poly[i],
                                                                           transcript,
                                                                           fri_params);
                            proof.eval_proof.witness.push_back(witnesses_evaluation[i]);
                        }

                        // permutation polynomial evaluation
                        std::array<typename FieldType::value_type, 2> evaluation_points_v_p = {challenge,
                                                                                               challenge * omega};
                        typename commitment_scheme_permutation_type::proof_type v_p_evaluation =
                            commitment_scheme_permutation_type::proof_eval(
                                evaluation_points_v_p,
                                permutation_argument.permutation_poly_commitment,
                                permutation_argument.permutation_polynomial,
                                transcript,
                                fri_params);
                        proof.eval_proof.permutation.push_back(v_p_evaluation);

                        std::array<typename FieldType::value_type, 1> evaluation_points_quotient = {challenge};
                        std::vector<typename commitment_scheme_quotient_type::proof_type> quotient_evaluation(
                            T_splitted.size());
                        for (std::size_t i = 0; i < T_splitted.size(); i++) {
                            quotient_evaluation[i] = commitment_scheme_quotient_type::proof_eval(
                                evaluation_points_quotient, T_commitments[i], T_splitted[i], transcript, fri_params);
                            proof.eval_proof.quotient.push_back(quotient_evaluation[i]);
                        }

                        return proof;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP
