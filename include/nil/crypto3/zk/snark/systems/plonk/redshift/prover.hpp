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
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType,
                         std::size_t WiresAmount,
                         std::size_t lambda,
                         std::size_t k,
                         std::size_t r,
                         std::size_t m = 2>
                class redshift_prover {

                    using types_policy = detail::redshift_types_policy<FieldType, WiresAmount>;
                    using transcript_manifest =
                        typename types_policy::template prover_fiat_shamir_heuristic_manifest<8>;

                    typedef hashes::sha2<256> merkle_hash_type;
                    typedef hashes::sha2<256> transcript_hash_type;

                    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

                    typedef list_polynomial_commitment_scheme<FieldType, merkle_hash_type, lambda, k, r, m> lpc;

                public:
                    static inline typename types_policy::template proof_type<lpc>
                        process(const typename types_policy::template preprocessed_data_type<k> preprocessed_data,
                                const typename types_policy::constraint_system_type &constraint_system,
                                const typename types_policy::variable_assignment_type &assignments,
                                const typename types_policy::public_input_type &PI) {

                        std::size_t N_wires = WiresAmount;
                        std::size_t N_perm = preprocessed_data.permutations.size();
                        std::size_t N_sel = preprocessed_data.selectors.size();
                        std::size_t N_PI = PI.size();
                        // std::size_t N_const = ...;

                        std::size_t N_rows = 0;
                        for (auto &wire_assignments : assignments) {
                            N_rows = std::max(N_rows, wire_assignments.size());
                        }

                        std::vector<typename FieldType::value_type> omega_powers(std::max({N_wires, N_perm, N_rows}) +
                                                                                 1 + 1);
                        omega_powers[0] = FieldType::value_type::one();
                        for (std::size_t power = 1; power < omega_powers.size(); power++) {
                            omega_powers[power] = preprocessed_data.omega * omega_powers[power - 1];
                        }

                        std::vector<typename FieldType::value_type> D_0(N_rows);
                        for (std::size_t power = 1; power <= N_rows; power++) {
                            D_0.emplace_back(preprocessed_data.omega.pow(power));
                        }

                        fiat_shamir_heuristic<transcript_manifest, transcript_hash_type> transcript;

                        // ... setup_values = ...;
                        // transcript(setup_values);

                        // 1. Add commitments to $w_i(X)$ to $\text{transcript}$

                        std::vector<math::polynomial::polynomial<typename FieldType::value_type>> w =
                            constraint_system.polynomials(assignments);

                        std::vector<merkle_tree_type> w_trees;
                        std::vector<typename lpc::commitment_type> w_commitments;
                        w_commitments.reserve(N_wires);
                        w_trees.reserve(N_wires);

                        for (std::size_t i = 0; i < N_wires; i++) {
                            w_trees.push_back(lpc::commit(w[i], D_0));
                            w_commitments.push_back(w_trees[i].root());
                            transcript(w_commitments[i]);
                        }

                        // 3. Denote witness polynomials included in permutation argument and public input polynomials
                        // as $f_i$
                        std::vector<math::polynomial::polynomial<typename FieldType::value_type>> f(N_perm + N_PI);

                        std::copy(w.begin(), w.end(), f.begin());

                        std::array<math::polynomial::polynomial<typename FieldType::value_type>, 3>
                            permutation_argument = redshift_permutation_argument<FieldType>::prove_argument(transcript);
                        // std::copy(PI.begin(), PI.end(), f.begin() + N_perm);

                        // 14. Get $\alpha_0, \dots, \alpha_8 \in \mathbb{F}$ from $hash(\text{transcript})$
                        constexpr const std::size_t f_parts = 4;
                        std::array<typename FieldType::value_type, f_parts> alphas =
                            transcript.template challenges<transcript_manifest::challenges_ids::alpha, f_parts, FieldType>();

                        // 15. Get $\tau$ from $hash(\text{transcript})$
                        typename FieldType::value_type tau =
                            transcript.template challenge<transcript_manifest::challenges_ids::tau, FieldType>();

                        // 16. Computing gates
                        // And 20. Compute N_T
                        std::size_t N_T = N_perm + N_PI;
                        std::vector<math::polynomial::polynomial<typename FieldType::value_type>> gates(N_sel);
                        std::vector<math::polynomial::polynomial<typename FieldType::value_type>> constraints =
                            constraint_system.polynomials(assignments);

                        for (std::size_t i = 0; i <= N_sel - 1; i++) {
                            gates[i] = {0};
                            std::size_t n_i;
#error Uninitialized n_i
                            for (std::size_t j = 0; j < n_i; j++) {
                                std::size_t d_i_j;
                                gates[i] = gates[i] + preprocessed_data.constraints[j] * tau.pow(d_i_j);
                            }

                            // gates[i] *= preprocessed_data.selectors[i];

                            N_T = std::max(N_T, gates[i].size() - 1);
                        }

                        // 18. Define F polynomials
                        const math::polynomial::polynomial<typename FieldType::value_type> L1 =
                            preprocessed_data.Lagrange_basis[1];

                        std::array<math::polynomial::polynomial<typename FieldType::value_type>, f_parts> F;

                        F[0] = permutation_argument[0];
                        F[1] = permutation_argument[1];
                        F[2] = permutation_argument[2];
                        F[3] = {0};
                        for (std::size_t i = 0; i < N_sel; i++) {
                            F[3] = F[3] + gates[i];
                        }

                        // 19. Compute F_consolidated
                        math::polynomial::polynomial<typename FieldType::value_type> F_consolidated = {0};
                        for (std::size_t i = 0; i < f_parts; i++) {
                            F_consolidated = F_consolidated + alphas[i] * F[i];
                        }

                        math::polynomial::polynomial<typename FieldType::value_type> T_consolidated =
                            F_consolidated / preprocessed_data.Z;

                        // 21. Split $T(X)$ into separate polynomials $T_0(X), ..., T_{N_T - 1}(X)$
                        std::vector<math::polynomial::polynomial<typename FieldType::value_type>> T(N_T);
                        // T = separate_T(T_consolidated);

                        // 22. Add commitments to $T_0(X), ..., T_{N_T - 1}(X)$ to $\text{transcript}$
                        std::vector<merkle_tree_type> T_trees;
                        std::vector<typename lpc::commitment_type> T_commitments;

                        for (std::size_t i = 0; i < N_perm + 1; i++) {
                            T_trees.push_back(lpc::commit(T[i], D_0));
                            T_commitments.push_back(T_trees[i].root());
                            transcript(T_commitments[i]);
                        }

                        // 23. Get $y \in \mathbb{F}/H$ from $hash|_{\mathbb{F}/H}(\text{transcript})$
                        typename FieldType::value_type upsilon =
                            transcript.template challenge<transcript_manifest::challenges_ids::upsilon, FieldType>();

                        std::array<typename FieldType::value_type, k> fT_evaluation_points = {upsilon};
                        std::vector<typename lpc::proof_type> f_lpc_proofs(N_wires);

                        // for (std::size_t i = 0; i < N_wires; i++){
                        //     f_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, f_trees[i], f[i], D_0));
                        // }

                        // std::array<typename FieldType::value_type, k>
                        //     PQ_evaluation_points = {upsilon, upsilon * preprocessed_data.omega};
                        // typename lpc::proof P_lpc_proof = lpc::proof_eval(PQ_evaluation_points, P_tree, P, D_0);
                        // typename lpc::proof Q_lpc_proof = lpc::proof_eval(PQ_evaluation_points, Q_tree, Q, D_0);

                        std::vector<typename lpc::proof_type> T_lpc_proofs(N_perm + 1);

                        for (std::size_t i = 0; i < N_perm + 1; i++) {
                            T_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, T_trees[i], T[i], D_0));
                        }

                        typename types_policy::template proof_type<lpc> proof;
                        // = typename types_policy::proof_type(std::move(f_commitments), std::move(P_commitment),
                        //                                   std::move(Q_commitment), std::move(T_commitments),
                        //                                   std::move(f_lpc_proofs), std::move(P_lpc_proof),
                        //                                   std::move(Q_lpc_proof), std::move(T_lpc_proofs));
                        proof.T_lpc_proofs = T_lpc_proofs;
                        proof.f_lpc_proofs = f_lpc_proofs;
                        proof.T_commitments = T_commitments;

                        return proof;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP
