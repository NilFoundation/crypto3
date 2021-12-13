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

#include <nil/crypto3/math/polynomial/polynom.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/merkle/tree.hpp>

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/types.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, std::size_t WiresAmount, 
                    std::size_t lambda, std::size_t k, std::size_t r, std::size_t m=2>
                class redshift_prover {

                    using types_policy = detail::redshift_types_policy<FieldType, WiresAmount>;
                    using transcript_manifest = typename types_policy::template prover_fiat_shamir_heuristic_manifest<11>;

                    typedef hashes::sha2<256> merkle_hash_type;
                    typedef hashes::sha2<256> transcript_hash_type;

                    typedef typename containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;

                    typedef list_polynomial_commitment_scheme<FieldType, 
                        merkle_hash_type, lambda, k, r, m> lpc;

                public:
                    static inline typename types_policy::template proof_type<lpc>
                        process(const typename types_policy::preprocessed_data_type preprocessed_data,
                                const typename types_policy::constraint_system_type &constraint_system,
                                const typename types_policy::variable_assignment_type &assignments) {

                        std::size_t N_wires = WiresAmount;
                        std::size_t N_perm = preprocessed_data.permutations.size();
                        std::size_t N_sel = preprocessed_data.selectors.size();
                        // std::size_t N_const = ...;

                        std::size_t n = 0;
                        for(auto &wire_assignments:assignments){
                            n = std::max(n, wire_assignments.size());
                        }

                        std::vector<typename FieldType::value_type> D_0(n);
                        for (std::size_t power = 1; power<=n; power++){
                            D_0.emplace_back(preprocessed_data.omega.pow(power));
                        }

                        fiat_shamir_heuristic<transcript_manifest, transcript_hash_type> transcript;

                        // ... setup_values = ...;
                        // transcript(setup_values);

                        // 2 - Define new witness polynomials
                        // and 3 - Add commitments to fi to transcript
                        std::vector<math::polynomial::polynom<typename FieldType::value_type>> f = 
                            constraint_system.get_polynoms(assignments);

                        std::vector<merkle_tree_type> f_trees;
                        std::vector<typename lpc::commitment_type> f_commitments;

                        for (std::size_t i = 0; i < N_wires; i++) {
                            math::polynomial::polynom<typename FieldType::value_type> h;
                            f[i] = f[i] + h * preprocessed_data.Z;
                            f_trees.push_back(lpc::commit(f[i]));
                            f_commitments[i].push_back(f_trees[i].root());
                            transcript(f_commitments[i]);
                        }

                        // 4
                        typename FieldType::value_type teta =
                            transcript.get_challenge<transcript_manifest::challenges_ids::teta, FieldType>();

                        // 5
                        // A(teta)
                        std::vector<typename FieldType::value_type> A;
                        // S(teta)
                        std::vector<typename FieldType::value_type> S;

                        // 6
                        math::polynomial::polynom<typename FieldType::value_type> A1;
                        math::polynomial::polynom<typename FieldType::value_type> S1;

                        // 7
                        merkle_tree_type A1_tree = lpc::commit(A1);
                        merkle_tree_type P1_tree = lpc::commit(P1);
                        typename lpc::commitment_type A1_commitment = A1_tree.root();
                        typename lpc::commitment_type P1_commitment = P1_tree.root();

                        transcript(A1_commitment);
                        transcript(P1_commitment);

                        // 8
                        typename FieldType::value_type beta =
                            transcript.get_challenge<transcript_manifest::challenges_ids::beta, FieldType>();

                        typename FieldType::value_type gamma =
                            transcript.get_challenge<transcript_manifest::challenges_ids::gamma, FieldType>();

                        // 9
                        // and 10
                        std::vector<math::polynomial::polynom<typename FieldType::value_type>> p(N_perm);
                        std::vector<math::polynomial::polynom<typename FieldType::value_type>> q(N_perm);

                        math::polynomial::polynom<typename FieldType::value_type> p1 = {1};
                        math::polynomial::polynom<typename FieldType::value_type> q1 = {1};

                        std::vector<math::polynomial::polynom> &S_sigma = preprocessed_data.permutations;
                        std::vector<math::polynomial::polynom> &S_id = preprocessed_data.identity_permutations;

                        for (std::size_t j = 0; j < N_perm; j++) {
                            p.push_back(f[j] + beta * S_id[j] + gamma);
                            q.push_back(f[j] + beta * S_sigma[j] + gamma);

                            p1 *= p[j];
                            q1 *= q[j];
                        }

                        // 11
                        std::vector<std::pair<typename FieldType::value_type,
                                              typename FieldType::value_type>>
                            P_interpolation_points(n + 1);
                        std::vector<std::pair<typename FieldType::value_type,
                                              typename FieldType::value_type>>
                            Q_interpolation_points(n + 1);

                        P_interpolation_points.push_back(std::make_pair(preprocessed_data.omega, 1));
                        for (std::size_t i = 2; i <= n + 1; i++) {

                            typename FieldType::value_type P_mul_result =
                                typename FieldType::one();
                            typename FieldType::value_type Q_mul_result =
                                typename FieldType::one();
                            for (std::size_t j = 1; j < i; j++) {
                                P_mul_result *= p1(preprocessed_data.omega.pow(i));
                                Q_mul_result *= q1(preprocessed_data.omega.pow(i));
                            }

                            P_interpolation_points.push_back(std::make_pair(preprocessed_data.omega.pow(i), P_mul_result));
                            Q_interpolation_points.push_back(std::make_pair(preprocessed_data.omega.pow(i), Q_mul_result));
                        }

                        math::polynomial::polynom<typename FieldType::value_type> P =
                            math::polynomial::lagrange_interpolation(P_interpolation_points);
                        math::polynomial::polynom<typename FieldType::value_type> Q =
                            math::polynomial::lagrange_interpolation(Q_interpolation_points);

                        // 12
                        merkle_tree_type P_tree = lpc::commit(P);
                        merkle_tree_type Q_tree = lpc::commit(Q);
                        typename lpc::commitment_type P_commitment = P_tree.root();
                        typename lpc::commitment_type Q_commitment = Q_tree.root();

                        transcript(P_commitment);
                        transcript(Q_commitment);

                        // 13
                        // ... V = ...;

                        // 14
                        transcript(lpc::commit(V).root());

                        // 15
                        std::array<typename FieldType::value_type, 6> alphas;
                        for (std::size_t i = 0; i < 6; i++) {
                            alphas[i] =
                                transcript.get_challenge<transcript_manifest::challenges_ids::alpha, i, FieldType>();
                        }

                        // 16
                        typename FieldType::value_type tau =
                            transcript.get_challenge<transcript_manifest::challenges_ids::tau, FieldType>();

                        // 17
                        // and 21
                        std::size_t N_T = N_perm;
                        std::vector<math::polynomial::polynom<typename FieldType::value_type>> gates(N_sel);
                        for (std::size_t i = 0; i < N_sel; i++) {
                            gates[i] = [0];
                            for (std::size_t j = 0; j < ...; j++){
                                gates[i] += preprocessed_data.constraints[j][i] * tau.pow(...);
                            }

                            gates[i] *= preprocessed_data.selectors[i];

                            N_T = std::max(N_T, gates[i].degree() - 1);
                        }                        

                        // 18
                        std::array<math::polynomial::polynom<typename FieldType::value_type>, 11> F;
                        F[0] = preprocessed_data.Lagrange_basis[1] * (P - 1);
                        F[1] = preprocessed_data.Lagrange_basis[1] * (Q - 1);
                        F[2] = P * p_1 - (P << 1);
                        F[3] = Q * q_1 - (Q << 1);
                        F[4] = preprocessed_data.Lagrange_basis[n] * ((P << 1) - (Q << 1));
                        F[5] = preprocessed_data.PI;

                        for (std::size_t i = 0; i < N_sel; i++) {
                            F[5] += gates[i];
                        }

                        // 19
                        // ...

                        // 20
                        math::polynomial::polynom<typename FieldType::value_type> F_consolidated = 0;
                        for (std::size_t i = 0; i < 11; i++) {
                            F_consolidated += a[i] * F[i];
                        }

                        math::polynomial::polynom<typename FieldType::value_type> T_consolidated = 
                            F_consolidated / Z;

                        // 22
                        std::vector<math::polynomial::polynom<typename FieldType::value_type>> T(N_T);
                        T = separate_T(T_consolidated);

                        // 23
                        std::vector<merkle_tree_type> T_trees;
                        std::vector<typename lpc::commitment_type> T_commitments;

                        for (std::size_t i = 0; i < N_perm + 1) {
                            T_trees.push_back(lpc::commit(T[i]));
                            T_commitments.push_back(T_trees[i].root());
                        }

                        typename FieldType::value_type upsilon =
                            transcript.get_challenge<transcript_manifest::challenges_ids::upsilon, FieldType>();

                        std::array<typename FieldType::value_type, k> 
                            fT_evaluation_points = {upsilon};
                        std::vector<typename lpc::proof> f_lpc_proofs(N_wires);

                        for (std::size_t i = 0; i < N_wires; i++){
                            f_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, f_trees[i], f[i], D_0));
                        }

                        std::array<typename FieldType::value_type, k> 
                            PQ_evaluation_points = {upsilon, upsilon * preprocessed_data.omega};
                        typename lpc::proof P_lpc_proof = lpc::proof_eval(PQ_evaluation_points, P_tree, P, D_0);
                        typename lpc::proof Q_lpc_proof = lpc::proof_eval(PQ_evaluation_points, Q_tree, Q, D_0);

                        std::vector<typename lpc::proof> T_lpc_proofs(N_perm + 1);

                        for (std::size_t i = 0; i < N_perm + 1; i++){
                            T_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, T_trees[i], T[i], D_0));
                        }

                        typename types_policy::proof_type proof =
                            typename types_policy::proof_type(std::move(f_commitments), std::move(P_commitment),
                                                              std::move(Q_commitment), std::move(T_commitments),
                                                              std::move(f_lpc_proofs), std::move(P_lpc_proof),
                                                              std::move(Q_lpc_proof), std::move(T_lpc_proofs));

                        return proof;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP
