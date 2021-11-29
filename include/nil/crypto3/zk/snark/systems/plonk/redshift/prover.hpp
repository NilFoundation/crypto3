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

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, std::size_t lambda, std::size_t m=2>
                class redshift_prover {

                    using types_policy = redshift_types_policy<FieldType>;
                    using transcript_manifest = types_policy::prover_fiat_shamir_heuristic_manifest<6>;

                    typedef hashes::sha2<256> merkle_hash_type;
                    typedef hashes::sha2<256> transcript_hash_type;

                    typedef typename merkletree::MerkleTree<Hash> merkle_tree_type;

                    constexpr static const std::size_t k = ...;
                    constexpr static const std::size_t r = ...;

                    constexpr static const typename FieldType::value_type omega = 
                        algebra::get_root_of_unity<FieldType>()
                    typedef list_polynomial_commitment_scheme<FieldType, 
                        Hash, lambda, k, r, m> lpc;

                public:
                    static inline typename types_policy::proof_type<lpc>
                        process(const types_policy::proving_key_type &proving_key,
                                const types_policy::primary_input_type &primary_input,
                                const types_policy::auxiliary_input_type &auxiliary_input) {

                        std::size_t N_wires = primary_input.size() + auxiliary_input.size();
                        std::size_t N_perm = ...;
                        std::size_t N_sel = ...;
                        std::size_t N_const = ...;

                        fiat_shamir_heuristic<transcript_manifest, transcript_hash_type> transcript;

                        ... setup_values = ...;
                        transcript(setup_values);

                        std::vector<math::polynomial::polynom<typename FieldType::value_type>> f(N_wires);

                        std::vector<merkle_tree_type> f_trees;
                        std::vector<typename lpc::commitment_type> f_commitments;

                        for (std::size_t i = 0; i < N_wires; i++) {
                            f.push_back(proving_key.f[i] + choose_h_i() * proving_key.Z(x));
                            f_trees.push_back(lpc::commit(f[i]));
                            f_commitments[i].push_back(f_trees[i].root());
                            transcript(f_commitments[i]);
                        }

                        typename transcript_hash_type::digest_type beta_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::beta>();

                        typename transcript_hash_type::digest_type gamma_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::gamma>();

                        typename FieldType::value_type beta =
                            algebra::marshalling<FieldType>(beta_bytes);
                        typename FieldType::value_type gamma =
                            algebra::marshalling<FieldType>(gamma_bytes);

                        std::vector<math::polynomial::polynom<typename FieldType::value_type>> p(N_perm);
                        std::vector<math::polynomial::polynom<typename FieldType::value_type>> q(N_perm);

                        math::polynomial::polynom<typename FieldType::value_type> p1 = {1};
                        math::polynomial::polynom<typename FieldType::value_type> q1 = {1};

                        for (std::size_t j = 0; j < N_perm; j++) {
                            p.push_back(f[j] + beta * S_id[j] + gamma);
                            q.push_back(f[j] + beta * S_sigma[j] + gamma);

                            p1 *= p[j];
                            q1 *= q[j];
                        }

                        std::vector<std::pair<typename FieldType::value_type,
                                              typename FieldType::value_type>>
                            P_interpolation_points(n + 1);
                        std::vector<std::pair<typename FieldType::value_type,
                                              typename FieldType::value_type>>
                            Q_interpolation_points(n + 1);

                        P_interpolation_points.push_back(std::make_pair(proving_key.omega, 1));
                        for (std::size_t i = 2; i <= n + 1; i++) {
                            typename FieldType::value_type P_mul_result =
                                typename FieldType::one();
                            typename FieldType::value_type Q_mul_result =
                                typename FieldType::one();
                            for (std::size_t j = 1; j < i; j++) {
                                P_mul_result *= p1(proving_key.omega.pow(i));
                                Q_mul_result *= q1(proving_key.omega.pow(i));
                            }

                            P_interpolation_points.push_back(std::make_pair(proving_key.omega.pow(i), P_mul_result));
                            Q_interpolation_points.push_back(std::make_pair(proving_key.omega.pow(i), Q_mul_result));
                        }

                        math::polynomial::polynom<typename FieldType::value_type> P =
                            math::polynomial::Lagrange_interpolation(P_interpolation_points);
                        math::polynomial::polynom<typename FieldType::value_type> Q =
                            math::polynomial::Lagrange_interpolation(Q_interpolation_points);

                        merkle_tree_type P_tree = lpc::commit(P);
                        merkle_tree_type Q_tree = lpc::commit(Q);
                        typename lpc::commitment_type P_commitment = P_tree.root();
                        typename lpc::commitment_type Q_commitment = Q_tree.root();

                        transcript(P_commitment);
                        transcript(Q_commitment);

                        std::array<typename FieldType::value_type, 6> alphas;
                        for (std::size_t i = 0; i < 6; i++) {
                            typename transcript_hash_type::digest_type alpha_bytes =
                                transcript.get_challenge<transcript_manifest::challenges_ids::alpha, i>();
                            alphas[i] = (algebra::marshalling<typename FieldType>(alpha_bytes));
                        }

                        std::array<math::polynomial::polynom<typename FieldType::value_type>, 6> F;
                        F[0] = proving_key.L_basis[1] * (P - 1);
                        F[1] = proving_key.L_basis[1] * (Q - 1);
                        F[2] = P * p_1 - (P << 1);
                        F[3] = Q * q_1 - (Q << 1);
                        F[4] = proving_key.L_basis[n] * ((P << 1) - (Q << 1));
                        F[5] = proving_key.PI;

                        for (std::size_t i = 0; i < N_sel; i++) {
                            F[5] += q[i] * ....gate[i];
                        }

                        for (std::size_t i = 0; i < N_const; i++) {
                            F[5] += proving_key.f_c[i];
                        }

                        math::polynomial::polynom<typename FieldType::value_type> F_consolidated = 0;
                        for (std::size_t i = 0; i < 6; i++) {
                            F_consolidated += a[i] * F[i];
                        }

                        math::polynomial::polynom<typename FieldType::value_type> T_consolidated = 
                            F_consolidated / Z;

                        std::vector<math::polynomial::polynom<typename FieldType::value_type>> T(N_perm + 1);
                        T = separate_T(T_consolidated);

                        std::vector<merkle_tree_type> T_trees;
                        std::vector<typename lpc::commitment_type> T_commitments;

                        for (std::size_t i = 0; i < N_perm + 1) {
                            T_trees.push_back(lpc::commit(T[i]));
                            T_commitments.push_back(T_trees[i].root());
                        }

                        typename transcript_hash_type::digest_type upsilon_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::upsilon>();

                        typename FieldType::value_type upsilon =
                            algebra::marshalling<FieldType>(upsilon_bytes);

                        std::array<typename FieldType::value_type, k> 
                            fT_evaluation_points = {upsilon};
                        std::vector<lpc::proof> f_lpc_proofs(N_wires);

                        for (std::size_t i = 0; i < N_wires; i++){
                            f_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, f_trees[i], f[i], ...));
                        }

                        std::array<typename FieldType::value_type, k> 
                            PQ_evaluation_points = {upsilon, upsilon * omega};
                        lpc::proof P_lpc_proof = lpc::proof_eval(PQ_evaluation_points, P_tree, P, ...);
                        lpc::proof Q_lpc_proof = lpc::proof_eval(PQ_evaluation_points, Q_tree, Q, ...);

                        std::vector<lpc::proof> T_lpc_proofs(N_perm + 1);

                        for (std::size_t i = 0; i < N_perm + 1; i++){
                            T_lpc_proofs.push_back(lpc::proof_eval(fT_evaluation_points, T_trees[i], T[i], ...));
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
