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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PERMUTATION_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_PERMUTATION_ARGUMENT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/merkle/tree.hpp>

#include <nil/crypto3/zk/snark/commitments/list_polynomial_commitment.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType>
                struct redshift_permutation_argument {
                    static inline std::array<math::polynomial::polynomial<typename FieldType::value_type>, 3>
                        prove_argument(fiat_shamir_heuristic<transcript_manifest, transcript_hash_type> &transcript, ) {
                        // 2. Get $\beta, \gamma \in \mathbb{F}$ from $hash(\text{transcript})$
                        typename FieldType::value_type beta =
                            transcript.template challenge<transcript_manifest::challenges_ids::beta, FieldType>();

                        typename FieldType::value_type gamma =
                            transcript.template challenge<transcript_manifest::challenges_ids::gamma, FieldType>();

                        // 4. For $1 < j \leq N_{\texttt{rows}}$ calculate $g_j, h_j$
                        std::vector<typename FieldType::value_type> g_points(N_rows + 1);
                        std::vector<typename FieldType::value_type> h_points(N_rows + 1);

                        const std::vector<math::polynomial::polynomial<typename FieldType::value_type>> &S_sigma =
                            preprocessed_data.permutations;
                        const std::vector<math::polynomial::polynomial<typename FieldType::value_type>> &S_id =
                            preprocessed_data.identity_permutations;

                        for (std::size_t j = 1; j <= N_rows; j++) {
                            g_points[j] = FieldType::value_type::one();
                            h_points[j] = FieldType::value_type::one();
                            for (std::size_t i = 0; i < N_perm + N_PI; i++) {

                                g_points[j] *= (f[j].evaluate(D_0[j]) + beta * S_id[j].evaluate(D_0[j]) + gamma);
                                h_points[j] *= (f[j].evaluate(D_0[j]) + beta * S_sigma[j].evaluate(D_0[j]) + gamma);
                            }
                        }

                        // 5. Calculate $V_P$
                        std::vector<typename FieldType::value_type>
                            V_P_interpolation_points(N_rows + 1);

                        V_P_interpolation_points.push_back(FieldType::value_type::one());
                        for (std::size_t j = 2; j < N_rows + 1; j++) {

                            typename FieldType::value_type tmp_mul_result = FieldType::value_type::one();
                            for (std::size_t i = 1; i <= j - 1; i++) {
                                tmp_mul_result *= g_points[i] / h_points[i];
                            }

                            V_P_interpolation_points.push_back(tmp_mul_result);
                        }

                        V_P_interpolation_points.push_back(FieldType::value_type::one());

                        const std::shared_ptr<math::evaluation_domain<FieldType>> V_P_domain =
                            math::make_evaluation_domain<FieldType>(N_rows + 1);

                        V_P_domain->inverse_fft(V_P_interpolation_points);

                        math::polynomial::polynomial<typename FieldType::value_type> V_P = V_P_interpolation_points;

                        // 6. Compute and add commitment to $V_P$ to $\text{transcript}$.
                        merkle_tree_type V_P_tree = lpc::commit(V_P, D_0);
                        typename lpc::commitment_type V_P_commitment = V_P_tree.root();
                        transcript(V_P_commitment);


                        // 17. Denote g_1,2, h_1,2
                        math::polynomial::polynomial<typename FieldType::value_type> g_1 = {1};                        
                        math::polynomial::polynomial<typename FieldType::value_type> h_1 = {1};

                        for (std::size_t i = 0; i <= N_perm + N_PI - 1; i++) {
                            g_1 = g_1 * (f[i] + beta * S_id[i] + gamma);
                            h_1 = h_1 * (f[i] + beta * S_sigma[i] + gamma);
                        }

                        const math::polynomial::polynomial<typename FieldType::value_type> q_last;
                        const math::polynomial::polynomial<typename FieldType::value_type> q_blind;

                        std::array<math::polynomial::polynomial<typename FieldType::value_type>, 3> F;
                        F[0] = L1 * (1 - V_P);
                        F[1] = (1 - (q_last + q_blind)) * (V_P_shifted * h_1 - V_P * g_1);
                        F[2] = q_last * (V_P * V_P - V_P);
                        
                        return F;
                    }

                    static inline std::array<typename FieldType::value_type, 3> 
                        verify_argument(fiat_shamir_heuristic<transcript_manifest, transcript_hash_type> &transcript, ) {
                        typename transcript_hash_type::digest_type beta_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::beta>();

                        typename transcript_hash_type::digest_type gamma_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::gamma>();

                        typename FieldType::value_type beta = algebra::marshalling<FieldType>(beta_bytes);
                        typename FieldType::value_type gamma = algebra::marshalling<FieldType>(gamma_bytes);

                        transcript(proof.P_commitment);
                        transcript(proof.Q_commitment);

                        const math::polynomial::polynomial<typename FieldType::value_type> q_last;
                        const math::polynomial::polynomial<typename FieldType::value_type> q_blind;

                        F[0] = verification_key.L_basis[1] * (P - 1);
                        F[1] = verification_key.L_basis[1] * (Q - 1);
                        F[2] = P * p_1 - (P << 1);
                        
                        return F;
                    }
                };
            } // namespace snark
        } // namespace zk
    } // namespace crypto3
} // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP