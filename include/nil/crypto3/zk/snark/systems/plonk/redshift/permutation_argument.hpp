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

#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType>
                class redshift_permutation_argument {

                static constexpr std::size_t argument_size = 3;

                public:
                    static inline std::array<math::polynomial::polynomial<typename FieldType::value_type>,
                                             argument_size>    // TODO: fix fiat-shamir
                        prove_argument(
                            fiat_shamir_heuristic_updated<hashes::keccak_1600<512>> &transcript,
                            std::size_t circuit_rows,
                            std::size_t permutation_size,
                            std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                            const math::polynomial::polynomial<typename FieldType::value_type> &lagrange_1,
                            const std::vector<math::polynomial::polynomial<typename FieldType::value_type>> &S_id,
                            const std::vector<math::polynomial::polynomial<typename FieldType::value_type>> &S_sigma,
                            const std::vector<math::polynomial::polynomial<typename FieldType::value_type>> &f,
                            const math::polynomial::polynomial<typename FieldType::value_type> &q_last,
                            const math::polynomial::polynomial<typename FieldType::value_type> &q_blind) {
                        // 1. $\beta_1, \gamma_1 = \challenge$
                        typename FieldType::value_type beta = transcript.template challenge<FieldType>();

                        typename FieldType::value_type gamma = transcript.template challenge<FieldType>();

                        // 2. Calculate id_binding, sigma_binding for j from 1 to N_rows
                        std::vector<typename FieldType::value_type> id_binding(circuit_rows);
                        std::vector<typename FieldType::value_type> sigma_binding(circuit_rows);

                        for (std::size_t j = 0; j < circuit_rows; j++) {
                            id_binding[j] = FieldType::value_type::one();
                            sigma_binding[j] = FieldType::value_type::one();
                            for (std::size_t i = 0; i < permutation_size; i++) {

                                id_binding[j] *=
                                    (f[i].evaluate(domain->get_domain_element(j)) + beta * S_id[i].evaluate(domain->get_domain_element(j)) + gamma);
                                sigma_binding[j] *=
                                    (f[i].evaluate(domain->get_domain_element(j)) + beta * S_sigma[i].evaluate(domain->get_domain_element(j)) + gamma);
                            }
                        }

                        // 3. Calculate $V_P$
                        std::vector<typename FieldType::value_type> V_P_interpolation_points(circuit_rows);

                        V_P_interpolation_points[0] = FieldType::value_type::one();
                        for (std::size_t j = 1; j < circuit_rows; j++) {
                            typename FieldType::value_type tmp_mul_result = FieldType::value_type::one();
                            for (std::size_t i = 0; i <= j - 1; i++) {
                                // TODO: use one division
                                tmp_mul_result *= id_binding[i] / sigma_binding[i];
                            }

                            V_P_interpolation_points[j] = tmp_mul_result;
                        }

                        const std::shared_ptr<math::evaluation_domain<FieldType>> V_P_domain =
                            math::make_evaluation_domain<FieldType>(circuit_rows);

                        V_P_domain->inverse_fft(V_P_interpolation_points);

                        math::polynomial::polynomial<typename FieldType::value_type> V_P(
                            V_P_interpolation_points.begin(), V_P_interpolation_points.end());

                        // 4. Compute and add commitment to $V_P$ to $\text{transcript}$.
                        // TODO: include commitment
                        // merkle_tree_type V_P_tree = fri::commit(V_P, D_0);
                        // typename fri::commitment_type V_P_commitment = V_P_tree.root();
                        // transcript(V_P_commitment);

                        // 5. Calculate g_perm, h_perm
                        math::polynomial::polynomial<typename FieldType::value_type> g = {1};
                        math::polynomial::polynomial<typename FieldType::value_type> h = {1};

                        for (std::size_t i = 0; i < permutation_size; i++) {
                            g = g * (f[i] + beta * S_id[i] + gamma);
                            h = h * (f[i] + beta * S_sigma[i] + gamma);
                        }

                        math::polynomial::polynomial<typename FieldType::value_type> one_polynomial = {1};
                        std::array<math::polynomial::polynomial<typename FieldType::value_type>, argument_size> F;
                        F[0] = lagrange_1 * (one_polynomial - V_P);
                        F[1] = (one_polynomial - (q_last + q_blind)) * ((domain->get_domain_element(0) * V_P) * h - V_P * g);
                        F[2] = q_last * (V_P * V_P - V_P);
                        
                        return F;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size> verify_argument() {
                        /*typename transcript_hash_type::digest_type beta_bytes =
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
                        F[2] = P * p_1 - (P << 1);*/
                        std::array<typename FieldType::value_type, argument_size> F;

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP