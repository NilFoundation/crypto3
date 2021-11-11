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

#include <nil/crypto3/zk/snark/commitments/fri_commitment.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename TCurve>
                class redshift_prover {

                    using types_policy = redshift_types_policy<TCurve>;
                    using transcript_manifest = types_policy::prover_fiat_shamir_heuristic_manifest<6>;

                public:
                    static inline typename types_policy::proof_type
                        process(const types_policy::proving_key_type &proving_key,
                                const types_policy::primary_input_type &primary_input,
                                const types_policy::auxiliary_input_type &auxiliary_input) {

                        std::size_t N_wires = primary_input.size() + auxiliary_input.size();
                        std::size_t N_perm = ...;
                        std::size_t N_sel = ...;
                        std::size_t N_const = ...;

                        fiat_shamir_heuristic<transcript_manifest, hashes::sha2> transcript;

                        ... setup_values = ...;
                        transcript(setup_values);

                        std::vector<math::polynomial::polynom<...>> f(N_wires);
                        std::vector<std::fri_commitment_cheme<...>> f_commitments(N_wires);

                        for (std::size_t i = 0; i < N_wires; i++) {
                            f.push_back(proving_key.f[i] + choose_h_i() * proving_key.Z(x));
                            f_commitments[i].commit(f[i]);
                            transcript(f_commitments[i]);
                        }

                        hashes::sha2::digest_type beta_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::beta>();

                        hashes::sha2::digest_type gamma_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::gamma>();

                        typename TCurve::scalar_field_type::value_type beta =
                            algebra::marshalling<TCurve::scalar_field_type>(beta_bytes);
                        typename TCurve::scalar_field_type::value_type gamma =
                            algebra::marshalling<TCurve::scalar_field_type>(gamma_bytes);

                        std::vector<math::polynomial::polynom<...>> p(N_perm);
                        std::vector<math::polynomial::polynom<...>> q(N_perm);

                        math::polynomial::polynom<...> p1 = math::polynomial::polynom<...>::one();
                        math::polynomial::polynom<...> q1 = math::polynomial::polynom<...>::one();

                        for (std::size_t j = 0; j < N_perm; j++) {
                            p.push_back(f[j] + beta * S_id[j] + gamma);
                            q.push_back(f[j] + beta * S_sigma[j] + gamma);

                            p1 *= p[j];
                            q1 *= q[j];
                        }

                        std::vector<std::pair<typename TCurve::scalar_field_type::value_type,
                                              typename TCurve::scalar_field_type::value_type>>
                            P_interpolation_points(n + 1);
                        std::vector<std::pair<typename TCurve::scalar_field_type::value_type,
                                              typename TCurve::scalar_field_type::value_type>>
                            Q_interpolation_points(n + 1);

                        P_interpolation_points.push_back(std::make_pair(proving_key.omega, 1));
                        for (std::size_t i = 2; i <= n + 1; i++) {
                            typename TCurve::scalar_field_type::value_type P_mul_result =
                                typename TCurve::scalar_field_type::one();
                            typename TCurve::scalar_field_type::value_type Q_mul_result =
                                typename TCurve::scalar_field_type::one();
                            for (std::size_t j = 1; j < i; j++) {
                                P_mul_result *= p1(proving_key.omega.pow(i));
                                Q_mul_result *= q1(proving_key.omega.pow(i));
                            }

                            P_interpolation_points.push_back(std::make_pair(proving_key.omega.pow(i), P_mul_result));
                            Q_interpolation_points.push_back(std::make_pair(proving_key.omega.pow(i), Q_mul_result));
                        }

                        math::polynomial::polynom<...> P =
                            math::polynomial::Lagrange_interpolation(P_interpolation_points);
                        math::polynomial::polynom<...> Q =
                            math::polynomial::Lagrange_interpolation(Q_interpolation_points);

                        std::fri_commitment_cheme<...> P_commitment();
                        std::fri_commitment_cheme<...> Q_commitment();

                        P_commitment.commit(P);
                        Q_commitment.commit(Q);
                        transcript(P_commitment);
                        transcript(Q_commitment);

                        std::array<typename TCurve::scalar_field_type::value_type, 6> alphas;
                        for (std::size_t i = 0; i < 6; i++) {
                            hashes::sha2::digest_type alpha_bytes =
                                transcript.get_challenge<transcript_manifest::challenges_ids::alpha, i>();
                            alphas[i] = (algebra::marshalling<typename TCurve::scalar_field_type>(alpha_bytes));
                        }

                        std::array<math::polynomial::polynom<...>, 6> F;
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

                        math::polynomial::polynom<...> F_consolidated = 0;
                        for (std::size_t i = 0; i < 6; i++) {
                            F_consolidated = a[i] * F[i];
                        }

                        math::polynomial::polynom<...> T_consolidated = F_consolidated / Z;

                        std::vector<math::polynomial::polynom<...>> T(N_perm + 2);
                        T = separate_T(T_consolidated);

                        std::vector<std::fri_commitment_cheme<...>> T_commitments(N_perm + 2);
                        for (std::size_t i = 0; i < N_perm + 2) {
                            T_commitments[i].commit(T[i]);
                        }

                        ...

                            typename types_policy::proof_type proof =
                                typename types_policy::proof_type(std::move(f_commitments), std::move(P_commitment),
                                                                  std::move(Q_commitment), std::move(T_commitments));

                        return proof;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP
