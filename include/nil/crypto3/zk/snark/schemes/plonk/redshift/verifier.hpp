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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP

#include <nil/crypto3/zk/snark/commitments/fri_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename TCurve>
                class redshift_verifier {

                    using types_policy = redshift_types_policy<TCurve>;
                    using transcript_manifest = types_policy::prover_fiat_shamir_heuristic_manifest<6>;
                    using constraint_system_type = plonk_constraint_system<typename TCurve::scalar_field_type>;

                public:
                    static inline bool process(const types_policy::verification_key_type &verification_key,
                                               const types_policy::primary_input_type &primary_input,
                                               const types_policy::proof_type &proof) {

                        std::size_t N_wires = ...;
                        std::size_t N_perm = ...;
                        std::size_t N_sel = ...;
                        std::size_t N_const = ...;

                        fiat_shamir_heuristic<transcript_manifest, hashes::sha2> transcript;

                        ... setup_values = ...;
                        transcript(setup_values);

                        for (std::size_t i = 0; i < N_wires; i++) {
                            transcript(proof.f_commitments[i]);
                        }

                        hashes::sha2::digest_type beta_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::beta>();

                        hashes::sha2::digest_type gamma_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::gamma>();

                        typename TCurve::scalar_field_type::value_type beta =
                            algebra::marshalling<TCurve::scalar_field_type>(beta_bytes);
                        typename TCurve::scalar_field_type::value_type gamma =
                            algebra::marshalling<TCurve::scalar_field_type>(gamma_bytes);

                        transcript(proof.P_commitment);
                        transcript(proof.Q_commitment);

                        std::array<typename TCurve::scalar_field_type::value_type, 6> alphas;
                        for (std::size_t i = 0; i < 6; i++) {
                            hashes::sha2::digest_type alpha_bytes =
                                transcript.get_challenge<transcript_manifest::challenges_ids::alpha, i>();
                            alphas[i] = (algebra::marshalling<typename TCurve::scalar_field_type>(alpha_bytes));
                        }

                        for (std::size_t i = 0; i < N_perm + 2; i++) {
                            transcript(proof.T_commitments[i]);
                        }

                        hashes::sha2::digest_type upsilon_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::upsilon>();

                        typename TCurve::scalar_field_type::value_type upsilon =
                            algebra::marshalling<TCurve::scalar_field_type>(upsilon_bytes);

                        ...

                            std::array<math::polynomial::polynom<...>, 6>
                                F;
                        F[0] = verification_key.L_basis[1] * (P - 1);
                        F[1] = verification_key.L_basis[1] * (Q - 1);
                        F[2] = P * p_1 - (P << 1);
                        F[3] = Q * q_1 - (Q << 1);
                        F[4] = verification_key.L_basis[n] * ((P << 1) - (Q << 1));
                        F[5] = verification_key.PI;

                        for (std::size_t i = 0; i < N_sel; i++) {
                            F[5] += q[i] * ....gate[i];
                        }

                        for (std::size_t i = 0; i < N_const; i++) {
                            F[5] += verification_key.f_c[i];
                        }

                        math::polynomial::polynom<...> T_consolidate;
                        T_consolidate = consolidate_T(T);

                        math::polynomial::polynom<...> F_consolidated = 0;
                        for (std::size_t i = 0; i < 6; i++) {
                            F_consolidated = a[i] * F[i];
                        }

                        return (F_consolidated == verification_key.Z * T);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP
