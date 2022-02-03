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

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/snark/commitments/fri_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/types.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, std::size_t lambda, std::size_t m = 2>
                class redshift_verifier {

                    using types_policy = detail::redshift_types_policy<FieldType>;
                    using transcript_manifest = types_policy::prover_fiat_shamir_heuristic_manifest<6>;

                    typedef hashes::sha2<256> merkle_hash_type;
                    typedef hashes::sha2<256> transcript_hash_type;

                    constexpr static const std::size_t k = ...;
                    constexpr static const std::size_t r = ...;

                    constexpr static const typename FieldType::value_type omega =
                        algebra::get_root_of_unity<FieldType>() typedef list_polynomial_commitment_scheme<
                            FieldType, merkle_hash_type, lambda, k, r, m>
                            lpc;

                public:
                    static inline bool process(const types_policy::verification_key_type &verification_key,
                                               const types_policy::primary_input_type &primary_input,
                                               const types_policy::proof_type<lpc> &proof) {

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

                        std::array<typename FieldType::value_type, 3> permutation_argument = 
                            redshift_permutation_argument<typename FieldType>::verify_argument(transcript);

                        constexpr const std::size_t f_parts = 4;
                        std::array<typename FieldType::value_type, f_parts> alphas;
                        for (std::size_t i = 0; i < f_parts; i++) {
                            typename transcript_hash_type::digest_type alpha_bytes =
                                transcript.get_challenge<transcript_manifest::challenges_ids::alpha, i>();
                            alphas[i] = (algebra::marshalling<FieldType>(alpha_bytes));
                        }

                        for (std::size_t i = 0; i < N_perm + 2; i++) {
                            transcript(proof.T_commitments[i]);
                        }

                        typename transcript_hash_type::digest_type upsilon_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::upsilon>();

                        typename FieldType::value_type upsilon = algebra::marshalling<FieldType>(upsilon_bytes);

                        std::array<typename FieldType::value_type, k> fT_evaluation_points = {upsilon};

                        for (std::size_t i = 0; i < N_wires; i++) {
                            if (!lpc::verify_eval(fT_evaluation_points, proof.f_commitments[i], proof.f_lpc_proofs[i],
                                                  ...)) {
                                return false;
                            }
                        }

                        std::array<typename FieldType::value_type, k> PQ_evaluation_points = {upsilon, upsilon * omega};
                        if (!lpc::verify_eval(PQ_evaluation_points, proof.P_commitment, proof.P_lpc_proof, ...)) {
                            return false;
                        }
                        if (!lpc::verify_eval(PQ_evaluation_points, proof.Q_commitment, proof.Q_lpc_proof, ...)) {
                            return false;
                        }

                        for (std::size_t i = 0; i < N_perm + 1; i++) {
                            if (!lpc::verify_eval(fT_evaluation_points, proof.T_commitments[i], proof.T_lpc_proofs[i],
                                                  ...)) {
                                return false;
                            }
                        }

                        std::array<math::polynomial::polynom<typename FieldType::value_type>, f_parts> F;
                        F[0] = permutation_argument[0];
                        F[1] = permutation_argument[1];
                        F[2] = permutation_argument[2];
                        F[3] = 0;

                        for (std::size_t i = 0; i < N_sel; i++) {
                            F[3] += q[i] * ....gate[i];
                        }

                        for (std::size_t i = 0; i < N_const; i++) {
                            F[3] += verification_key.f_c[i];
                        }

                        math::polynomial::polynom<typename FieldType::value_type> T_consolidate;
                        T_consolidate = consolidate_T(T);

                        math::polynomial::polynom<typename FieldType::value_type> F_consolidated = 0;
                        for (std::size_t i = 0; i < f_parts; i++) {
                            F_consolidated += a[i] * F[i];
                        }

                        return (F_consolidated == verification_key.Z * T);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP
