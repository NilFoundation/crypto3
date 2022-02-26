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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>

#include <nil/crypto3/zk/snark/commitments/fri.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>
#include "nil/crypto3/zk/snark/systems/plonk/redshift/detail/redshift_policy.hpp"
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename ParamsType>
                class redshift_verifier {

                    constexpr static const std::size_t witness_columns = ParamsType::witness_columns;
                    constexpr static const std::size_t public_columns = ParamsType::public_columns;
                    using merkle_hash_type = typename ParamsType::commitment_params_type::merkle_hash_type;
                    using transcript_hash_type = typename ParamsType::commitment_params_type::transcript_hash_type;

                    using policy_type = detail::redshift_policy<FieldType, ParamsType>;

                    constexpr static const std::size_t lambda = ParamsType::commitment_params_type::lambda;
                    constexpr static const std::size_t r = ParamsType::commitment_params_type::r;
                    constexpr static const std::size_t m = ParamsType::commitment_params_type::m;

                    constexpr static const std::size_t opening_points_witness = 1;
                    constexpr static const std::size_t opening_points_v_p = 2;
                    constexpr static const std::size_t opening_points_t = 1;

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

                    constexpr static const std::size_t gate_parts = 1;
                    constexpr static const std::size_t permutation_parts = 3;
                    constexpr static const std::size_t f_parts = 9;

                public:
                    static inline bool process(    // const policy_type::verification_key_type &verification_key,
                                                   // const policy_type::primary_input_type &primary_input,
                        const typename policy_type::template proof_type<commitment_scheme_witness_type,
                                                                        commitment_scheme_permutation_type,
                                                                        commitment_scheme_quotient_type> &proof,
                        const typename policy_type::template circuit_short_description<commitment_scheme_witness_type>
                            &short_description) {    // TODO: decsription commitment scheme

                        fiat_shamir_heuristic_sequential<transcript_hash_type> transcript;

                        // 1. Add circuit definition to transcript
                        // transcript(short_description);

                        for (std::size_t i = 0; i < witness_columns; i++) {
                            // transcript(proof.witness_commitments[i]);
                        }

                        /*std::array<typename FieldType::value_type, permutation_parts> permutation_argument =
                            redshift_permutation_argument<FieldType, lpc_type, witness_columns,
                        public_columns>::verify_eval( verifier_transcript, preprocessed_data, short_description, y,
                        proof.witness_evaluation, v_p_at_y, v_p_at_y_shifted, proof.v_perm_commitment);

                        std::array<typename FieldType::value_type, f_parts> alphas =
                                transcript.template challenges<FieldType, f_parts>();

                        for (std::size_t i = 0; i < N_perm + 2; i++) {
                            transcript(proof.T_commitments[i]);
                        }

                        typename FieldType::value_type upsilon =
                            transcript.template challenge<FieldType>();

                        std::array<typename FieldType::value_type, k> fT_evaluation_points = {upsilon};

                        for (std::size_t i = 0; i < N_wires; i++) {
                            if (!lpc::verify_eval(fT_evaluation_points, proof.f_commitments[i], proof.f_lpc_proofs[i],
                                                  ...)) {
                                return false;
                            }
                        }

                        const typename FieldType::value_type omega = algebra::get_root_of_unity<FieldType>();
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

                        std::array<math::polynomial<typename FieldType::value_type>, f_parts> F;
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

                        math::polynomial<typename FieldType::value_type> T_consolidate;
                        T_consolidate = consolidate_T(T);

                        math::polynomial<typename FieldType::value_type> F_consolidated = 0;
                        for (std::size_t i = 0; i < f_parts; i++) {
                            F_consolidated += a[i] * F[i];
                        }

                        return (F_consolidated == verification_key.Z * T);*/
                        return true;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_VERIFIER_HPP
