//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_R1CS_PPZKSNARK_BASIC_VERIFIER_HPP
#define CRYPTO3_R1CS_PPZKSNARK_BASIC_VERIFIER_HPP

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_ppzksnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_process_verification_key {
                    typedef detail::r1cs_ppzksnark_policy<CurveType> policy_type;

                    using g2_type = typename CurveType::template g2_type<>;

                public:
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    static inline processed_verification_key_type
                        process(const verification_key_type &verification_key) {

                        processed_verification_key_type processed_verification_key;
                        processed_verification_key.pp_G2_one_precomp =
                            precompute_g2<CurveType>(g2_type::value_type::one());
                        processed_verification_key.vk_alphaA_g2_precomp =
                            precompute_g2<CurveType>(verification_key.alphaA_g2);
                        processed_verification_key.vk_alphaB_g1_precomp =
                            precompute_g1<CurveType>(verification_key.alphaB_g1);
                        processed_verification_key.vk_alphaC_g2_precomp =
                            precompute_g2<CurveType>(verification_key.alphaC_g2);
                        processed_verification_key.vk_rC_Z_g2_precomp =
                            precompute_g2<CurveType>(verification_key.rC_Z_g2);
                        processed_verification_key.vk_gamma_g2_precomp =
                            precompute_g2<CurveType>(verification_key.gamma_g2);
                        processed_verification_key.vk_gamma_beta_g1_precomp =
                            precompute_g1<CurveType>(verification_key.gamma_beta_g1);
                        processed_verification_key.vk_gamma_beta_g2_precomp =
                            precompute_g2<CurveType>(verification_key.gamma_beta_g2);

                        processed_verification_key.encoded_IC_query = verification_key.encoded_IC_query;

                        return processed_verification_key;
                    }
                };

                template<typename CurveType>
                class r1cs_ppzksnark_verifier_weak_input_consistency {
                    typedef detail::r1cs_ppzksnark_policy<CurveType> policy_type;

                    using pairing_policy = pairing::pairing_policy<CurveType>;
                    using g1_type = typename CurveType::template g1_type<>;
                    using g2_type = typename CurveType::template g2_type<>;
                    using gt_type = typename CurveType::gt_type;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;
                    using gt_value_type = typename gt_type::value_type;
                    using g1_precomputed_type = typename pairing_policy::g1_precomputed_type;
                    using g2_precomputed_type = typename pairing_policy::g2_precomputed_type;

                public:
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;
                    typedef typename policy_type::proof_type proof_type;

                    /**
                     * A verifier algorithm for the R1CS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has weak input consistency.
                     */
                    static inline bool process(const verification_key_type &verification_key,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        return process(r1cs_ppzksnark_process_verification_key<CurveType>::process(verification_key),
                                       primary_input, proof);
                    }

                    /**
                     * A verifier algorithm for the R1CS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has weak input consistency.
                     */
                    static inline bool process(const processed_verification_key_type &processed_verification_key,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {

                        assert(processed_verification_key.encoded_IC_query.domain_size() >= primary_input.size());

                        const container::accumulation_vector<g1_type> accumulated_IC =
                            processed_verification_key.encoded_IC_query.accumulate_chunk(primary_input.begin(),
                                                                                         primary_input.end(), 0);
                        const g1_value_type &acc = accumulated_IC.first;

                        bool result = true;

                        if (!proof.is_well_formed()) {
                            result = false;
                        }
                        g1_precomputed_type proof_g_A_g_precomp = precompute_g1<CurveType>(proof.g_A.g);
                        g1_precomputed_type proof_g_A_h_precomp = precompute_g1<CurveType>(proof.g_A.h);
                        typename gt_type::value_type kc_A_1 = miller_loop<CurveType>(
                            proof_g_A_g_precomp, processed_verification_key.vk_alphaA_g2_precomp);
                        typename gt_type::value_type kc_A_2 =
                            miller_loop<CurveType>(proof_g_A_h_precomp, processed_verification_key.pp_G2_one_precomp);
                        gt_value_type kc_A = final_exponentiation<CurveType>(kc_A_1 * kc_A_2.unitary_inversed());
                        if (kc_A != gt_value_type::one()) {
                            result = false;
                        }

                        g2_precomputed_type proof_g_B_g_precomp = precompute_g2<CurveType>(proof.g_B.g);
                        g1_precomputed_type proof_g_B_h_precomp = precompute_g1<CurveType>(proof.g_B.h);
                        typename gt_type::value_type kc_B_1 = miller_loop<CurveType>(
                            processed_verification_key.vk_alphaB_g1_precomp, proof_g_B_g_precomp);
                        typename gt_type::value_type kc_B_2 =
                            miller_loop<CurveType>(proof_g_B_h_precomp, processed_verification_key.pp_G2_one_precomp);
                        gt_value_type kc_B = final_exponentiation<CurveType>(kc_B_1 * kc_B_2.unitary_inversed());
                        if (kc_B != gt_value_type::one()) {
                            result = false;
                        }

                        g1_precomputed_type proof_g_C_g_precomp = precompute_g1<CurveType>(proof.g_C.g);
                        g1_precomputed_type proof_g_C_h_precomp = precompute_g1<CurveType>(proof.g_C.h);
                        typename gt_type::value_type kc_C_1 = miller_loop<CurveType>(
                            proof_g_C_g_precomp, processed_verification_key.vk_alphaC_g2_precomp);
                        typename gt_type::value_type kc_C_2 =
                            miller_loop<CurveType>(proof_g_C_h_precomp, processed_verification_key.pp_G2_one_precomp);
                        gt_value_type kc_C = final_exponentiation<CurveType>(kc_C_1 * kc_C_2.unitary_inversed());
                        if (kc_C != gt_value_type::one()) {
                            result = false;
                        }

                        // check that g^((A+acc)*B)=g^(H*\Prod(t-\sigma)+C)
                        // equivalently, via pairings, that e(g^(A+acc), g^B) = e(g^H, g^Z) + e(g^C, g^1)
                        g1_precomputed_type proof_g_A_g_acc_precomp = precompute_g1<CurveType>(proof.g_A.g + acc);
                        g1_precomputed_type proof_g_H_precomp = precompute_g1<CurveType>(proof.g_H);
                        typename gt_type::value_type QAP_1 =
                            miller_loop<CurveType>(proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                        typename gt_type::value_type QAP_23 = double_miller_loop<CurveType>(
                            proof_g_H_precomp, processed_verification_key.vk_rC_Z_g2_precomp, proof_g_C_g_precomp,
                            processed_verification_key.pp_G2_one_precomp);
                        gt_value_type QAP = final_exponentiation<CurveType>(QAP_1 * QAP_23.unitary_inversed());
                        if (QAP != gt_value_type::one()) {
                            result = false;
                        }

                        g1_precomputed_type proof_g_K_precomp = precompute_g1<CurveType>(proof.g_K);
                        g1_precomputed_type proof_g_A_g_acc_C_precomp =
                            precompute_g1<CurveType>((proof.g_A.g + acc) + proof.g_C.g);
                        typename gt_type::value_type K_1 =
                            miller_loop<CurveType>(proof_g_K_precomp, processed_verification_key.vk_gamma_g2_precomp);
                        typename gt_type::value_type K_23 = double_miller_loop<CurveType>(
                            proof_g_A_g_acc_C_precomp, processed_verification_key.vk_gamma_beta_g2_precomp,
                            processed_verification_key.vk_gamma_beta_g1_precomp, proof_g_B_g_precomp);
                        gt_value_type K = final_exponentiation<CurveType>(K_1 * K_23.unitary_inversed());
                        if (K != gt_value_type::one()) {
                            result = false;
                        }

                        return result;
                    }
                };

                template<typename CurveType>
                class r1cs_ppzksnark_verifier_strong_input_consistency {
                    typedef detail::r1cs_ppzksnark_policy<CurveType> policy_type;

                public:
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;
                    typedef typename policy_type::proof_type proof_type;

                    /**
                     * A verifier algorithm for the R1CS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has strong input consistency.
                     */
                    static inline bool process(const verification_key_type &verification_key,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        return process(r1cs_ppzksnark_process_verification_key<CurveType>::process(verification_key),
                                       primary_input, proof);
                    }

                    /**
                     * A verifier algorithm for the R1CS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has strong input consistency.
                     */
                    static inline bool process(const processed_verification_key_type &processed_verification_key,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        bool result = true;

                        if (processed_verification_key.encoded_IC_query.domain_size() != primary_input.size()) {
                            result = false;
                        } else {
                            result = r1cs_ppzksnark_verifier_weak_input_consistency<CurveType>::process(
                                processed_verification_key, primary_input, proof);
                        }

                        return result;
                    }
                };

                // /**
                //  *
                //  * A verifier algorithm for the R1CS ppzkSNARK that:
                //  * (1) accepts a non-processed verification key,
                //  * (2) has weak input consistency, and
                //  * (3) uses affine coordinates for elliptic-curve computations.
                //  */
                // template<typename CurveType>
                // class r1cs_ppzksnark_affine_verifier_weak_input_consistency {
                //     typedef detail::r1cs_ppzksnark_policy<CurveType> policy_type;

                //     using pairing_policy = typename CurveType::pairing;
                //     using g1_type = typename CurveType::template g1_type<>;
                //     using g2_type = typename CurveType::template g2_type<>;
                //     using gt_type = typename CurveType::gt_type;
                //     using g1_value_type = typename g1_type::value_type;
                //     using g2_value_type = typename g2_type::value_type;
                //     using gt_value_type = typename gt_type::value_type;
                //     using scalar_field_type = typename CurveType::scalar_field_type;
                //     using g1_precomputed_type = typename pairing_policy::g1_precomputed_type;
                //     using g2_precomputed_type = typename pairing_policy::g2_precomputed_type;
                //     using affine_ate_g1_precomp = typename pairing_policy::affine_ate_g1_precomp;
                //     using affine_ate_g2_precomp = typename pairing_policy::affine_ate_g2_precomp;

                // public:
                //     typedef typename policy_type::primary_input_type primary_input_type;
                //     typedef typename policy_type::verification_key_type verification_key_type;
                //     typedef typename policy_type::processed_verification_key_type processed_verification_key_type;
                //     typedef typename policy_type::proof_type proof_type;

                //     static inline bool process(const verification_key_type &vk,
                //                                const primary_input_type &primary_input,
                //                                const proof_type &proof) {
                //         typedef typename CurveType::pairing pairing_policy;

                //         assert(vk.encoded_IC_query.domain_size() >= primary_input.size());

                //         affine_ate_g2_precomp pvk_pp_G2_one_precomp =
                //             affine_ate_precompute_g2<CurveType>(g2_value_type::one());
                //         affine_ate_g2_precomp pvk_vk_alphaA_g2_precomp =
                //             affine_ate_precompute_g2<CurveType>(vk.alphaA_g2);
                //         affine_ate_g1_precomp pvk_vk_alphaB_g1_precomp =
                //             affine_ate_precompute_g1<CurveType>(vk.alphaB_g1);
                //         affine_ate_g2_precomp pvk_vk_alphaC_g2_precomp =
                //             affine_ate_precompute_g2<CurveType>(vk.alphaC_g2);
                //         affine_ate_g2_precomp pvk_vk_rC_Z_g2_precomp =
                //             affine_ate_precompute_g2<CurveType>(vk.rC_Z_g2);
                //         affine_ate_g2_precomp pvk_vk_gamma_g2_precomp =
                //             affine_ate_precompute_g2<CurveType>(vk.gamma_g2);
                //         affine_ate_g1_precomp pvk_vk_gamma_beta_g1_precomp =
                //             affine_ate_precompute_g1<CurveType>(vk.gamma_beta_g1);
                //         affine_ate_g2_precomp pvk_vk_gamma_beta_g2_precomp =
                //             affine_ate_precompute_g2<CurveType>(vk.gamma_beta_g2);

                //         const accumulation_vector<g1_type> accumulated_IC =
                //             vk.encoded_IC_query.accumulate_chunk<scalar_field_type>(primary_input.begin(),
                //                                                                              primary_input.end(), 0);
                //         assert(accumulated_IC.is_fully_accumulated());
                //         const g1_value_type &acc = accumulated_IC.first;

                //         bool result = true;
                //         affine_ate_g1_precomp proof_g_A_g_precomp = affine_ate_precompute_g1<CurveType>(proof.g_A.g);
                //         affine_ate_g1_precomp proof_g_A_h_precomp = affine_ate_precompute_g1<CurveType>(proof.g_A.h);
                //         typename gt_type::value_type kc_A_miller = affine_ate_e_over_e_miller_loop<CurveType>(
                //             proof_g_A_g_precomp, pvk_vk_alphaA_g2_precomp, proof_g_A_h_precomp,
                //             pvk_pp_G2_one_precomp);
                //         gt_value_type kc_A = final_exponentiation<CurveType>(kc_A_miller);

                //         if (kc_A != gt_value_type::one()) {
                //             result = false;
                //         }

                //         affine_ate_g2_precomp proof_g_B_g_precomp =
                //             affine_ate_precompute_g2<CurveType>(proof.g_B.g);
                //         affine_ate_g1_precomp proof_g_B_h_precomp =
                //             affine_ate_precompute_g1<CurveType>(proof.g_B.h);
                //         typename gt_type::value_type kc_B_miller = affine_ate_e_over_e_miller_loop<CurveType>(
                //             pvk_vk_alphaB_g1_precomp, proof_g_B_g_precomp, proof_g_B_h_precomp,
                //             pvk_pp_G2_one_precomp);
                //         gt_value_type kc_B = final_exponentiation<CurveType>(kc_B_miller);
                //         if (kc_B != gt_value_type::one()) {
                //             result = false;
                //         }

                //         affine_ate_g1_precomp proof_g_C_g_precomp =
                //             affine_ate_precompute_g1<CurveType>(proof.g_C.g);
                //         affine_ate_g1_precomp proof_g_C_h_precomp =
                //             affine_ate_precompute_g1<CurveType>(proof.g_C.h);
                //         typename gt_type::value_type kc_C_miller = affine_ate_e_over_e_miller_loop<CurveType>(
                //             proof_g_C_g_precomp, pvk_vk_alphaC_g2_precomp, proof_g_C_h_precomp,
                //             pvk_pp_G2_one_precomp);
                //         gt_value_type kc_C = final_exponentiation<CurveType>(kc_C_miller);
                //         if (kc_C != gt_value_type::one()) {
                //             result = false;
                //         }

                //         affine_ate_g1_precomp proof_g_A_g_acc_precomp =
                //             affine_ate_precompute_g1<CurveType>(proof.g_A.g + acc);
                //         affine_ate_g1_precomp proof_g_H_precomp = affine_ate_precompute_g1<CurveType>(proof.g_H);
                //         typename gt_type::value_type QAP_miller =
                //             affine_ate_e_times_e_over_e_miller_loop<CurveType>(
                //                 proof_g_H_precomp, pvk_vk_rC_Z_g2_precomp, proof_g_C_g_precomp,
                //                 pvk_pp_G2_one_precomp, proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                //         gt_value_type QAP = final_exponentiation<CurveType>(QAP_miller);
                //         if (QAP != gt_value_type::one()) {
                //             result = false;
                //         }

                //         affine_ate_g1_precomp proof_g_K_precomp = affine_ate_precompute_g1<CurveType>(proof.g_K);
                //         affine_ate_g1_precomp proof_g_A_g_acc_C_precomp =
                //             affine_ate_precompute_g1<CurveType>((proof.g_A.g + acc) + proof.g_C.g);
                //         typename gt_type::value_type K_miller =
                //             affine_ate_e_times_e_over_e_miller_loop<CurveType>(
                //                 proof_g_A_g_acc_C_precomp, pvk_vk_gamma_beta_g2_precomp,
                //                 pvk_vk_gamma_beta_g1_precomp, proof_g_B_g_precomp, proof_g_K_precomp,
                //                 pvk_vk_gamma_g2_precomp);
                //         gt_value_type K = final_exponentiation<CurveType>(K_miller);
                //         if (K != gt_value_type::one()) {
                //             result = false;
                //         }

                //         return result;
                //     }
                // };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_VERIFIER_HPP
