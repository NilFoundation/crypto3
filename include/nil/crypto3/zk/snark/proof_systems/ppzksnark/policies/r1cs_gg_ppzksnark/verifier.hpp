//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for a ppzkSNARK for BACS.
//
// This includes:
// - class for proving key
// - class for verification key
// - class for processed verification key
// - class for key pair (proving key & verification key)
// - class for proof
// - generator algorithm
// - prover algorithm
// - verifier algorithm (with strong or weak input consistency)
// - online verifier algorithm (with strong or weak input consistency)
//
// The implementation is a straightforward combination of:
// (1) a BACS-to-R1CS reduction, and
// (2) a ppzkSNARK for R1CS.
//
//
// Acronyms:
//
// - BACS = "Bilinear Arithmetic Circuit Satisfiability"
// - R1CS = "Rank-1 Constraint System"
// - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_VERIFIER_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_VERIFIER_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

//#include <nil/crypto3/algebra/multiexp/default.hpp>

//#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

//#include <nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_gg_ppzksnark/types_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    /**
                     * Convert a (non-processed) verification key into a processed verification key.
                     */
                    class r1cs_gg_ppzksnark_verifier_process_vk {
                        using types_policy = detail::r1cs_gg_ppzksnark_types_policy;
                    public:

                        using constraint_system_type = typename types_policy::constraint_system;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        template<typename CurveType>
                        processed_verification_key_type operator()(const verification_key_type &verification_key) {

                            using pairing_policy = typename CurveType::pairing_policy;

                            processed_verification_key_type processed_verification_key;
                            processed_verification_key.vk_alpha_g1_beta_g2 = verification_key.alpha_g1_beta_g2;
                            processed_verification_key.vk_gamma_g2_precomp = pairing_policy::precompute_g2(verification_key.gamma_g2);
                            processed_verification_key.vk_delta_g2_precomp = pairing_policy::precompute_g2(verification_key.delta_g2);
                            // processed_verification_key.gamma_ABC_g1 = verification_key.gamma_ABC_g1;
                            // when ready

                            return processed_verification_key;
                        }
                    };

                    /*
                      Below are four variants of verifier algorithm for the R1CS GG-ppzkSNARK.

                      These are the four cases that arise from the following two choices:

                      (1) The verifier accepts a (non-processed) verification key or, instead, a processed
                      verification key. In the latter case, we call the algorithm an "online verifier".

                      (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                      Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                      weak input consistency requires that |primary_input| <= CS.num_inputs (and
                      the primary input is implicitly padded with zeros up to length CS.num_inputs).
                    */

                    /**
                     * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has weak input consistency.
                     */
                    class r1cs_gg_ppzksnark_verifier_weak_IC {
                        using types_policy = detail::r1cs_gg_ppzksnark_types_policy;
                    public:

                        using constraint_system_type = typename types_policy::constraint_system;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        template<typename CurveType>
                        bool operator()(const verification_key_type &verification_key,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {
                            processed_verification_key_type processed_verification_key = 
                                r1cs_gg_ppzksnark_verifier_process_vk<CurveType>(verification_key);
                            bool result = online_verifier_weak_IC<CurveType>(processed_verification_key, primary_input, proof);
                            return result;
                        }
                    };

                    /**
                     * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has strong input consistency.
                     */
                    class r1cs_gg_ppzksnark_verifier_strong_IC {
                        using types_policy = detail::r1cs_gg_ppzksnark_types_policy;
                    public:

                        using constraint_system_type = typename types_policy::constraint_system;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        template<typename CurveType>
                        bool operator()(const verification_key_type &verification_key,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {
                            processed_verification_key_type processed_verification_key = r1cs_gg_ppzksnark_verifier_process_vk(verification_key);
                            bool result = r1cs_gg_ppzksnark_online_verifier_strong_IC(processed_verification_key, primary_input, proof);
                            return result;
                        }
                    };

                    /**
                     * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has weak input consistency.
                     */
                    class r1cs_gg_ppzksnark_online_verifier_weak_IC {
                        using types_policy = detail::r1cs_gg_ppzksnark_types_policy;
                    public:

                        using constraint_system_type = typename types_policy::constraint_system;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        template<typename CurveType>
                        bool operator()(const processed_verification_key_type &processed_verification_key,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {

                            using pairing_policy = typename CurveType::pairing_policy;

                            assert(processed_verification_key.gamma_ABC_g1.domain_size() >= primary_input.size());

                            accumulation_vector<typename CurveType::g1_type> accumulated_IC;
                            /*const accumulation_vector<typename CurveType::g1_type> accumulated_IC
                             = processed_verification_key.gamma_ABC_g1.template accumulate_chunk<typename CurveType::scalar_field_type>(
                                primary_input.begin(), primary_input.end(), 0);*/
                            // uncomment
                            // when accumulate_chunk ready
                            const typename CurveType::g1_type::value_type &acc = accumulated_IC.first;

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }
                            const typename pairing_policy::G1_precomp proof_g_A_precomp =
                                pairing_policy::precompute_g1(proof.g_A);
                            const typename pairing_policy::G2_precomp proof_g_B_precomp =
                                pairing_policy::precompute_g2(proof.g_B);
                            const typename pairing_policy::G1_precomp proof_g_C_precomp =
                                pairing_policy::precompute_g1(proof.g_C);
                            const typename pairing_policy::G1_precomp acc_precomp = pairing_policy::precompute_g1(acc);

                            const typename pairing_policy::Fqk_type::value_type QAP1 =
                                pairing_policy::miller_loop(proof_g_A_precomp, proof_g_B_precomp);
                            const typename pairing_policy::Fqk_type::value_type QAP2 =
                                pairing_policy::double_miller_loop(acc_precomp, processed_verification_key.vk_gamma_g2_precomp,
                                                                   proof_g_C_precomp, processed_verification_key.vk_delta_g2_precomp);
                            const typename CurveType::gt_type QAP =
                                pairing_policy::final_exponentiation(QAP1 * QAP2.unitary_inversed());

                            if (QAP != processed_verification_key.vk_alpha_g1_beta_g2) {
                                result = false;
                            }

                            return result;
                        }
                    };

                    /**
                     * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has strong input consistency.
                     */
                    class r1cs_gg_ppzksnark_online_verifier_strong_IC {
                        using types_policy = detail::r1cs_gg_ppzksnark_types_policy;
                    public:

                        using constraint_system_type = typename types_policy::constraint_system;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        template<typename CurveType>
                        bool operator()(const processed_verification_key_type &processed_verification_key,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {
                            bool result = true;

                            if (processed_verification_key.gamma_ABC_g1.domain_size() != primary_input.size()) {
                                result = false;
                            } else {
                                result = online_verifier_weak_IC(processed_verification_key, primary_input, proof);
                            }

                            return result;
                        }
                    };

                    /**
                     * For debugging purposes (of verifier_component):
                     *
                     * A verifier algorithm for the R1CS GG-ppzkSNARK that:
                     * (1) accepts a non-processed verification key,
                     * (2) has weak input consistency, and
                     * (3) uses affine coordinates for elliptic-curve computations.
                     */
                    class r1cs_gg_ppzksnark_affine_verifier_weak_IC {
                        using types_policy = detail::r1cs_gg_ppzksnark_types_policy;
                    public:

                        using constraint_system_type = typename types_policy::constraint_system;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;
                    
                        template<typename CurveType>
                        bool operator()(const verification_key_type &verification_key,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {

                            using pairing_policy = typename CurveType::pairing_policy;

                            assert(verification_key.gamma_ABC_g1.domain_size() >= primary_input.size());

                            typename pairing_policy::affine_ate_G2_precomp pvk_vk_gamma_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(verification_key.gamma_g2);
                            typename pairing_policy::affine_ate_G2_precomp pvk_vk_delta_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(verification_key.delta_g2);

                            const accumulation_vector<typename CurveType::g1_type> accumulated_IC =
                                verification_key.gamma_ABC_g1.template accumulate_chunk<typename CurveType::scalar_field_type>(
                                    primary_input.begin(), primary_input.end(), 0);
                            const typename CurveType::g1_type::value_type &acc = accumulated_IC.first;

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }

                            const typename pairing_policy::affine_ate_G1_precomp proof_g_A_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_A);
                            const typename pairing_policy::affine_ate_G2_precomp proof_g_B_precomp =
                                pairing_policy::affine_ate_precompute_G2(proof.g_B);
                            const typename pairing_policy::affine_ate_G1_precomp proof_g_C_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_C);
                            const typename pairing_policy::affine_ate_G1_precomp acc_precomp =
                                pairing_policy::affine_ate_precompute_G1(acc);

                            const typename pairing_policy::Fqk::value_type QAP_miller =
                                CurveType::affine_ate_e_times_e_over_e_miller_loop(
                                    acc_precomp, pvk_vk_gamma_g2_precomp, proof_g_C_precomp, pvk_vk_delta_g2_precomp,
                                    proof_g_A_precomp, proof_g_B_precomp);
                            const typename CurveType::gt_type QAP =
                                pairing_policy::final_exponentiation(QAP_miller.unitary_inversed());

                            if (QAP != verification_key.alpha_g1_beta_g2) {
                                result = false;
                            }
                            return result;
                        }
                    };
                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_BASIC_VERIFIER_HPP
