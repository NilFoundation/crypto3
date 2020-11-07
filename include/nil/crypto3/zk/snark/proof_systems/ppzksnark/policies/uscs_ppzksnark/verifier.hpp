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

#ifndef CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_VERIFIER_HPP
#define CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_VERIFIER_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs.hpp>

//#include <nil/crypto3/algebra/multiexp/multiexp.hpp>

//#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/reductions/uscs_to_ssp.hpp>
#include <nil/crypto3/zk/snark/relations/arithmetic_programs/ssp.hpp>
#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/uscs_ppzksnark/types_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    /*
                     Below are four variants of verifier algorithm for the USCS ppzkSNARK.

                     These are the four cases that arise from the following two choices:

                     (1) The verifier accepts a (non-processed) verification key or, instead, a processed
                     verification key. In the latter case, we call the algorithm an "online verifier".

                     (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                         Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                         weak input consistency requires that |primary_input| <= CS.num_inputs (and
                         the primary input is implicitly padded with zeros up to length CS.num_inputs).
                     */

                    /**
                     * Convert a (non-processed) verification key into a processed verification key.
                     */
                    class uscs_ppzksnark_verifier_process_vk {
                        using types_policy = detail::uscs_ppzksnark_types_policy;
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
                        processed_verification_key operator()(const verification_key_type &vk) {

                            processed_verification_key_type pvk;

                            pvk.pp_G1_one_precomp =
                                CurveType::precompute_g1(typename CurveType::g1_type::value_type::one());
                            pvk.pp_G2_one_precomp =
                                CurveType::precompute_g2(typename CurveType::g2_type::value_type::one());

                            pvk.vk_tilde_g2_precomp = CurveType::precompute_g2(vk.tilde_g2);
                            pvk.vk_alpha_tilde_g2_precomp = CurveType::precompute_g2(vk.alpha_tilde_g2);
                            pvk.vk_Z_g2_precomp = CurveType::precompute_g2(vk.Z_g2);

                            pvk.pairing_of_g1_and_g2 =
                                miller_loop<CurveType>(pvk.pp_G1_one_precomp, pvk.pp_G2_one_precomp);

                            pvk.encoded_IC_query = vk.encoded_IC_query;

                            return pvk;
                        }
                    };

                    /**
                     * A verifier algorithm for the USCS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has weak input consistency.
                     */
                    class uscs_ppzksnark_online_verifier_weak_IC {
                        using types_policy = detail::uscs_ppzksnark_types_policy;
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
                        bool operator()(const processed_verification_key_type &pvk,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {
                            using pairing_policy = typename CurveType::pairing_policy;

                            assert(pvk.encoded_IC_query.domain_size() >= primary_input.size());

                            const accumulation_vector<typename CurveType::g1_type> accumulated_IC =
                                pvk.encoded_IC_query.template accumulate_chunk<typename CurveType::scalar_field_type>(
                                    primary_input.begin(), primary_input.end(), 0);
                            assert(accumulated_IC.is_fully_accumulated());
                            const typename CurveType::g1_type::value_type &acc = accumulated_IC.first;

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }

                            typename pairing_policy::G1_precomp proof_V_g1_with_acc_precomp =
                                pairing_policy::precompute_g1(proof.V_g1 + acc);
                            typename pairing_policy::G2_precomp proof_V_g2_precomp =
                                pairing_policy::precompute_g2(proof.V_g2);
                            typename pairing_policy::Fqk_type V_1 =
                                pairing_policy::miller_loop(proof_V_g1_with_acc_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::Fqk_type V_2 =
                                pairing_policy::miller_loop(pvk.pp_G1_one_precomp, proof_V_g2_precomp);
                            typename CurveType::gt_type V =
                                pairing_policy::final_exponentiation(V_1 * V_2.unitary_inversed());

                            if (V != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::G1_precomp proof_H_g1_precomp =
                                pairing_policy::precompute_g1(proof.H_g1);
                            typename pairing_policy::Fqk_type SSP_1 =
                                pairing_policy::miller_loop(proof_V_g1_with_acc_precomp, proof_V_g2_precomp);
                            typename pairing_policy::Fqk_type SSP_2 =
                                pairing_policy::miller_loop(proof_H_g1_precomp, pvk.vk_Z_g2_precomp);
                            typename CurveType::gt_type SSP = pairing_policy::final_exponentiation(
                                SSP_1.unitary_inversed() * SSP_2 * pvk.pairing_of_g1_and_g2);

                            if (SSP != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::G1_precomp proof_V_g1_precomp =
                                pairing_policy::precompute_g1(proof.V_g1);
                            typename pairing_policy::G1_precomp proof_alpha_V_g1_precomp =
                                pairing_policy::precompute_g1(proof.alpha_V_g1);
                            typename pairing_policy::Fqk_type alpha_V_1 =
                                pairing_policy::miller_loop(proof_V_g1_precomp, pvk.vk_alpha_tilde_g2_precomp);
                            typename pairing_policy::Fqk_type alpha_V_2 =
                                pairing_policy::miller_loop(proof_alpha_V_g1_precomp, pvk.vk_tilde_g2_precomp);
                            typename CurveType::gt_type alpha_V =
                                pairing_policy::final_exponentiation(alpha_V_1 * alpha_V_2.unitary_inversed());

                            if (alpha_V != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            return result;
                        }
                    };

                    /**
                     * A verifier algorithm for the USCS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has weak input consistency.
                     */
                    class uscs_ppzksnark_verifier_weak_IC {
                        using types_policy = detail::uscs_ppzksnark_types_policy;
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
                        bool operator()(const verification_key_type &vk,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {

                            processed_verification_key_type pvk = uscs_ppzksnark_verifier_process_vk(vk);
                            bool result = uscs_ppzksnark_online_verifier_weak_IC(pvk, primary_input, proof);
                            return result;
                        }
                    };

                    /**
                     * A verifier algorithm for the USCS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has strong input consistency.
                     */
                    class uscs_ppzksnark_online_verifier_strong_IC {
                        using types_policy = detail::uscs_ppzksnark_types_policy;
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
                        bool operator()(const processed_verification_key_type &pvk,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {

                            bool result = true;

                            if (pvk.encoded_IC_query.domain_size() != primary_input.size()) {
                                result = false;
                            } else {
                                result = uscs_ppzksnark_online_verifier_weak_IC(pvk, primary_input, proof);
                            }

                            return result;
                        }
                    };

                    /**
                     * A verifier algorithm for the USCS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has strong input consistency.
                     */
                    class uscs_ppzksnark_verifier_strong_IC {
                        using types_policy = detail::uscs_ppzksnark_types_policy;
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
                        bool operator()(const verification_key_type &vk,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {

                            processed_verification_key_type pvk = uscs_ppzksnark_verifier_process_vk(vk);
                            bool result = uscs_ppzksnark_online_verifier_strong_IC(pvk, primary_input, proof);
                            return result;
                        }
                    };

                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_USCS_PPZKSNARK_BASIC_VERIFIER_HPP
