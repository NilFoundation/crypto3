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

#ifndef CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_VERIFIER_HPP
#define CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_VERIFIER_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/tbcs_ppzksnark/types_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    /*
                     Below are four variants of verifier algorithm for the TBCS ppzkSNARK.

                     These are the four cases that arise from the following two choices:

                     (1) The verifier accepts a (non-processed) verification key or, instead, a processed
                     verification key. In the latter case, we call the algorithm an "online verifier".

                     (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                         Strong input consistency requires that |primary_input| = C.num_inputs, whereas
                         weak input consistency requires that |primary_input| <= C.num_inputs (and
                         the primary input is implicitly padded with zeros up to length C.num_inputs).
                     */

                    /**
                     * Convert a (non-processed) verification key into a processed verification key.
                     */
                    template<typename CurveType>
                    class tbcs_ppzksnark_verifier_process_vk {
                        using types_policy = detail::tbcs_ppzksnark_types_policy;
                    public:
                        using circuit_type = typename types_policy::circuit;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        static inline processed_verification_key_type process(const verification_key_type &vk) {
                            const processed_verification_key_type pvk = uscs_ppzksnark_verifier_process_vk<CurveType>::process(vk);

                            return pvk;
                        }
                    };

                    /**
                     * A verifier algorithm for the TBCS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has weak input consistency.
                     */
                    template<typename CurveType>
                    class tbcs_ppzksnark_verifier_weak_input_consistency {
                        using types_policy = detail::tbcs_ppzksnark_types_policy;
                    public:
                        using circuit_type = typename types_policy::circuit;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        static inline bool process(const verification_key_type &vk,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {
                            typedef typename CurveType::scalar_field_type field_type;
                            const uscs_primary_input<field_type> uscs_input =
                                algebra::convert_bit_vector_to_field_element_vector<field_type>(primary_input);
                            const processed_verification_key_type pvk = tbcs_ppzksnark_verifier_process_vk(vk)<CurveType>::process;
                            const bool bit = uscs_ppzksnark_online_verifier_weak_input_consistency<CurveType>::process(pvk, uscs_input, proof);

                            return bit;
                        }
                    };

                    /**
                     * A verifier algorithm for the TBCS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has strong input consistency.
                     */
                    template<typename CurveType>
                    class tbcs_ppzksnark_verifier_strong_input_consistency {
                        using types_policy = detail::tbcs_ppzksnark_types_policy;
                    public:
                        using circuit_type = typename types_policy::circuit;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        static inline bool process(const verification_key_type &vk,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {
                            typedef typename CurveType::scalar_field_type field_type;
                            const processed_verification_key pvk = tbcs_ppzksnark_verifier_process_vk<CurveType>::process(vk);
                            const uscs_primary_input<field_type> uscs_input =
                                algebra::convert_bit_vector_to_field_element_vector<field_type>(primary_input);
                            const bool bit =
                                uscs_ppzksnark_online_verifier_strong_input_consistency<CurveType>::process(pvk, uscs_input, proof);

                            return bit;
                        }
                    };

                    /**
                     * A verifier algorithm for the TBCS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has weak input consistency.
                     */
                    template<typename CurveType>
                    class tbcs_ppzksnark_online_verifier_weak_input_consistency {
                        using types_policy = detail::tbcs_ppzksnark_types_policy;
                    public:
                        using circuit_type = typename types_policy::circuit;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        static inline bool process(const processed_verification_key_type &pvk,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {

                            typedef typename CurveType::scalar_field_type field_type;
                            const uscs_primary_input<field_type> uscs_input =
                                algebra::convert_bit_vector_to_field_element_vector<field_type>(primary_input);
                            const bool bit = uscs_ppzksnark_online_verifier_weak_input_consistency<CurveType>::process(pvk, uscs_input, proof);

                            return bit;
                        }
                    };

                    /**
                     * A verifier algorithm for the TBCS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has strong input consistency.
                     */
                    template<typename CurveType>
                    class tbcs_ppzksnark_online_verifier_strong_input_consistency {
                        using types_policy = detail::tbcs_ppzksnark_types_policy;
                    public:
                        using circuit_type = typename types_policy::circuit;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        static inline bool process(const processed_verification_key_type &pvk,
                                        const primary_input_type &primary_input,
                                        const proof_type &proof) {
                            typedef typename CurveType::scalar_field_type field_type;
                            const uscs_primary_input<field_type> uscs_input =
                                algebra::convert_bit_vector_to_field_element_vector<field_type>(primary_input);
                            const bool bit =
                                uscs_ppzksnark_online_verifier_strong_input_consistency<CurveType>::process(pvk, uscs_input, proof);

                            return bit;
                        }
                    };

                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_VERIFIER_HPP
