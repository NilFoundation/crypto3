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

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_VERIFIER_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_VERIFIER_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/bacs_ppzksnark/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    using basic_policy = detail::bacs_ppzksnark_basic_policy;
                    
                    using circuit_type = typename basic_policy::circuit;
                    using primary_input_type = typename basic_policy::primary_input;
                    using auxiliary_input_type = typename basic_policy::auxiliary_input;

                    using proving_key_type = typename basic_policy::proving_key;
                    using verification_key_type = typename basic_policy::verification_key;
                    using processed_verification_key_type = typename basic_policy::processed_verification_key;

                    using keypair_type = typename basic_policy::keypair;
                    using proof_type = typename basic_policy::proof;

                    /**
                     * Convert a (non-processed) verification key into a processed verification key.
                     */
                    struct verifier_process_vk {
                        template<typename CurveType>
                        processed_verification_key operator()(const verification_key &vk) {
                            const processed_verification_key pvk = r1cs_ppzksnark<CurveType>::verifier_process_vk(vk);

                            return pvk;
                        }
                    };

                    /**
                     * A verifier algorithm for the BACS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has weak input consistency.
                     */
                    struct verifier_weak_IC {
                        template<typename CurveType>
                        bool operator()(const verification_key &vk,
                                        const primary_input &primary_input,
                                        const proof &proof) {
                            const processed_verification_key pvk = verifier_process_vk(vk);
                            const bool bit =
                                r1cs_ppzksnark<CurveType>::online_verifier_weak_IC(pvk, primary_input, proof);

                            return bit;
                        }
                    };

                    /**
                     * A verifier algorithm for the BACS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has strong input consistency.
                     */
                    struct verifier_strong_IC {
                        template<typename CurveType>
                        bool operator()(const verification_key &vk,
                                            const primary_input &primary_input,
                                            const proof &proof) {

                            const processed_verification_key pvk = verifier_process_vk(vk);
                            const bool bit =
                                r1cs_ppzksnark<CurveType>::online_verifier_strong_IC(pvk, primary_input, proof);

                            return bit;
                        }
                    };

                    /**
                     * A verifier algorithm for the BACS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has weak input consistency.
                     */
                    struct online_verifier_weak_IC {
                        template<typename CurveType>
                        bool operator()(const processed_verification_key &pvk,
                                                        const primary_input &primary_input,
                                                        const proof &proof) {
                            const bool bit =
                                r1cs_ppzksnark<CurveType>::online_verifier_weak_IC(pvk, primary_input, proof);

                            return bit;
                        }
                    };

                    /**
                     * A verifier algorithm for the BACS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has strong input consistency.
                     */
                    struct online_verifier_strong_IC {
                        template<typename CurveType>
                        bool operator()(const processed_verification_key &pvk,
                                                          const primary_input &primary_input,
                                                          const proof &proof) {
                            const bool bit =
                                r1cs_ppzksnark<CurveType>::online_verifier_strong_IC(pvk, primary_input, proof);

                            return bit;
                        }
                    };

                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_VERIFIER_HPP
