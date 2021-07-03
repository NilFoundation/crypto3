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

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_VERIFIER_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_VERIFIER_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark.hpp>

#include <nil/crypto3/zk/snark/algorithms/verify.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename CurveType>
                class bacs_ppzksnark_process_verification_key {
                    typedef detail::bacs_ppzksnark_policy<CurveType> policy_type;

                public:
                    typedef typename policy_type::circuit_type circuit_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    static inline processed_verification_key_type
                        process(const verification_key_type &verification_key) {
                        return r1cs_ppzksnark_process_verification_key<CurveType>::process(verification_key);
                    }
                };

                /*
                 Below are four variants of verifier algorithm for the BACS ppzkSNARK.

                 These are the four cases that arise from the following two choices:

                 (1) The verifier accepts a (non-processed) verification key or, instead, a processed
                 verification key. In the latter case, we call the algorithm an "online verifier".

                 (2) The verifier checks for "weak" input consistency or, instead, "strong" input
                 consistency. Strong input consistency requires that |primary_input| = C.num_inputs, whereas
                     weak input consistency requires that |primary_input| <= C.num_inputs (and
                     the primary input is implicitly padded with zeros up to length C.num_inputs).
                 */

                template<typename CurveType>
                class bacs_ppzksnark_verifier_weak_input_consistency {
                    typedef detail::bacs_ppzksnark_policy<CurveType> policy_type;

                    using r1cs_ppzksnark_weak_proof_system =
                        r1cs_ppzksnark<CurveType,
                                       r1cs_ppzksnark_generator<CurveType>,
                                       r1cs_ppzksnark_prover<CurveType>,
                                       r1cs_ppzksnark_verifier_weak_input_consistency<CurveType>>;

                public:
                    typedef typename policy_type::circuit_type circuit_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    /**
                     * A verifier algorithm for the BACS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has weak input consistency.
                     */
                    static inline bool process(const verification_key_type &verification_key,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        return verify<r1cs_ppzksnark_weak_proof_system>(
                            bacs_ppzksnark_process_verification_key<CurveType>::process(verification_key),
                            primary_input,
                            proof);
                    }

                    /**
                     * A verifier algorithm for the BACS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has weak input consistency.
                     */
                    static inline bool process(const processed_verification_key_type &processed_verification_key,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        return verify<r1cs_ppzksnark_weak_proof_system>(
                            processed_verification_key, primary_input, proof);
                    }
                };

                template<typename CurveType>
                class bacs_ppzksnark_verifier_strong_input_consistency {
                    typedef detail::bacs_ppzksnark_policy<CurveType> policy_type;

                    using r1cs_ppzksnark_proof_system = r1cs_ppzksnark<CurveType>;

                public:
                    typedef typename policy_type::circuit_type circuit_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    /**
                     * A verifier algorithm for the BACS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has strong input consistency.
                     */
                    static inline bool process(const verification_key_type &verification_key,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        return verify<r1cs_ppzksnark_proof_system>(
                            bacs_ppzksnark_process_verification_key<CurveType>::process(verification_key),
                            primary_input,
                            proof);
                    }

                    /**
                     * A verifier algorithm for the BACS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has strong input consistency.
                     */
                    static inline bool process(const processed_verification_key_type &processed_verification_key,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        return verify<r1cs_ppzksnark_proof_system>(processed_verification_key, primary_input, proof);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_VERIFIER_HPP
