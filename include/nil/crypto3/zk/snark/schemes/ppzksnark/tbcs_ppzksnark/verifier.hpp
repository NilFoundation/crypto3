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

#ifndef CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_VERIFIER_HPP
#define CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_VERIFIER_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/uscs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/tbcs_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/zk/snark/algorithms/verify.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

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
                class tbcs_ppzksnark_process_verification_key {
                    typedef detail::tbcs_ppzksnark_policy<CurveType> policy_type;

                public:
                    typedef typename policy_type::circuit_type circuit_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    static inline processed_verification_key_type process(const verification_key_type &vk) {
                        return uscs_ppzksnark_process_verification_key<CurveType>::process(vk);
                    }
                };

                template<typename CurveType>
                class tbcs_ppzksnark_verifier_weak_input_consistency {
                    typedef detail::tbcs_ppzksnark_policy<CurveType> policy_type;

                    using uscs_ppzksnark_weak_proof_system = uscs_ppzksnark<CurveType,
                                          uscs_ppzksnark_generator<CurveType>,
                                          uscs_ppzksnark_prover<CurveType>,
                                          uscs_ppzksnark_verifier_weak_input_consistency<CurveType>>;

                public:
                    typedef CurveType curve_type;

                    typedef typename policy_type::circuit_type circuit_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    /**
                     * A verifier algorithm for the TBCS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has weak input consistency.
                     */
                    static inline bool process(const verification_key_type &vk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        typedef typename CurveType::scalar_field_type field_type;
                        const uscs_primary_input<field_type> uscs_input =
                            algebra::convert_bit_vector_to_field_element_vector<field_type>(primary_input);
                        return verify<uscs_ppzksnark_weak_proof_system>(
                            tbcs_ppzksnark_process_verification_key<CurveType>::process(vk), uscs_input, proof);
                    }

                    /**
                     * A verifier algorithm for the TBCS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has weak input consistency.
                     */
                    static inline bool process(const processed_verification_key_type &pvk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {

                        typedef typename CurveType::scalar_field_type field_type;
                        const uscs_primary_input<field_type> uscs_input =
                            algebra::convert_bit_vector_to_field_element_vector<field_type>(primary_input);

                        return verify<uscs_ppzksnark_weak_proof_system>(pvk, uscs_input, proof);
                    }
                };

                template<typename CurveType>
                class tbcs_ppzksnark_verifier_strong_input_consistency {
                    typedef detail::tbcs_ppzksnark_policy<CurveType> policy_type;

                    using uscs_ppzksnark_proof_system = uscs_ppzksnark<CurveType>;
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
                     * A verifier algorithm for the TBCS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has strong input consistency.
                     */
                    static inline bool process(const verification_key_type &vk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        typedef typename CurveType::scalar_field_type field_type;
                        const uscs_primary_input<field_type> uscs_input =
                            algebra::convert_bit_vector_to_field_element_vector<field_type>(primary_input);

                        return verify<uscs_ppzksnark_proof_system>(
                            tbcs_ppzksnark_process_verification_key<CurveType>::process(vk), uscs_input, proof);
                    }

                    /**
                     * A verifier algorithm for the TBCS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has strong input consistency.
                     */
                    static inline bool process(const processed_verification_key_type &pvk,
                                               const primary_input_type &primary_input,
                                               const proof_type &proof) {
                        typedef typename CurveType::scalar_field_type field_type;
                        const uscs_primary_input<field_type> uscs_input =
                            algebra::convert_bit_vector_to_field_element_vector<field_type>(primary_input);

                        return verify<uscs_ppzksnark_proof_system>(pvk, uscs_input, proof);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_VERIFIER_HPP
