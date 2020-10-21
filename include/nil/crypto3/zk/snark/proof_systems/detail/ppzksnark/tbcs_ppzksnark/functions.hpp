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
// @file Declaration of interfaces for a ppzkSNARK for TBCS.
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
// (1) a TBCS-to-USCS reduction, and
// (2) a ppzkSNARK for USCS.
//
//
// Acronyms:
//
// - TBCS = "Two-input Boolean Circuit Satisfiability"
// - USCS = "Unitary-Square Constraint System"
// - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TBCS_PPZKSNARK_FUNCTIONS_HPP
#define CRYPTO3_ZK_TBCS_PPZKSNARK_FUNCTIONS_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/tbcs_ppzksnark/params.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark/uscs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct tbcs_ppzksnark_functions {

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the TBCS ppzkSNARK.
                         */
                        struct proving_key {
                            typedef typename CurveType::scalar_field_type FieldType;

                            circuit circuit;
                            uscs_ppzksnark_proving_key<CurveType> uscs_pk;

                            proving_key() {};
                            proving_key(const proving_key<CurveType> &other) = default;
                            proving_key(proving_key<CurveType> &&other) = default;
                            proving_key(const circuit &circuit,
                                                       const uscs_ppzksnark_proving_key<CurveType> &uscs_pk) :
                                circuit(circuit),
                                uscs_pk(uscs_pk) {
                            }
                            proving_key(circuit &&circuit,
                                                       uscs_ppzksnark_proving_key<CurveType> &&uscs_pk) :
                                circuit(std::move(circuit)),
                                uscs_pk(std::move(uscs_pk)) {
                            }

                            proving_key<CurveType> &operator=(const proving_key<CurveType> &other) = default;

                            std::size_t G1_size() const {
                                return uscs_pk.G1_size();
                            }

                            std::size_t G2_size() const {
                                return uscs_pk.G2_size();
                            }

                            std::size_t G1_sparse_size() const {
                                return uscs_pk.G1_sparse_size();
                            }

                            std::size_t G2_sparse_size() const {
                                return uscs_pk.G2_sparse_size();
                            }

                            std::size_t size_in_bits() const {
                                return uscs_pk.size_in_bits();
                            }

                            bool operator==(const proving_key<CurveType> &other) const {
                                return (this->circuit == other.circuit && this->uscs_pk == other.uscs_pk);
                            }
                        };

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the TBCS ppzkSNARK.
                         */
                        using verification_key = uscs_ppzksnark_verification_key<CurveType>;

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the TBCS ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        using processed_verification_key = uscs_ppzksnark_processed_verification_key<CurveType>;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the TBCS ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        struct keypair {
                            proving_key<CurveType> pk;
                            verification_key<CurveType> vk;

                            keypair() {};
                            keypair(keypair<CurveType> &&other) = default;
                            keypair(const proving_key<CurveType> &pk,
                                                   const verification_key<CurveType> &vk) :
                                pk(pk),
                                vk(vk) {
                            }

                            keypair(proving_key<CurveType> &&pk,
                                                   verification_key<CurveType> &&vk) :
                                pk(std::move(pk)),
                                vk(std::move(vk)) {
                            }
                        };

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the TBCS ppzkSNARK.
                         */
                        using proof = uscs_ppzksnark_proof<CurveType>;

                        /***************************** Main algorithms *******************************/

                        /*
                         Below are four variants of verifier algorithm for the TBCS ppzkSNARK.

                         These are the four cases that arise from the following two choices:

                         (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
                             In the latter case, we call the algorithm an "online verifier".

                         (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                             Strong input consistency requires that |primary_input| = C.num_inputs, whereas
                             weak input consistency requires that |primary_input| <= C.num_inputs (and
                             the primary input is implicitly padded with zeros up to length C.num_inputs).
                         */

                        /**
                         * A generator algorithm for the TBCS ppzkSNARK.
                         *
                         * Given a TBCS circuit C, this algorithm produces proving and verification keys for C.
                         */
                        static keypair<CurveType> generator(const circuit &circuit) {
                            typedef typename CurveType::scalar_field_type FieldType;

                            const uscs_constraint_system<FieldType> uscs_cs = tbcs_to_uscs_instance_map<FieldType>(circuit);
                            const uscs_ppzksnark_keypair<CurveType> uscs_keypair = uscs_ppzksnark_generator<CurveType>(uscs_cs);

                            return keypair<CurveType>(proving_key<CurveType>(circuit, uscs_keypair.pk),
                                                               uscs_keypair.vk);
                        }

                        /**
                         * A prover algorithm for the TBCS ppzkSNARK.
                         *
                         * Given a TBCS primary input X and a TBCS auxiliary input Y, this algorithm
                         * produces a proof (of knowledge) that attests to the following statement:
                         *               ``there exists Y such that C(X,Y)=0''.
                         * Above, C is the TBCS circuit that was given as input to the generator algorithm.
                         */
                        static proof<CurveType> prover(const proving_key<CurveType> &pk,
                                                       const primary_input &primary_input,
                                                       const auxiliary_input &auxiliary_input) {
                            typedef typename CurveType::scalar_field_type FieldType;

                            const uscs_variable_assignment<FieldType> uscs_va =
                                tbcs_to_uscs_witness_map<FieldType>(pk.circuit, primary_input, auxiliary_input);
                            const uscs_primary_input<FieldType> uscs_pi =
                                algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                            const uscs_auxiliary_input<FieldType> uscs_ai(
                                uscs_va.begin() + primary_input.size(),
                                uscs_va.end());    // TODO: faster to just change bacs_to_r1cs_witness_map into two :(
                            const uscs_ppzksnark_proof<CurveType> uscs_proof =
                                uscs_ppzksnark_prover<CurveType>(pk.uscs_pk, uscs_pi, uscs_ai);

                            return uscs_proof;
                        }

                        /**
                         * Convert a (non-processed) verification key into a processed verification key.
                         */
                        static processed_verification_key<CurveType>
                            verifier_process_vk(const verification_key<CurveType> &vk) {
                            const processed_verification_key<CurveType> pvk =
                                uscs_ppzksnark_verifier_process_vk<CurveType>(vk);

                            return pvk;
                        }

                        /**
                         * A verifier algorithm for the TBCS ppzkSNARK that:
                         * (1) accepts a non-processed verification key, and
                         * (2) has weak input consistency.
                         */
                        static bool verifier_weak_IC(const verification_key<CurveType> &vk,
                                                     const primary_input &primary_input,
                                                     const proof<CurveType> &proof) {
                            typedef typename CurveType::scalar_field_type FieldType;
                            const uscs_primary_input<FieldType> uscs_input =
                                algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                            const processed_verification_key<CurveType> pvk =
                                verifier_process_vk<CurveType>(vk);
                            const bool bit = uscs_ppzksnark_online_verifier_weak_IC<CurveType>(pvk, uscs_input, proof);

                            return bit;
                        }

                        /**
                         * A verifier algorithm for the TBCS ppzkSNARK that:
                         * (1) accepts a non-processed verification key, and
                         * (2) has strong input consistency.
                         */
                        static bool verifier_strong_IC(const verification_key<CurveType> &vk,
                                                       const primary_input &primary_input,
                                                       const proof<CurveType> &proof) {
                            typedef typename CurveType::scalar_field_type FieldType;
                            const processed_verification_key<CurveType> pvk =
                                verifier_process_vk<CurveType>(vk);
                            const uscs_primary_input<FieldType> uscs_input =
                                algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                            const bool bit = uscs_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, uscs_input, proof);

                            return bit;
                        }

                        /**
                         * A verifier algorithm for the TBCS ppzkSNARK that:
                         * (1) accepts a processed verification key, and
                         * (2) has weak input consistency.
                         */
                        static bool online_verifier_weak_IC(const processed_verification_key<CurveType> &pvk,
                                                            const primary_input &primary_input,
                                                            const proof<CurveType> &proof) {
                            typedef typename CurveType::scalar_field_type FieldType;
                            const uscs_primary_input<FieldType> uscs_input =
                                algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                            const bool bit = uscs_ppzksnark_online_verifier_weak_IC<CurveType>(pvk, uscs_input, proof);

                            return bit;
                        }

                        /**
                         * A verifier algorithm for the TBCS ppzkSNARK that:
                         * (1) accepts a processed verification key, and
                         * (2) has strong input consistency.
                         */
                        static bool online_verifier_strong_IC(const processed_verification_key<CurveType> &pvk,
                                                              const primary_input &primary_input,
                                                              const proof<CurveType> &proof) {
                            typedef typename CurveType::scalar_field_type FieldType;
                            const uscs_primary_input<FieldType> uscs_input =
                                algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                            const bool bit = uscs_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, uscs_input, proof);

                            return bit;
                        }

                    };
                }    // namespace detail
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_FUNCTIONS_HPP
