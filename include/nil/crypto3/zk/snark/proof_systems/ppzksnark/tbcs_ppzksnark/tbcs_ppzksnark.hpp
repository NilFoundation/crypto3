//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

#ifndef TBCS_PPZKSNARK_HPP_
#define TBCS_PPZKSNARK_HPP_

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs/tbcs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/tbcs_ppzksnark/tbcs_ppzksnark_params.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark/uscs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs/tbcs_to_uscs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Proving key ********************************/

                template<typename ppT>
                class tbcs_ppzksnark_proving_key;

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const tbcs_ppzksnark_proving_key<ppT> &pk);

                template<typename ppT>
                std::istream &operator>>(std::istream &in, tbcs_ppzksnark_proving_key<ppT> &pk);

                /**
                 * A proving key for the TBCS ppzkSNARK.
                 */
                template<typename ppT>
                class tbcs_ppzksnark_proving_key {
                public:
                    typedef algebra::Fr<ppT> FieldType;

                    tbcs_ppzksnark_circuit circuit;
                    uscs_ppzksnark_proving_key<ppT> uscs_pk;

                    tbcs_ppzksnark_proving_key() {};
                    tbcs_ppzksnark_proving_key(const tbcs_ppzksnark_proving_key<ppT> &other) = default;
                    tbcs_ppzksnark_proving_key(tbcs_ppzksnark_proving_key<ppT> &&other) = default;
                    tbcs_ppzksnark_proving_key(const tbcs_ppzksnark_circuit &circuit,
                                               const uscs_ppzksnark_proving_key<ppT> &uscs_pk) :
                        circuit(circuit),
                        uscs_pk(uscs_pk) {
                    }
                    tbcs_ppzksnark_proving_key(tbcs_ppzksnark_circuit &&circuit,
                                               uscs_ppzksnark_proving_key<ppT> &&uscs_pk) :
                        circuit(std::move(circuit)),
                        uscs_pk(std::move(uscs_pk)) {
                    }

                    tbcs_ppzksnark_proving_key<ppT> &operator=(const tbcs_ppzksnark_proving_key<ppT> &other) = default;

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

                    void print_size() const {
                        uscs_pk.print_size();
                    }

                    bool operator==(const tbcs_ppzksnark_proving_key<ppT> &other) const;
                    friend std::ostream &operator<<<ppT>(std::ostream &out, const tbcs_ppzksnark_proving_key<ppT> &pk);
                    friend std::istream &operator>><ppT>(std::istream &in, tbcs_ppzksnark_proving_key<ppT> &pk);
                };

                /******************************* Verification key ****************************/

                /**
                 * A verification key for the TBCS ppzkSNARK.
                 */
                template<typename ppT>
                using tbcs_ppzksnark_verification_key = uscs_ppzksnark_verification_key<ppT>;

                /************************ Processed verification key *************************/

                /**
                 * A processed verification key for the TBCS ppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename ppT>
                using tbcs_ppzksnark_processed_verification_key = uscs_ppzksnark_processed_verification_key<ppT>;

                /********************************** Key pair *********************************/

                /**
                 * A key pair for the TBCS ppzkSNARK, which consists of a proving key and a verification key.
                 */
                template<typename ppT>
                class tbcs_ppzksnark_keypair {
                public:
                    tbcs_ppzksnark_proving_key<ppT> pk;
                    tbcs_ppzksnark_verification_key<ppT> vk;

                    tbcs_ppzksnark_keypair() {};
                    tbcs_ppzksnark_keypair(tbcs_ppzksnark_keypair<ppT> &&other) = default;
                    tbcs_ppzksnark_keypair(const tbcs_ppzksnark_proving_key<ppT> &pk,
                                           const tbcs_ppzksnark_verification_key<ppT> &vk) :
                        pk(pk),
                        vk(vk) {
                    }

                    tbcs_ppzksnark_keypair(tbcs_ppzksnark_proving_key<ppT> &&pk,
                                           tbcs_ppzksnark_verification_key<ppT> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {
                    }
                };

                /*********************************** Proof ***********************************/

                /**
                 * A proof for the TBCS ppzkSNARK.
                 */
                template<typename ppT>
                using tbcs_ppzksnark_proof = uscs_ppzksnark_proof<ppT>;

                /***************************** Main algorithms *******************************/

                /**
                 * A generator algorithm for the TBCS ppzkSNARK.
                 *
                 * Given a TBCS circuit C, this algorithm produces proving and verification keys for C.
                 */
                template<typename ppT>
                tbcs_ppzksnark_keypair<ppT> tbcs_ppzksnark_generator(const tbcs_ppzksnark_circuit &circuit);

                /**
                 * A prover algorithm for the TBCS ppzkSNARK.
                 *
                 * Given a TBCS primary input X and a TBCS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that C(X,Y)=0''.
                 * Above, C is the TBCS circuit that was given as input to the generator algorithm.
                 */
                template<typename ppT>
                tbcs_ppzksnark_proof<ppT> tbcs_ppzksnark_prover(const tbcs_ppzksnark_proving_key<ppT> &pk,
                                                                const tbcs_ppzksnark_primary_input &primary_input,
                                                                const tbcs_ppzksnark_auxiliary_input &auxiliary_input);

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
                 * A verifier algorithm for the TBCS ppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename ppT>
                bool tbcs_ppzksnark_verifier_weak_IC(const tbcs_ppzksnark_verification_key<ppT> &vk,
                                                     const tbcs_ppzksnark_primary_input &primary_input,
                                                     const tbcs_ppzksnark_proof<ppT> &proof);

                /**
                 * A verifier algorithm for the TBCS ppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename ppT>
                bool tbcs_ppzksnark_verifier_strong_IC(const tbcs_ppzksnark_verification_key<ppT> &vk,
                                                       const tbcs_ppzksnark_primary_input &primary_input,
                                                       const tbcs_ppzksnark_proof<ppT> &proof);

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename ppT>
                tbcs_ppzksnark_processed_verification_key<ppT>
                    tbcs_ppzksnark_verifier_process_vk(const tbcs_ppzksnark_verification_key<ppT> &vk);

                /**
                 * A verifier algorithm for the TBCS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename ppT>
                bool tbcs_ppzksnark_online_verifier_weak_IC(const tbcs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                            const tbcs_ppzksnark_primary_input &primary_input,
                                                            const tbcs_ppzksnark_proof<ppT> &proof);

                /**
                 * A verifier algorithm for the TBCS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename ppT>
                bool tbcs_ppzksnark_online_verifier_strong_IC(const tbcs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                              const tbcs_ppzksnark_primary_input &primary_input,
                                                              const tbcs_ppzksnark_proof<ppT> &proof);

                template<typename ppT>
                bool tbcs_ppzksnark_proving_key<ppT>::operator==(const tbcs_ppzksnark_proving_key<ppT> &other) const {
                    return (this->circuit == other.circuit && this->uscs_pk == other.uscs_pk);
                }

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const tbcs_ppzksnark_proving_key<ppT> &pk) {
                    out << pk.circuit << OUTPUT_NEWLINE;
                    out << pk.uscs_pk << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename ppT>
                std::istream &operator>>(std::istream &in, tbcs_ppzksnark_proving_key<ppT> &pk) {
                    in >> pk.circuit;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pk.uscs_pk;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename ppT>
                tbcs_ppzksnark_keypair<ppT> tbcs_ppzksnark_generator(const tbcs_ppzksnark_circuit &circuit) {
                    typedef algebra::Fr<ppT> FieldType;

                    const uscs_constraint_system<FieldType> uscs_cs = tbcs_to_uscs_instance_map<FieldType>(circuit);
                    const uscs_ppzksnark_keypair<ppT> uscs_keypair = uscs_ppzksnark_generator<ppT>(uscs_cs);

                    return tbcs_ppzksnark_keypair<ppT>(tbcs_ppzksnark_proving_key<ppT>(circuit, uscs_keypair.pk),
                                                       uscs_keypair.vk);
                }

                template<typename ppT>
                tbcs_ppzksnark_proof<ppT> tbcs_ppzksnark_prover(const tbcs_ppzksnark_proving_key<ppT> &pk,
                                                                const tbcs_ppzksnark_primary_input &primary_input,
                                                                const tbcs_ppzksnark_auxiliary_input &auxiliary_input) {
                    typedef algebra::Fr<ppT> FieldType;

                    const uscs_variable_assignment<FieldType> uscs_va =
                        tbcs_to_uscs_witness_map<FieldType>(pk.circuit, primary_input, auxiliary_input);
                    const uscs_primary_input<FieldType> uscs_pi =
                        algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                    const uscs_auxiliary_input<FieldType> uscs_ai(
                        uscs_va.begin() + primary_input.size(),
                        uscs_va.end());    // TODO: faster to just change bacs_to_r1cs_witness_map into two :(
                    const uscs_ppzksnark_proof<ppT> uscs_proof =
                        uscs_ppzksnark_prover<ppT>(pk.uscs_pk, uscs_pi, uscs_ai);

                    return uscs_proof;
                }

                template<typename ppT>
                tbcs_ppzksnark_processed_verification_key<ppT>
                    tbcs_ppzksnark_verifier_process_vk(const tbcs_ppzksnark_verification_key<ppT> &vk) {
                    const tbcs_ppzksnark_processed_verification_key<ppT> pvk =
                        uscs_ppzksnark_verifier_process_vk<ppT>(vk);

                    return pvk;
                }

                template<typename ppT>
                bool tbcs_ppzksnark_verifier_weak_IC(const tbcs_ppzksnark_verification_key<ppT> &vk,
                                                     const tbcs_ppzksnark_primary_input &primary_input,
                                                     const tbcs_ppzksnark_proof<ppT> &proof) {
                    typedef algebra::Fr<ppT> FieldType;
                    const uscs_primary_input<FieldType> uscs_input =
                        algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                    const tbcs_ppzksnark_processed_verification_key<ppT> pvk =
                        tbcs_ppzksnark_verifier_process_vk<ppT>(vk);
                    const bool bit = uscs_ppzksnark_online_verifier_weak_IC<ppT>(pvk, uscs_input, proof);

                    return bit;
                }

                template<typename ppT>
                bool tbcs_ppzksnark_verifier_strong_IC(const tbcs_ppzksnark_verification_key<ppT> &vk,
                                                       const tbcs_ppzksnark_primary_input &primary_input,
                                                       const tbcs_ppzksnark_proof<ppT> &proof) {
                    typedef algebra::Fr<ppT> FieldType;
                    const tbcs_ppzksnark_processed_verification_key<ppT> pvk =
                        tbcs_ppzksnark_verifier_process_vk<ppT>(vk);
                    const uscs_primary_input<FieldType> uscs_input =
                        algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                    const bool bit = uscs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, uscs_input, proof);

                    return bit;
                }

                template<typename ppT>
                bool tbcs_ppzksnark_online_verifier_weak_IC(const tbcs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                            const tbcs_ppzksnark_primary_input &primary_input,
                                                            const tbcs_ppzksnark_proof<ppT> &proof) {
                    typedef algebra::Fr<ppT> FieldType;
                    const uscs_primary_input<FieldType> uscs_input =
                        algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                    const bool bit = uscs_ppzksnark_online_verifier_weak_IC<ppT>(pvk, uscs_input, proof);

                    return bit;
                }

                template<typename ppT>
                bool tbcs_ppzksnark_online_verifier_strong_IC(const tbcs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                              const tbcs_ppzksnark_primary_input &primary_input,
                                                              const tbcs_ppzksnark_proof<ppT> &proof) {
                    typedef algebra::Fr<ppT> FieldType;
                    const uscs_primary_input<FieldType> uscs_input =
                        algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                    const bool bit = uscs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, uscs_input, proof);

                    return bit;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // TBCS_PPZKSNARK_HPP_
