//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

#ifndef BACS_PPZKSNARK_HPP_
#define BACS_PPZKSNARK_HPP_

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/bacs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/bacs_ppzksnark/bacs_ppzksnark_params.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Proving key ********************************/

                template<typename ppT>
                class bacs_ppzksnark_proving_key;

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const bacs_ppzksnark_proving_key<ppT> &pk);

                template<typename ppT>
                std::istream &operator>>(std::istream &in, bacs_ppzksnark_proving_key<ppT> &pk);

                /**
                 * A proving key for the BACS ppzkSNARK.
                 */
                template<typename ppT>
                class bacs_ppzksnark_proving_key {
                public:
                    bacs_ppzksnark_circuit<ppT> circuit;
                    r1cs_ppzksnark_proving_key<ppT> r1cs_pk;

                    bacs_ppzksnark_proving_key() {};
                    bacs_ppzksnark_proving_key(const bacs_ppzksnark_proving_key<ppT> &other) = default;
                    bacs_ppzksnark_proving_key(bacs_ppzksnark_proving_key<ppT> &&other) = default;
                    bacs_ppzksnark_proving_key(const bacs_ppzksnark_circuit<ppT> &circuit,
                                               const r1cs_ppzksnark_proving_key<ppT> &r1cs_pk) :
                        circuit(circuit),
                        r1cs_pk(r1cs_pk) {
                    }
                    bacs_ppzksnark_proving_key(bacs_ppzksnark_circuit<ppT> &&circuit,
                                               r1cs_ppzksnark_proving_key<ppT> &&r1cs_pk) :
                        circuit(std::move(circuit)),
                        r1cs_pk(std::move(r1cs_pk)) {
                    }

                    bacs_ppzksnark_proving_key<ppT> &operator=(const bacs_ppzksnark_proving_key<ppT> &other) = default;

                    size_t G1_size() const {
                        return r1cs_pk.G1_size();
                    }

                    size_t G2_size() const {
                        return r1cs_pk.G2_size();
                    }

                    size_t G1_sparse_size() const {
                        return r1cs_pk.G1_sparse_size();
                    }

                    size_t G2_sparse_size() const {
                        return r1cs_pk.G2_sparse_size();
                    }

                    size_t size_in_bits() const {
                        return r1cs_pk.size_in_bits();
                    }

                    void print_size() const {
                        r1cs_pk.print_size();
                    }

                    bool operator==(const bacs_ppzksnark_proving_key<ppT> &other) const;
                    friend std::ostream &operator<<<ppT>(std::ostream &out, const bacs_ppzksnark_proving_key<ppT> &pk);
                    friend std::istream &operator>><ppT>(std::istream &in, bacs_ppzksnark_proving_key<ppT> &pk);
                };

                /******************************* Verification key ****************************/

                /**
                 * A verification key for the BACS ppzkSNARK.
                 */
                template<typename ppT>
                using bacs_ppzksnark_verification_key = r1cs_ppzksnark_verification_key<ppT>;

                /************************ Processed verification key *************************/

                /**
                 * A processed verification key for the BACS ppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename ppT>
                using bacs_ppzksnark_processed_verification_key = r1cs_ppzksnark_processed_verification_key<ppT>;

                /********************************** Key pair *********************************/

                /**
                 * A key pair for the BACS ppzkSNARK, which consists of a proving key and a verification key.
                 */
                template<typename ppT>
                class bacs_ppzksnark_keypair {
                public:
                    bacs_ppzksnark_proving_key<ppT> pk;
                    bacs_ppzksnark_verification_key<ppT> vk;

                    bacs_ppzksnark_keypair() {};
                    bacs_ppzksnark_keypair(bacs_ppzksnark_keypair<ppT> &&other) = default;
                    bacs_ppzksnark_keypair(const bacs_ppzksnark_proving_key<ppT> &pk,
                                           const bacs_ppzksnark_verification_key<ppT> &vk) :
                        pk(pk),
                        vk(vk) {
                    }

                    bacs_ppzksnark_keypair(bacs_ppzksnark_proving_key<ppT> &&pk,
                                           bacs_ppzksnark_verification_key<ppT> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {
                    }
                };

                /*********************************** Proof ***********************************/

                /**
                 * A proof for the BACS ppzkSNARK.
                 */
                template<typename ppT>
                using bacs_ppzksnark_proof = r1cs_ppzksnark_proof<ppT>;

                /***************************** Main algorithms *******************************/

                /**
                 * A generator algorithm for the BACS ppzkSNARK.
                 *
                 * Given a BACS circuit C, this algorithm produces proving and verification keys for C.
                 */
                template<typename ppT>
                bacs_ppzksnark_keypair<ppT> bacs_ppzksnark_generator(const bacs_ppzksnark_circuit<ppT> &circuit);

                /**
                 * A prover algorithm for the BACS ppzkSNARK.
                 *
                 * Given a BACS primary input X and a BACS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that C(X,Y)=0''.
                 * Above, C is the BACS circuit that was given as input to the generator algorithm.
                 */
                template<typename ppT>
                bacs_ppzksnark_proof<ppT>
                    bacs_ppzksnark_prover(const bacs_ppzksnark_proving_key<ppT> &pk,
                                          const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                          const bacs_ppzksnark_auxiliary_input<ppT> &auxiliary_input);

                /*
                 Below are four variants of verifier algorithm for the BACS ppzkSNARK.

                 These are the four cases that arise from the following two choices:

                 (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
                     In the latter case, we call the algorithm an "online verifier".

                 (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                     Strong input consistency requires that |primary_input| = C.num_inputs, whereas
                     weak input consistency requires that |primary_input| <= C.num_inputs (and
                     the primary input is implicitly padded with zeros up to length C.num_inputs).
                 */

                /**
                 * A verifier algorithm for the BACS ppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename ppT>
                bool bacs_ppzksnark_verifier_weak_IC(const bacs_ppzksnark_verification_key<ppT> &vk,
                                                     const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                                     const bacs_ppzksnark_proof<ppT> &proof);

                /**
                 * A verifier algorithm for the BACS ppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename ppT>
                bool bacs_ppzksnark_verifier_strong_IC(const bacs_ppzksnark_verification_key<ppT> &vk,
                                                       const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                                       const bacs_ppzksnark_proof<ppT> &proof);

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename ppT>
                bacs_ppzksnark_processed_verification_key<ppT>
                    bacs_ppzksnark_verifier_process_vk(const bacs_ppzksnark_verification_key<ppT> &vk);

                /**
                 * A verifier algorithm for the BACS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename ppT>
                bool bacs_ppzksnark_online_verifier_weak_IC(const bacs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                            const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                                            const bacs_ppzksnark_proof<ppT> &proof);

                /**
                 * A verifier algorithm for the BACS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename ppT>
                bool bacs_ppzksnark_online_verifier_strong_IC(const bacs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                              const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                                              const bacs_ppzksnark_proof<ppT> &proof);

                template<typename ppT>
                bool bacs_ppzksnark_proving_key<ppT>::operator==(const bacs_ppzksnark_proving_key<ppT> &other) const {
                    return (this->circuit == other.circuit && this->r1cs_pk == other.r1cs_pk);
                }

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const bacs_ppzksnark_proving_key<ppT> &pk) {
                    out << pk.circuit << OUTPUT_NEWLINE;
                    out << pk.r1cs_pk << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename ppT>
                std::istream &operator>>(std::istream &in, bacs_ppzksnark_proving_key<ppT> &pk) {
                    in >> pk.circuit;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pk.r1cs_pk;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename ppT>
                bacs_ppzksnark_keypair<ppT> bacs_ppzksnark_generator(const bacs_ppzksnark_circuit<ppT> &circuit) {
                    typedef algebra::Fr<ppT> FieldType;

                    const r1cs_constraint_system<FieldType> r1cs_cs = bacs_to_r1cs_instance_map<FieldType>(circuit);
                    const r1cs_ppzksnark_keypair<ppT> r1cs_keypair = r1cs_ppzksnark_generator<ppT>(r1cs_cs);

                    return bacs_ppzksnark_keypair<ppT>(bacs_ppzksnark_proving_key<ppT>(circuit, r1cs_keypair.pk),
                                                       r1cs_keypair.vk);
                }

                template<typename ppT>
                bacs_ppzksnark_proof<ppT>
                    bacs_ppzksnark_prover(const bacs_ppzksnark_proving_key<ppT> &pk,
                                          const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                          const bacs_ppzksnark_auxiliary_input<ppT> &auxiliary_input) {
                    typedef algebra::Fr<ppT> FieldType;

                    const r1cs_variable_assignment<FieldType> r1cs_va =
                        bacs_to_r1cs_witness_map<FieldType>(pk.circuit, primary_input, auxiliary_input);
                    const r1cs_auxiliary_input<FieldType> r1cs_ai(
                        r1cs_va.begin() + primary_input.size(),
                        r1cs_va.end());    // TODO: faster to just change bacs_to_r1cs_witness_map into two :(
                    const r1cs_ppzksnark_proof<ppT> r1cs_proof =
                        r1cs_ppzksnark_prover<ppT>(pk.r1cs_pk, primary_input, r1cs_ai);

                    return r1cs_proof;
                }

                template<typename ppT>
                bacs_ppzksnark_processed_verification_key<ppT>
                    bacs_ppzksnark_verifier_process_vk(const bacs_ppzksnark_verification_key<ppT> &vk) {
                    const bacs_ppzksnark_processed_verification_key<ppT> pvk =
                        r1cs_ppzksnark_verifier_process_vk<ppT>(vk);

                    return pvk;
                }

                template<typename ppT>
                bool bacs_ppzksnark_verifier_weak_IC(const bacs_ppzksnark_verification_key<ppT> &vk,
                                                     const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                                     const bacs_ppzksnark_proof<ppT> &proof) {
                    const bacs_ppzksnark_processed_verification_key<ppT> pvk =
                        bacs_ppzksnark_verifier_process_vk<ppT>(vk);
                    const bool bit = r1cs_ppzksnark_online_verifier_weak_IC<ppT>(pvk, primary_input, proof);

                    return bit;
                }

                template<typename ppT>
                bool bacs_ppzksnark_verifier_strong_IC(const bacs_ppzksnark_verification_key<ppT> &vk,
                                                       const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                                       const bacs_ppzksnark_proof<ppT> &proof) {
                    const bacs_ppzksnark_processed_verification_key<ppT> pvk =
                        bacs_ppzksnark_verifier_process_vk<ppT>(vk);
                    const bool bit = r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, primary_input, proof);

                    return bit;
                }

                template<typename ppT>
                bool bacs_ppzksnark_online_verifier_weak_IC(const bacs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                            const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                                            const bacs_ppzksnark_proof<ppT> &proof) {
                    const bool bit = r1cs_ppzksnark_online_verifier_weak_IC<ppT>(pvk, primary_input, proof);

                    return bit;
                }

                template<typename ppT>
                bool bacs_ppzksnark_online_verifier_strong_IC(const bacs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                              const bacs_ppzksnark_primary_input<ppT> &primary_input,
                                                              const bacs_ppzksnark_proof<ppT> &proof) {
                    const bool bit = r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, primary_input, proof);

                    return bit;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // BACS_PPZKSNARK_HPP_
