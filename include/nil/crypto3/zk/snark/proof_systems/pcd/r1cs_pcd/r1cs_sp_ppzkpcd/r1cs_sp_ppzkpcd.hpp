//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a *single-predicate* ppzkPCD for R1CS.
//
// This includes:
// - class for proving key
// - class for verification key
// - class for processed verification key
// - class for key pair (proving key & verification key)
// - class for proof
// - generator algorithm
// - prover algorithm
// - verifier algorithm
// - online verifier algorithm
//
// The implementation follows, extends, and optimizes the approach described
// in \[BCTV14]. Thus, PCD is constructed from two "matched" ppzkSNARKs for R1CS.
//
// Acronyms:
//
// "R1CS" = "Rank-1 Constraint Systems"
// "ppzkSNARK" = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
// "ppzkPCD" = "Pre-Processing Zero-Knowledge Proof-Carrying Data"
//
// References:
//
// \[BCTV14]:
// "Scalable Zero Knowledge via Cycles of Elliptic Curves",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// CRYPTO 2014,
// <http://eprint.iacr.org/2014/595>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_SP_PPZKPCD_HPP_
#define CRYPTO3_ZK_R1CS_SP_PPZKPCD_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd_params.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Proving key ********************************/

                template<typename PCD_ppT>
                class r1cs_sp_ppzkpcd_proving_key;

                template<typename PCD_ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &pk);

                template<typename PCD_ppT>
                std::istream &operator>>(std::istream &in, r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &pk);

                /**
                 * A proving key for the R1CS (single-predicate) ppzkPCD.
                 */
                template<typename PCD_ppT>
                class r1cs_sp_ppzkpcd_proving_key {
                public:
                    typedef typename PCD_ppT::curve_A_pp A_pp;
                    typedef typename PCD_ppT::curve_B_pp B_pp;

                    r1cs_sp_ppzkpcd_compliance_predicate<PCD_ppT> compliance_predicate;

                    r1cs_ppzksnark_proving_key<A_pp> compliance_step_r1cs_pk;
                    r1cs_ppzksnark_proving_key<B_pp> translation_step_r1cs_pk;

                    r1cs_ppzksnark_verification_key<A_pp> compliance_step_r1cs_vk;
                    r1cs_ppzksnark_verification_key<B_pp> translation_step_r1cs_vk;

                    r1cs_sp_ppzkpcd_proving_key() {};
                    r1cs_sp_ppzkpcd_proving_key(const r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &other) = default;
                    r1cs_sp_ppzkpcd_proving_key(r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &&other) = default;
                    r1cs_sp_ppzkpcd_proving_key(
                        const r1cs_sp_ppzkpcd_compliance_predicate<PCD_ppT> &compliance_predicate,
                        r1cs_ppzksnark_proving_key<A_pp> &&compliance_step_r1cs_pk,
                        r1cs_ppzksnark_proving_key<B_pp> &&translation_step_r1cs_pk,
                        const r1cs_ppzksnark_verification_key<A_pp> &compliance_step_r1cs_vk,
                        const r1cs_ppzksnark_verification_key<B_pp> &translation_step_r1cs_vk) :
                        compliance_predicate(compliance_predicate),
                        compliance_step_r1cs_pk(std::move(compliance_step_r1cs_pk)),
                        translation_step_r1cs_pk(std::move(translation_step_r1cs_pk)),
                        compliance_step_r1cs_vk(std::move(compliance_step_r1cs_vk)),
                        translation_step_r1cs_vk(std::move(translation_step_r1cs_vk)) {};

                    r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &
                        operator=(const r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &other) = default;

                    std::size_t size_in_bits() const {
                        return (compliance_step_r1cs_pk.size_in_bits() + translation_step_r1cs_pk.size_in_bits() +
                                compliance_step_r1cs_vk.size_in_bits() + translation_step_r1cs_vk.size_in_bits());
                    }

                    bool operator==(const r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &other) const;
                    friend std::ostream &operator<<<PCD_ppT>(std::ostream &out,
                                                             const r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &pk);
                    friend std::istream &operator>>
                        <PCD_ppT>(std::istream &in, r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &pk);
                };

                /******************************* Verification key ****************************/

                template<typename PCD_ppT>
                class r1cs_sp_ppzkpcd_verification_key;

                template<typename PCD_ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk);

                template<typename PCD_ppT>
                std::istream &operator>>(std::istream &in, r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk);

                /**
                 * A verification key for the R1CS (single-predicate) ppzkPCD.
                 */
                template<typename PCD_ppT>
                class r1cs_sp_ppzkpcd_verification_key {
                public:
                    typedef typename PCD_ppT::curve_A_pp A_pp;
                    typedef typename PCD_ppT::curve_B_pp B_pp;

                    r1cs_ppzksnark_verification_key<A_pp> compliance_step_r1cs_vk;
                    r1cs_ppzksnark_verification_key<B_pp> translation_step_r1cs_vk;

                    r1cs_sp_ppzkpcd_verification_key() = default;
                    r1cs_sp_ppzkpcd_verification_key(const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &other) = default;
                    r1cs_sp_ppzkpcd_verification_key(r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &&other) = default;
                    r1cs_sp_ppzkpcd_verification_key(
                        const r1cs_ppzksnark_verification_key<A_pp> &compliance_step_r1cs_vk,
                        const r1cs_ppzksnark_verification_key<B_pp> &translation_step_r1cs_vk) :
                        compliance_step_r1cs_vk(std::move(compliance_step_r1cs_vk)),
                        translation_step_r1cs_vk(std::move(translation_step_r1cs_vk)) {};

                    r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &
                        operator=(const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &other) = default;

                    std::size_t size_in_bits() const {
                        return (compliance_step_r1cs_vk.size_in_bits() + translation_step_r1cs_vk.size_in_bits());
                    }

                    bool operator==(const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &other) const;
                    friend std::ostream &operator<<<PCD_ppT>(std::ostream &out,
                                                             const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk);
                    friend std::istream &operator>>
                        <PCD_ppT>(std::istream &in, r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk);

                    static r1cs_sp_ppzkpcd_verification_key<PCD_ppT> dummy_verification_key();
                };

                /************************ Processed verification key *************************/

                template<typename PCD_ppT>
                class r1cs_sp_ppzkpcd_processed_verification_key;

                template<typename PCD_ppT>
                std::ostream &operator<<(std::ostream &out,
                                         const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk);

                template<typename PCD_ppT>
                std::istream &operator>>(std::istream &in, r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk);

                /**
                 * A processed verification key for the R1CS (single-predicate) ppzkPCD.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename PCD_ppT>
                class r1cs_sp_ppzkpcd_processed_verification_key {
                public:
                    typedef typename PCD_ppT::curve_A_pp A_pp;
                    typedef typename PCD_ppT::curve_B_pp B_pp;

                    r1cs_ppzksnark_processed_verification_key<A_pp> compliance_step_r1cs_pvk;
                    r1cs_ppzksnark_processed_verification_key<B_pp> translation_step_r1cs_pvk;
                    std::vector<bool> translation_step_r1cs_vk_bits;

                    r1cs_sp_ppzkpcd_processed_verification_key() {};
                    r1cs_sp_ppzkpcd_processed_verification_key(
                        const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &other) = default;
                    r1cs_sp_ppzkpcd_processed_verification_key(
                        r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &&other) = default;
                    r1cs_sp_ppzkpcd_processed_verification_key(
                        r1cs_ppzksnark_processed_verification_key<A_pp> &&compliance_step_r1cs_pvk,
                        r1cs_ppzksnark_processed_verification_key<B_pp> &&translation_step_r1cs_pvk,
                        const std::vector<bool> &translation_step_r1cs_vk_bits) :
                        compliance_step_r1cs_pvk(std::move(compliance_step_r1cs_pvk)),
                        translation_step_r1cs_pvk(std::move(translation_step_r1cs_pvk)),
                        translation_step_r1cs_vk_bits(std::move(translation_step_r1cs_vk_bits)) {};

                    r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &
                        operator=(const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &other) = default;

                    std::size_t size_in_bits() const {
                        return (compliance_step_r1cs_pvk.size_in_bits() + translation_step_r1cs_pvk.size_in_bits() +
                                translation_step_r1cs_vk_bits.size());
                    }

                    bool operator==(const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &other) const;
                    friend std::ostream &
                        operator<<<PCD_ppT>(std::ostream &out,
                                            const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk);
                    friend std::istream &operator>>
                        <PCD_ppT>(std::istream &in, r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk);
                };

                /********************************* Key pair **********************************/

                /**
                 * A key pair for the R1CS (single-predicate) ppzkPC, which consists of a proving key and a verification
                 * key.
                 */
                template<typename PCD_ppT>
                class r1cs_sp_ppzkpcd_keypair {
                public:
                    typedef typename PCD_ppT::curve_A_pp A_pp;
                    typedef typename PCD_ppT::curve_B_pp B_pp;

                    r1cs_sp_ppzkpcd_proving_key<PCD_ppT> pk;
                    r1cs_sp_ppzkpcd_verification_key<PCD_ppT> vk;

                    r1cs_sp_ppzkpcd_keypair() {};
                    r1cs_sp_ppzkpcd_keypair(r1cs_sp_ppzkpcd_keypair<PCD_ppT> &&other) = default;
                    r1cs_sp_ppzkpcd_keypair(r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &&pk,
                                            r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {};
                    r1cs_sp_ppzkpcd_keypair(r1cs_ppzksnark_keypair<A_pp> &&kp_A, r1cs_ppzksnark_keypair<B_pp> &&kp_B) :
                        pk(std::move(kp_A.pk), std::move(kp_B.pk)), vk(std::move(kp_A.vk), std::move(kp_B.vk)) {};
                };

                /*********************************** Proof ***********************************/

                /**
                 * A proof for the R1CS (single-predicate) ppzkPCD.
                 */
                template<typename PCD_ppT>
                using r1cs_sp_ppzkpcd_proof = r1cs_ppzksnark_proof<typename PCD_ppT::curve_B_pp>;

                /***************************** Main algorithms *******************************/

                /**
                 * A generator algorithm for the R1CS (single-predicate) ppzkPCD.
                 *
                 * Given a compliance predicate, this algorithm produces proving and verification keys for the
                 * predicate.
                 */
                template<typename PCD_ppT>
                r1cs_sp_ppzkpcd_keypair<PCD_ppT> r1cs_sp_ppzkpcd_generator(
                    const r1cs_sp_ppzkpcd_compliance_predicate<PCD_ppT> &compliance_predicate);

                /**
                 * A prover algorithm for the R1CS (single-predicate) ppzkPCD.
                 *
                 * Given a proving key, inputs for the compliance predicate, and proofs for
                 * the predicate's input messages, this algorithm produces a proof (of knowledge)
                 * that attests to the compliance of the output message.
                 */
                template<typename PCD_ppT>
                r1cs_sp_ppzkpcd_proof<PCD_ppT>
                    r1cs_sp_ppzkpcd_prover(const r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &pk,
                                           const r1cs_sp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                           const r1cs_sp_ppzkpcd_auxiliary_input<PCD_ppT> &auxiliary_input,
                                           const std::vector<r1cs_sp_ppzkpcd_proof<PCD_ppT>> &incoming_proofs);

                /*
                 Below are two variants of verifier algorithm for the R1CS (single-predicate) ppzkPCD.

                 These are the two cases that arise from whether the verifier accepts a
                 (non-processed) verification key or, instead, a processed verification key.
                 In the latter case, we call the algorithm an "online verifier".
                 */

                /**
                 * A verifier algorithm for the R1CS (single-predicate) ppzkPCD that
                 * accepts a non-processed verification key.
                 */
                template<typename PCD_ppT>
                bool r1cs_sp_ppzkpcd_verifier(const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk,
                                              const r1cs_sp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                              const r1cs_sp_ppzkpcd_proof<PCD_ppT> &proof);

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename PCD_ppT>
                r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT>
                    r1cs_sp_ppzkpcd_process_vk(const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk);

                /**
                 * A verifier algorithm for the R1CS (single-predicate) ppzkPCD that
                 * accepts a processed verification key.
                 */
                template<typename PCD_ppT>
                bool r1cs_sp_ppzkpcd_online_verifier(const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk,
                                                     const r1cs_sp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                                     const r1cs_sp_ppzkpcd_proof<PCD_ppT> &proof);

                template<typename PCD_ppT>
                bool r1cs_sp_ppzkpcd_proving_key<PCD_ppT>::operator==(
                    const r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &other) const {
                    return (this->compliance_predicate == other.compliance_predicate &&
                            this->compliance_step_r1cs_pk == other.compliance_step_r1cs_pk &&
                            this->translation_step_r1cs_pk == other.translation_step_r1cs_pk &&
                            this->compliance_step_r1cs_vk == other.compliance_step_r1cs_vk &&
                            this->translation_step_r1cs_vk == other.translation_step_r1cs_vk);
                }

                template<typename PCD_ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &pk) {
                    out << pk.compliance_predicate;
                    out << pk.compliance_step_r1cs_pk;
                    out << pk.translation_step_r1cs_pk;
                    out << pk.compliance_step_r1cs_vk;
                    out << pk.translation_step_r1cs_vk;

                    return out;
                }

                template<typename PCD_ppT>
                std::istream &operator>>(std::istream &in, r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &pk) {
                    in >> pk.compliance_predicate;
                    in >> pk.compliance_step_r1cs_pk;
                    in >> pk.translation_step_r1cs_pk;
                    in >> pk.compliance_step_r1cs_vk;
                    in >> pk.translation_step_r1cs_vk;

                    return in;
                }

                template<typename PCD_ppT>
                bool r1cs_sp_ppzkpcd_verification_key<PCD_ppT>::operator==(
                    const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &other) const {
                    return (this->compliance_step_r1cs_vk == other.compliance_step_r1cs_vk &&
                            this->translation_step_r1cs_vk == other.translation_step_r1cs_vk);
                }

                template<typename PCD_ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk) {
                    out << vk.compliance_step_r1cs_vk;
                    out << vk.translation_step_r1cs_vk;

                    return out;
                }

                template<typename PCD_ppT>
                std::istream &operator>>(std::istream &in, r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk) {
                    in >> vk.compliance_step_r1cs_vk;
                    in >> vk.translation_step_r1cs_vk;

                    return in;
                }

                template<typename PCD_ppT>
                r1cs_sp_ppzkpcd_verification_key<PCD_ppT>
                    r1cs_sp_ppzkpcd_verification_key<PCD_ppT>::dummy_verification_key() {
                    typedef typename PCD_ppT::curve_A_pp curve_A_pp;
                    typedef typename PCD_ppT::curve_B_pp curve_B_pp;

                    r1cs_sp_ppzkpcd_verification_key<PCD_ppT> result;
                    result.compliance_step_r1cs_vk =
                        r1cs_ppzksnark_verification_key<typename PCD_ppT::curve_A_pp>::dummy_verification_key(
                            sp_compliance_step_pcd_circuit_maker<curve_A_pp>::input_size_in_elts());
                    result.translation_step_r1cs_vk =
                        r1cs_ppzksnark_verification_key<typename PCD_ppT::curve_B_pp>::dummy_verification_key(
                            sp_translation_step_pcd_circuit_maker<curve_B_pp>::input_size_in_elts());

                    return result;
                }

                template<typename PCD_ppT>
                bool r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT>::operator==(
                    const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &other) const {
                    return (this->compliance_step_r1cs_pvk == other.compliance_step_r1cs_pvk &&
                            this->translation_step_r1cs_pvk == other.translation_step_r1cs_pvk &&
                            this->translation_step_r1cs_vk_bits == other.translation_step_r1cs_vk_bits);
                }

                template<typename PCD_ppT>
                std::ostream &operator<<(std::ostream &out,
                                         const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk) {
                    out << pvk.compliance_step_r1cs_pvk;
                    out << pvk.translation_step_r1cs_pvk;
                    algebra::serialize_bit_vector(out, pvk.translation_step_r1cs_vk_bits);

                    return out;
                }

                template<typename PCD_ppT>
                std::istream &operator>>(std::istream &in, r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk) {
                    in >> pvk.compliance_step_r1cs_pvk;
                    in >> pvk.translation_step_r1cs_pvk;
                    algebra::deserialize_bit_vector(in, pvk.translation_step_r1cs_vk_bits);

                    return in;
                }

                template<typename PCD_ppT>
                r1cs_sp_ppzkpcd_keypair<PCD_ppT> r1cs_sp_ppzkpcd_generator(
                    const r1cs_sp_ppzkpcd_compliance_predicate<PCD_ppT> &compliance_predicate) {
                    assert(algebra::Fr<typename PCD_ppT::curve_A_pp>::mod ==
                           algebra::Fq<typename PCD_ppT::curve_B_pp>::mod);
                    assert(algebra::Fq<typename PCD_ppT::curve_A_pp>::mod ==
                           algebra::Fr<typename PCD_ppT::curve_B_pp>::mod);

                    typedef algebra::Fr<typename PCD_ppT::curve_A_pp> FieldT_A;
                    typedef algebra::Fr<typename PCD_ppT::curve_B_pp> FieldT_B;

                    typedef typename PCD_ppT::curve_A_pp curve_A_pp;
                    typedef typename PCD_ppT::curve_B_pp curve_B_pp;

                    assert(compliance_predicate.is_well_formed());

                    sp_compliance_step_pcd_circuit_maker<curve_A_pp> compliance_step_pcd_circuit(compliance_predicate);
                    compliance_step_pcd_circuit.generate_r1cs_constraints();
                    const r1cs_constraint_system<FieldT_A> compliance_step_pcd_circuit_cs =
                        compliance_step_pcd_circuit.get_circuit();

                    r1cs_ppzksnark_keypair<curve_A_pp> compliance_step_keypair =
                        r1cs_ppzksnark_generator<curve_A_pp>(compliance_step_pcd_circuit_cs);

                    sp_translation_step_pcd_circuit_maker<curve_B_pp> translation_step_pcd_circuit(
                        compliance_step_keypair.vk);
                    translation_step_pcd_circuit.generate_r1cs_constraints();
                    const r1cs_constraint_system<FieldT_B> translation_step_pcd_circuit_cs =
                        translation_step_pcd_circuit.get_circuit();

                    r1cs_ppzksnark_keypair<curve_B_pp> translation_step_keypair =
                        r1cs_ppzksnark_generator<curve_B_pp>(translation_step_pcd_circuit_cs);

                    return r1cs_sp_ppzkpcd_keypair<PCD_ppT>(
                        r1cs_sp_ppzkpcd_proving_key<PCD_ppT>(compliance_predicate,
                                                             std::move(compliance_step_keypair.pk),
                                                             std::move(translation_step_keypair.pk),
                                                             compliance_step_keypair.vk,
                                                             translation_step_keypair.vk),
                        r1cs_sp_ppzkpcd_verification_key<PCD_ppT>(compliance_step_keypair.vk,
                                                                  translation_step_keypair.vk));
                }

                template<typename PCD_ppT>
                r1cs_sp_ppzkpcd_proof<PCD_ppT>
                    r1cs_sp_ppzkpcd_prover(const r1cs_sp_ppzkpcd_proving_key<PCD_ppT> &pk,
                                           const r1cs_sp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                           const r1cs_sp_ppzkpcd_auxiliary_input<PCD_ppT> &auxiliary_input,
                                           const std::vector<r1cs_sp_ppzkpcd_proof<PCD_ppT>> &incoming_proofs) {
                    typedef algebra::Fr<typename PCD_ppT::curve_A_pp> FieldT_A;
                    typedef algebra::Fr<typename PCD_ppT::curve_B_pp> FieldT_B;

                    typedef typename PCD_ppT::curve_A_pp curve_A_pp;
                    typedef typename PCD_ppT::curve_B_pp curve_B_pp;

                    const std::vector<bool> translation_step_r1cs_vk_bits =
                        r1cs_ppzksnark_verification_key_variable<curve_A_pp>::get_verification_key_bits(
                            pk.translation_step_r1cs_vk);

                    sp_compliance_step_pcd_circuit_maker<curve_A_pp> compliance_step_pcd_circuit(
                        pk.compliance_predicate);
                    compliance_step_pcd_circuit.generate_r1cs_witness(
                        pk.translation_step_r1cs_vk, primary_input, auxiliary_input, incoming_proofs);

                    const r1cs_primary_input<FieldT_A> compliance_step_primary_input =
                        compliance_step_pcd_circuit.get_primary_input();
                    const r1cs_auxiliary_input<FieldT_A> compliance_step_auxiliary_input =
                        compliance_step_pcd_circuit.get_auxiliary_input();

                    const r1cs_ppzksnark_proof<curve_A_pp> compliance_step_proof = r1cs_ppzksnark_prover<curve_A_pp>(
                        pk.compliance_step_r1cs_pk, compliance_step_primary_input, compliance_step_auxiliary_input);


                    sp_translation_step_pcd_circuit_maker<curve_B_pp> translation_step_pcd_circuit(
                        pk.compliance_step_r1cs_vk);

                    const r1cs_primary_input<FieldT_B> translation_step_primary_input =
                        get_sp_translation_step_pcd_circuit_input<curve_B_pp>(translation_step_r1cs_vk_bits,
                                                                              primary_input);
                    translation_step_pcd_circuit.generate_r1cs_witness(
                        translation_step_primary_input, compliance_step_proof);    // TODO: potential for better naming

                    const r1cs_auxiliary_input<FieldT_B> translation_step_auxiliary_input =
                        translation_step_pcd_circuit.get_auxiliary_input();
                    const r1cs_ppzksnark_proof<curve_B_pp> translation_step_proof = r1cs_ppzksnark_prover<curve_B_pp>(
                        pk.translation_step_r1cs_pk, translation_step_primary_input, translation_step_auxiliary_input);

                    return translation_step_proof;
                }

                template<typename PCD_ppT>
                bool r1cs_sp_ppzkpcd_online_verifier(const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk,
                                                     const r1cs_sp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                                     const r1cs_sp_ppzkpcd_proof<PCD_ppT> &proof)

                {
                    typedef typename PCD_ppT::curve_B_pp curve_B_pp;

                    const r1cs_primary_input<typename curve_B_pp::scalar_field_type> r1cs_input =
                        get_sp_translation_step_pcd_circuit_input<curve_B_pp>(pvk.translation_step_r1cs_vk_bits,
                                                                              primary_input);
                    const bool result =
                        r1cs_ppzksnark_online_verifier_strong_IC(pvk.translation_step_r1cs_pvk, r1cs_input, proof);

                    return result;
                }

                template<typename PCD_ppT>
                r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT>
                    r1cs_sp_ppzkpcd_process_vk(const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk) {
                    typedef typename PCD_ppT::curve_A_pp curve_A_pp;
                    typedef typename PCD_ppT::curve_B_pp curve_B_pp;

                    r1cs_ppzksnark_processed_verification_key<curve_A_pp> compliance_step_r1cs_pvk =
                        r1cs_ppzksnark_verifier_process_vk<curve_A_pp>(vk.compliance_step_r1cs_vk);
                    r1cs_ppzksnark_processed_verification_key<curve_B_pp> translation_step_r1cs_pvk =
                        r1cs_ppzksnark_verifier_process_vk<curve_B_pp>(vk.translation_step_r1cs_vk);
                    const std::vector<bool> translation_step_r1cs_vk_bits =
                        r1cs_ppzksnark_verification_key_variable<curve_A_pp>::get_verification_key_bits(
                            vk.translation_step_r1cs_vk);

                    return r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT>(std::move(compliance_step_r1cs_pvk),
                                                                               std::move(translation_step_r1cs_pvk),
                                                                               translation_step_r1cs_vk_bits);
                }

                template<typename PCD_ppT>
                bool r1cs_sp_ppzkpcd_verifier(const r1cs_sp_ppzkpcd_verification_key<PCD_ppT> &vk,
                                              const r1cs_sp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                              const r1cs_sp_ppzkpcd_proof<PCD_ppT> &proof) {
                    const r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> pvk = r1cs_sp_ppzkpcd_process_vk(vk);
                    const bool result = r1cs_sp_ppzkpcd_online_verifier(pvk, primary_input, proof);

                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // R1CS_SP_PPZKPCD_HPP_
