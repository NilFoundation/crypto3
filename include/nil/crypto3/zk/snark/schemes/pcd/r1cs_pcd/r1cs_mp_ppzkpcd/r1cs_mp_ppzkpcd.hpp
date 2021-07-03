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
// @file Declaration of interfaces for a *multi-predicate* ppzkPCD for R1CS.
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
// in \[CTV15]. Thus, PCD is constructed from two "matched" ppzkSNARKs for R1CS.
//
// Acronyms:
//
// "R1CS" = "Rank-1 Constraint Systems"
// "ppzkSNARK" = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
// "ppzkPCD" = "Pre-Processing Zero-Knowledge Proof-Carrying Data"
//
// References:
//
// \[CTV15]:
// "Cluster Computing in Zero Knowledge",
// Alessandro Chiesa, Eran Tromer, Madars Virza,
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_MP_PPZKPCD_HPP
#define CRYPTO3_R1CS_MP_PPZKPCD_HPP

#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/set_commitment.hpp>

#include <nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/ppzkpcd_compliance_predicate.hpp>
#include <nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/r1cs_mp_ppzkpcd_params.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_ppzksnark.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Proving key ********************************/

                /**
                 * A proving key for the R1CS (multi-predicate) ppzkPCD.
                 */
                template<typename PCD_ppT>
                class r1cs_mp_ppzkpcd_proving_key {
                public:
                    typedef typename PCD_ppT::curve_A_pp A_pp;
                    typedef typename PCD_ppT::curve_B_pp B_pp;

                    std::vector<r1cs_mp_ppzkpcd_compliance_predicate<PCD_ppT>> compliance_predicates;

                    std::vector<typename r1cs_ppzksnark<A_pp>::proving_key_type> compliance_step_r1cs_pks;
                    std::vector<typename r1cs_ppzksnark<B_pp>::proving_key_type> translation_step_r1cs_pks;

                    std::vector<typename r1cs_ppzksnark<A_pp>::verification_key_type> compliance_step_r1cs_vks;
                    std::vector<typename r1cs_ppzksnark<B_pp>::verification_key_type> translation_step_r1cs_vks;

                    set_commitment commitment_to_translation_step_r1cs_vks;
                    std::vector<set_membership_proof> compliance_step_r1cs_vk_membership_proofs;

                    std::map<std::size_t, std::size_t> compliance_predicate_name_to_idx;

                    r1cs_mp_ppzkpcd_proving_key() {};
                    r1cs_mp_ppzkpcd_proving_key(const r1cs_mp_ppzkpcd_proving_key<PCD_ppT> &other) = default;
                    r1cs_mp_ppzkpcd_proving_key(r1cs_mp_ppzkpcd_proving_key<PCD_ppT> &&other) = default;
                    r1cs_mp_ppzkpcd_proving_key(
                        const std::vector<r1cs_mp_ppzkpcd_compliance_predicate<PCD_ppT>> &compliance_predicates,
                        const std::vector<typename r1cs_ppzksnark<A_pp>::proving_key_type> &compliance_step_r1cs_pk,
                        const std::vector<typename r1cs_ppzksnark<B_pp>::proving_key_type> &translation_step_r1cs_pk,
                        const std::vector<typename r1cs_ppzksnark<A_pp>::verification_key_type>
                            &compliance_step_r1cs_vk,
                        const std::vector<typename r1cs_ppzksnark<B_pp>::verification_key_type>
                            &translation_step_r1cs_vk,
                        const set_commitment &commitment_to_translation_step_r1cs_vks,
                        const std::vector<set_membership_proof> &compliance_step_r1cs_vk_membership_proofs,
                        const std::map<std::size_t, std::size_t> &compliance_predicate_name_to_idx) :
                        compliance_predicates(compliance_predicates),
                        compliance_step_r1cs_pks(compliance_step_r1cs_pks),
                        translation_step_r1cs_pks(translation_step_r1cs_pks),
                        compliance_step_r1cs_vks(compliance_step_r1cs_vks),
                        translation_step_r1cs_vks(translation_step_r1cs_vks),
                        commitment_to_translation_step_r1cs_vks(commitment_to_translation_step_r1cs_vks),
                        compliance_step_r1cs_vk_membership_proofs(compliance_step_r1cs_vk_membership_proofs),
                        compliance_predicate_name_to_idx(compliance_predicate_name_to_idx) {
                    }

                    r1cs_mp_ppzkpcd_proving_key<PCD_ppT> &
                        operator=(const r1cs_mp_ppzkpcd_proving_key<PCD_ppT> &other) = default;

                    std::size_t size_in_bits() const;

                    bool is_well_formed() const;

                    bool operator==(const r1cs_mp_ppzkpcd_proving_key<PCD_ppT> &other) const;
                };

                /******************************* Verification key ****************************/

                /**
                 * A verification key for the R1CS (multi-predicate) ppzkPCD.
                 */
                template<typename PCD_ppT>
                class r1cs_mp_ppzkpcd_verification_key {
                public:
                    typedef typename PCD_ppT::curve_A_pp A_pp;
                    typedef typename PCD_ppT::curve_B_pp B_pp;

                    std::vector<typename r1cs_ppzksnark<A_pp>::verification_key_type> compliance_step_r1cs_vks;
                    std::vector<typename r1cs_ppzksnark<B_pp>::verification_key_type> translation_step_r1cs_vks;
                    set_commitment commitment_to_translation_step_r1cs_vks;

                    r1cs_mp_ppzkpcd_verification_key() = default;
                    r1cs_mp_ppzkpcd_verification_key(const r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &other) = default;
                    r1cs_mp_ppzkpcd_verification_key(r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &&other) = default;
                    r1cs_mp_ppzkpcd_verification_key(
                        const std::vector<typename r1cs_ppzksnark<A_pp>::verification_key_type>
                            &compliance_step_r1cs_vks,
                        const std::vector<typename r1cs_ppzksnark<B_pp>::verification_key_type>
                            &translation_step_r1cs_vks,
                        const set_commitment &commitment_to_translation_step_r1cs_vks) :
                        compliance_step_r1cs_vks(compliance_step_r1cs_vks),
                        translation_step_r1cs_vks(translation_step_r1cs_vks),
                        commitment_to_translation_step_r1cs_vks(commitment_to_translation_step_r1cs_vks) {
                    }

                    r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &
                        operator=(const r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &other) = default;

                    std::size_t size_in_bits() const;

                    bool operator==(const r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &other) const;
                };

                /************************* Processed verification key **************************/

                /**
                 * A processed verification key for the R1CS (multi-predicate) ppzkPCD.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename PCD_ppT>
                class r1cs_mp_ppzkpcd_processed_verification_key {
                public:
                    typedef typename PCD_ppT::curve_A_pp A_pp;
                    typedef typename PCD_ppT::curve_B_pp B_pp;

                    std::vector<typename r1cs_ppzksnark<A_pp>::processed_verification_key_type>
                        compliance_step_r1cs_pvks;
                    std::vector<typename r1cs_ppzksnark<B_pp>::processed_verification_key_type>
                        translation_step_r1cs_pvks;
                    set_commitment commitment_to_translation_step_r1cs_vks;

                    r1cs_mp_ppzkpcd_processed_verification_key() = default;
                    r1cs_mp_ppzkpcd_processed_verification_key(
                        const r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> &other) = default;
                    r1cs_mp_ppzkpcd_processed_verification_key(
                        r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> &&other) = default;
                    r1cs_mp_ppzkpcd_processed_verification_key(
                        std::vector<typename r1cs_ppzksnark<A_pp>::processed_verification_key_type>
                            &&compliance_step_r1cs_pvks,
                        std::vector<typename r1cs_ppzksnark<B_pp>::processed_verification_key_type>
                            &&translation_step_r1cs_pvks,
                        const set_commitment &commitment_to_translation_step_r1cs_vks) :
                        compliance_step_r1cs_pvks(std::move(compliance_step_r1cs_pvks)),
                        translation_step_r1cs_pvks(std::move(translation_step_r1cs_pvks)),
                        commitment_to_translation_step_r1cs_vks(commitment_to_translation_step_r1cs_vks) {};

                    r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> &
                        operator=(const r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> &other) = default;

                    std::size_t size_in_bits() const;

                    bool operator==(const r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> &other) const;
                };

                /********************************** Key pair *********************************/

                /**
                 * A key pair for the R1CS (multi-predicate) ppzkPC, which consists of a proving key and a verification
                 * key.
                 */
                template<typename PCD_ppT>
                class r1cs_mp_ppzkpcd_keypair {
                public:
                    r1cs_mp_ppzkpcd_proving_key<PCD_ppT> pk;
                    r1cs_mp_ppzkpcd_verification_key<PCD_ppT> vk;

                    r1cs_mp_ppzkpcd_keypair() = default;
                    r1cs_mp_ppzkpcd_keypair(r1cs_mp_ppzkpcd_keypair<PCD_ppT> &&other) = default;
                    r1cs_mp_ppzkpcd_keypair(r1cs_mp_ppzkpcd_proving_key<PCD_ppT> &&pk,
                                            r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {};
                };

                /*********************************** Proof ***********************************/

                /**
                 * A proof for the R1CS (multi-predicate) ppzkPCD.
                 */
                template<typename PCD_ppT>
                class r1cs_mp_ppzkpcd_proof {
                public:
                    std::size_t compliance_predicate_idx;
                    typename r1cs_ppzksnark<typename PCD_ppT::curve_B_pp>::proof_type r1cs_proof;

                    r1cs_mp_ppzkpcd_proof() = default;
                    r1cs_mp_ppzkpcd_proof(
                        const std::size_t compliance_predicate_idx,
                        const typename r1cs_ppzksnark<typename PCD_ppT::curve_B_pp>::proof_type &r1cs_proof) :
                        compliance_predicate_idx(compliance_predicate_idx),
                        r1cs_proof(r1cs_proof) {
                    }

                    std::size_t size_in_bits() const;

                    bool operator==(const r1cs_mp_ppzkpcd_proof<PCD_ppT> &other) const;
                };

                /***************************** Main algorithms *******************************/

                /**
                 * A generator algorithm for the R1CS (multi-predicate) ppzkPCD.
                 *
                 * Given a vector of compliance predicates, this algorithm produces proving and verification keys for
                 * the vector.
                 */
                template<typename PCD_ppT>
                r1cs_mp_ppzkpcd_keypair<PCD_ppT> r1cs_mp_ppzkpcd_generator(
                    const std::vector<r1cs_mp_ppzkpcd_compliance_predicate<PCD_ppT>> &compliance_predicates);

                /**
                 * A prover algorithm for the R1CS (multi-predicate) ppzkPCD.
                 *
                 * Given a proving key, name of chosen compliance predicate, inputs for the
                 * compliance predicate, and proofs for the predicate's input messages, this
                 * algorithm produces a proof (of knowledge) that attests to the compliance of
                 * the output message.
                 */
                template<typename PCD_ppT>
                r1cs_mp_ppzkpcd_proof<PCD_ppT>
                    r1cs_mp_ppzkpcd_prover(const r1cs_mp_ppzkpcd_proving_key<PCD_ppT> &pk,
                                           const std::size_t compliance_predicate_name,
                                           const r1cs_mp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                           const r1cs_mp_ppzkpcd_auxiliary_input<PCD_ppT> &auxiliary_input,
                                           const std::vector<r1cs_mp_ppzkpcd_proof<PCD_ppT>> &incoming_proofs);

                /*
                  Below are two variants of verifier algorithm for the R1CS (multi-predicate) ppzkPCD.

                  These are the two cases that arise from whether the verifier accepts a
                  (non-processed) verification key or, instead, a processed verification key.
                  In the latter case, we call the algorithm an "online verifier".
                */

                /**
                 * A verifier algorithm for the R1CS (multi-predicate) ppzkPCD that
                 * accepts a non-processed verification key.
                 */
                template<typename PCD_ppT>
                bool r1cs_mp_ppzkpcd_verifier(const r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &vk,
                                              const r1cs_mp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                              const r1cs_mp_ppzkpcd_proof<PCD_ppT> &proof);

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename PCD_ppT>
                r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT>
                    r1cs_mp_ppzkpcd_process_vk(const r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &vk);

                /**
                 * A verifier algorithm for the R1CS (multi-predicate) ppzkPCD that
                 * accepts a processed verification key.
                 */
                template<typename PCD_ppT>
                bool r1cs_mp_ppzkpcd_online_verifier(const r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk,
                                                     const r1cs_mp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                                     const r1cs_mp_ppzkpcd_proof<PCD_ppT> &proof);

                template<typename PCD_ppT>
                std::size_t r1cs_mp_ppzkpcd_proving_key<PCD_ppT>::size_in_bits() const {
                    const std::size_t num_predicates = compliance_predicates.size();

                    std::size_t result = 0;
                    for (std::size_t i = 0; i < num_predicates; ++i) {
                        result +=
                            (compliance_predicates[i].size_in_bits() + compliance_step_r1cs_pks[i].size_in_bits() +
                             translation_step_r1cs_pks[i].size_in_bits() + compliance_step_r1cs_vks[i].size_in_bits() +
                             translation_step_r1cs_vks[i].size_in_bits() +
                             compliance_step_r1cs_vk_membership_proofs[i].size_in_bits());
                    }
                    result += commitment_to_translation_step_r1cs_vks.size();

                    return result;
                }

                template<typename PCD_ppT>
                bool r1cs_mp_ppzkpcd_proving_key<PCD_ppT>::is_well_formed() const {
                    const std::size_t num_predicates = compliance_predicates.size();

                    bool result;
                    result = result && (compliance_step_r1cs_pks.size() == num_predicates);
                    result = result && (translation_step_r1cs_pks.size() == num_predicates);
                    result = result && (compliance_step_r1cs_vks.size() == num_predicates);
                    result = result && (translation_step_r1cs_vks.size() == num_predicates);
                    result = result && (compliance_step_r1cs_vk_membership_proofs.size() == num_predicates);

                    return result;
                }

                template<typename PCD_ppT>
                bool r1cs_mp_ppzkpcd_proving_key<PCD_ppT>::operator==(
                    const r1cs_mp_ppzkpcd_proving_key<PCD_ppT> &other) const {
                    return (this->compliance_predicates == other.compliance_predicates &&
                            this->compliance_step_r1cs_pks == other.compliance_step_r1cs_pks &&
                            this->translation_step_r1cs_pks == other.translation_step_r1cs_pks &&
                            this->compliance_step_r1cs_vks == other.compliance_step_r1cs_vks &&
                            this->translation_step_r1cs_vks == other.translation_step_r1cs_vks &&
                            this->commitment_to_translation_step_r1cs_vks ==
                                other.commitment_to_translation_step_r1cs_vks &&
                            this->compliance_step_r1cs_vk_membership_proofs ==
                                other.compliance_step_r1cs_vk_membership_proofs &&
                            this->compliance_predicate_name_to_idx == other.compliance_predicate_name_to_idx);
                }

                template<typename PCD_ppT>
                std::size_t r1cs_mp_ppzkpcd_verification_key<PCD_ppT>::size_in_bits() const {
                    const std::size_t num_predicates = compliance_step_r1cs_vks.size();

                    std::size_t result = 0;
                    for (std::size_t i = 0; i < num_predicates; ++i) {
                        result +=
                            (compliance_step_r1cs_vks[i].size_in_bits() + translation_step_r1cs_vks[i].size_in_bits());
                    }

                    result += commitment_to_translation_step_r1cs_vks.size();

                    return result;
                }

                template<typename PCD_ppT>
                bool r1cs_mp_ppzkpcd_verification_key<PCD_ppT>::operator==(
                    const r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &other) const {
                    return (this->compliance_step_r1cs_vks == other.compliance_step_r1cs_vks &&
                            this->translation_step_r1cs_vks == other.translation_step_r1cs_vks &&
                            this->commitment_to_translation_step_r1cs_vks ==
                                other.commitment_to_translation_step_r1cs_vks);
                }

                template<typename PCD_ppT>
                std::size_t r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT>::size_in_bits() const {
                    const std::size_t num_predicates = compliance_step_r1cs_pvks.size();

                    std::size_t result = 0;
                    for (std::size_t i = 0; i < num_predicates; ++i) {
                        result += (compliance_step_r1cs_pvks[i].size_in_bits() +
                                   translation_step_r1cs_pvks[i].size_in_bits());
                    }

                    result += commitment_to_translation_step_r1cs_vks.size();

                    return result;
                }

                template<typename PCD_ppT>
                bool r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT>::operator==(
                    const r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> &other) const {
                    return (this->compliance_step_r1cs_pvks == other.compliance_step_r1cs_pvks &&
                            this->translation_step_r1cs_pvks == other.translation_step_r1cs_pvks &&
                            this->commitment_to_translation_step_r1cs_vks ==
                                other.commitment_to_translation_step_r1cs_vks);
                }

                template<typename PCD_ppT>
                bool r1cs_mp_ppzkpcd_proof<PCD_ppT>::operator==(const r1cs_mp_ppzkpcd_proof<PCD_ppT> &other) const {
                    return (this->compliance_predicate_idx == other.compliance_predicate_idx &&
                            this->r1cs_proof == other.r1cs_proof);
                }

                template<typename PCD_ppT>
                r1cs_mp_ppzkpcd_keypair<PCD_ppT> r1cs_mp_ppzkpcd_generator(
                    const std::vector<r1cs_mp_ppzkpcd_compliance_predicate<PCD_ppT>> &compliance_predicates) {
                    assert(algebra::Fr<typename PCD_ppT::curve_A_pp>::mod ==
                           algebra::Fq<typename PCD_ppT::curve_B_pp>::mod);
                    assert(algebra::Fq<typename PCD_ppT::curve_A_pp>::mod ==
                           algebra::Fr<typename PCD_ppT::curve_B_pp>::mod);

                    typedef typename PCD_ppT::curve_A_pp curve_A_pp;
                    typedef typename PCD_ppT::curve_B_pp curve_B_pp;

                    typedef typename curve_A_pp::scalar_field_type FieldT_A;
                    typedef typename curve_B_pp::scalar_field_type FieldT_B;

                    std::cout << "Call to r1cs_mp_ppzkpcd_generator" << std::endl;

                    r1cs_mp_ppzkpcd_keypair<PCD_ppT> keypair;
                    const std::size_t translation_input_size =
                        mp_translation_step_pcd_circuit_maker<curve_B_pp>::input_size_in_elts();
                    const std::size_t vk_size_in_bits =
                        r1cs_ppzksnark_verification_key_variable<curve_A_pp>::size_in_bits(translation_input_size);
                    printf("%zu %zu\n", translation_input_size, vk_size_in_bits);

                    set_commitment_accumulator<crh_with_bit_out_component<FieldT_A>> all_translation_vks(
                        compliance_predicates.size(), vk_size_in_bits);

                    std::cout << "Perform type checks" << std::endl;
                    std::map<std::size_t, std::size_t> type_counts;

                    for (auto &cp : compliance_predicates) {
                        type_counts[cp.type] += 1;
                    }

                    for (auto &cp : compliance_predicates) {
                        if (cp.relies_on_same_type_inputs) {
                            for (std::size_t type : cp.accepted_input_types) {
                                assert(type_counts[type] == 1); /* each of accepted_input_types must be unique */
                            }
                        } else {
                            assert(cp.accepted_input_types.empty());
                        }
                    }

                    for (std::size_t i = 0; i < compliance_predicates.size(); ++i) {
                        std::cout << FMT("",
                                         "Process predicate %zu (with name %zu and type %zu)",
                                         i,
                                         compliance_predicates[i].name,
                                         compliance_predicates[i].type)
                                  << std::endl;
                        assert(compliance_predicates[i].is_well_formed());

                        std::cout << "Construct compliance step PCD circuit" << std::endl;
                        mp_compliance_step_pcd_circuit_maker<curve_A_pp> mp_compliance_step_pcd_circuit(
                            compliance_predicates[i], compliance_predicates.size());
                        mp_compliance_step_pcd_circuit.generate_r1cs_constraints();
                        r1cs_constraint_system<FieldT_A> mp_compliance_step_pcd_circuit_cs =
                            mp_compliance_step_pcd_circuit.get_circuit();

                        std::cout << "Generate key pair for compliance step PCD circuit" << std::endl;
                        typename r1cs_ppzksnark<curve_A_pp>::keypair_type mp_compliance_step_keypair =
                            r1cs_ppzksnark<curve_A_pp>::generator(mp_compliance_step_pcd_circuit_cs);

                        std::cout << "Construct translation step PCD circuit" << std::endl;
                        mp_translation_step_pcd_circuit_maker<curve_B_pp> mp_translation_step_pcd_circuit(
                            mp_compliance_step_keypair.vk);
                        mp_translation_step_pcd_circuit.generate_r1cs_constraints();
                        r1cs_constraint_system<FieldT_B> mp_translation_step_pcd_circuit_cs =
                            mp_translation_step_pcd_circuit.get_circuit();

                        std::cout << "Generate key pair for translation step PCD circuit" << std::endl;
                        typename r1cs_ppzksnark<curve_B_pp>::keypair_type mp_translation_step_keypair =
                            r1cs_ppzksnark<curve_B_pp>::generator(mp_translation_step_pcd_circuit_cs);

                        std::cout << "Augment set of translation step verification keys" << std::endl;
                        const std::vector<bool> vk_bits =
                            r1cs_ppzksnark_verification_key_variable<curve_A_pp>::get_verification_key_bits(
                                mp_translation_step_keypair.vk);
                        all_translation_vks.add(vk_bits);

                        std::cout << "Update r1cs_mp_ppzkpcd keypair" << std::endl;
                        keypair.pk.compliance_predicates.emplace_back(compliance_predicates[i]);
                        keypair.pk.compliance_step_r1cs_pks.emplace_back(mp_compliance_step_keypair.pk);
                        keypair.pk.translation_step_r1cs_pks.emplace_back(mp_translation_step_keypair.pk);
                        keypair.pk.compliance_step_r1cs_vks.emplace_back(mp_compliance_step_keypair.vk);
                        keypair.pk.translation_step_r1cs_vks.emplace_back(mp_translation_step_keypair.vk);
                        const std::size_t cp_name = compliance_predicates[i].name;
                        assert(keypair.pk.compliance_predicate_name_to_idx.find(cp_name) ==
                               keypair.pk.compliance_predicate_name_to_idx.end());    // all names must be distinct
                        keypair.pk.compliance_predicate_name_to_idx[cp_name] = i;

                        keypair.vk.compliance_step_r1cs_vks.emplace_back(mp_compliance_step_keypair.vk);
                        keypair.vk.translation_step_r1cs_vks.emplace_back(mp_translation_step_keypair.vk);
                    }

                    std::cout << "Compute set commitment and corresponding membership proofs" << std::endl;
                    const set_commitment cm = all_translation_vks.get_commitment();
                    keypair.pk.commitment_to_translation_step_r1cs_vks = cm;
                    keypair.vk.commitment_to_translation_step_r1cs_vks = cm;
                    for (std::size_t i = 0; i < compliance_predicates.size(); ++i) {
                        const std::vector<bool> vk_bits =
                            r1cs_ppzksnark_verification_key_variable<curve_A_pp>::get_verification_key_bits(
                                keypair.vk.translation_step_r1cs_vks[i]);
                        const set_membership_proof proof = all_translation_vks.get_membership_proof(vk_bits);

                        keypair.pk.compliance_step_r1cs_vk_membership_proofs.emplace_back(proof);
                    }

                    return keypair;
                }

                template<typename PCD_ppT>
                r1cs_mp_ppzkpcd_proof<PCD_ppT>
                    r1cs_mp_ppzkpcd_prover(const r1cs_mp_ppzkpcd_proving_key<PCD_ppT> &pk,
                                           const std::size_t compliance_predicate_name,
                                           const r1cs_mp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                           const r1cs_mp_ppzkpcd_auxiliary_input<PCD_ppT> &auxiliary_input,
                                           const std::vector<r1cs_mp_ppzkpcd_proof<PCD_ppT>> &prev_proofs) {
                    typedef typename PCD_ppT::curve_A_pp curve_A_pp;
                    typedef typename PCD_ppT::curve_B_pp curve_B_pp;

                    typedef typename curve_A_pp::scalar_field_type FieldT_A;
                    typedef typename curve_B_pp::scalar_field_type FieldT_B;

                    std::cout << "Call to r1cs_mp_ppzkpcd_prover" << std::endl;

                    auto it = pk.compliance_predicate_name_to_idx.find(compliance_predicate_name);
                    assert(it != pk.compliance_predicate_name_to_idx.end());
                    const std::size_t compliance_predicate_idx = it->second;

                    std::cout << "Prove compliance step" << std::endl;
                    assert(compliance_predicate_idx < pk.compliance_predicates.size());
                    assert(prev_proofs.size() <= pk.compliance_predicates[compliance_predicate_idx].max_arity);

                    const std::size_t arity = prev_proofs.size();
                    const std::size_t max_arity = pk.compliance_predicates[compliance_predicate_idx].max_arity;

                    if (pk.compliance_predicates[compliance_predicate_idx].relies_on_same_type_inputs) {
                        const std::size_t input_predicate_idx = prev_proofs[0].compliance_predicate_idx;
                        for (std::size_t i = 1; i < arity; ++i) {
                            assert(prev_proofs[i].compliance_predicate_idx == input_predicate_idx);
                        }
                    }

                    std::vector<typename r1cs_ppzksnark<curve_B_pp>::proof_type> padded_proofs(max_arity);
                    for (std::size_t i = 0; i < arity; ++i) {
                        padded_proofs[i] = prev_proofs[i].r1cs_proof;
                    }

                    std::vector<typename r1cs_ppzksnark<curve_B_pp>::verification_key_type> translation_step_vks;
                    std::vector<set_membership_proof> membership_proofs;

                    for (std::size_t i = 0; i < arity; ++i) {
                        const std::size_t input_predicate_idx = prev_proofs[i].compliance_predicate_idx;
                        translation_step_vks.emplace_back(pk.translation_step_r1cs_vks[input_predicate_idx]);
                        membership_proofs.emplace_back(
                            pk.compliance_step_r1cs_vk_membership_proofs[input_predicate_idx]);

#ifdef DEBUG
                        if (auxiliary_input.incoming_messages[i]->type != 0) {
                            printf("check proof for message %zu\n", i);
                            const r1cs_primary_input<FieldT_B> translated_msg =
                                get_mp_translation_step_pcd_circuit_input<curve_B_pp>(
                                    pk.commitment_to_translation_step_r1cs_vks, auxiliary_input.incoming_messages[i]);
                            const bool bit = r1cs_ppzksnark<curve_B_pp>::verifier_strong_input_consistency(
                                translation_step_vks[i], translated_msg, padded_proofs[i]);
                            assert(bit);
                        } else {
                            printf("message %zu is base case\n", i);
                        }
#endif
                    }

                    /* pad with dummy vks/membership proofs */
                    for (std::size_t i = arity; i < max_arity; ++i) {
                        printf("proof %zu will be a dummy\n", arity);
                        translation_step_vks.emplace_back(pk.translation_step_r1cs_vks[0]);
                        membership_proofs.emplace_back(pk.compliance_step_r1cs_vk_membership_proofs[0]);
                    }

                    mp_compliance_step_pcd_circuit_maker<curve_A_pp> mp_compliance_step_pcd_circuit(
                        pk.compliance_predicates[compliance_predicate_idx], pk.compliance_predicates.size());

                    mp_compliance_step_pcd_circuit.generate_r1cs_witness(pk.commitment_to_translation_step_r1cs_vks,
                                                                         translation_step_vks,
                                                                         membership_proofs,
                                                                         primary_input,
                                                                         auxiliary_input,
                                                                         padded_proofs);

                    const r1cs_primary_input<FieldT_A> compliance_step_primary_input =
                        mp_compliance_step_pcd_circuit.get_primary_input();
                    const r1cs_auxiliary_input<FieldT_A> compliance_step_auxiliary_input =
                        mp_compliance_step_pcd_circuit.get_auxiliary_input();
                    const typename r1cs_ppzksnark<curve_A_pp>::proof_type compliance_step_proof =
                        r1cs_ppzksnark<curve_A_pp>::prover(pk.compliance_step_r1cs_pks[compliance_predicate_idx],
                                                           compliance_step_primary_input,
                                                           compliance_step_auxiliary_input);

#ifdef DEBUG
                    const r1cs_primary_input<FieldT_A> compliance_step_input =
                        get_mp_compliance_step_pcd_circuit_input<curve_A_pp>(pk.commitment_to_translation_step_r1cs_vks,
                                                                             primary_input.outgoing_message);
                    const bool compliance_step_ok = r1cs_ppzksnark<curve_A_pp>::verifier_strong_input_consistency(
                        pk.compliance_step_r1cs_vks[compliance_predicate_idx],
                        compliance_step_input,
                        compliance_step_proof);
                    assert(compliance_step_ok);
#endif

                    std::cout << "Prove translation step" << std::endl;
                    mp_translation_step_pcd_circuit_maker<curve_B_pp> mp_translation_step_pcd_circuit(
                        pk.compliance_step_r1cs_vks[compliance_predicate_idx]);

                    const r1cs_primary_input<FieldT_B> translation_step_primary_input =
                        get_mp_translation_step_pcd_circuit_input<curve_B_pp>(
                            pk.commitment_to_translation_step_r1cs_vks, primary_input);
                    mp_translation_step_pcd_circuit.generate_r1cs_witness(translation_step_primary_input,
                                                                          compliance_step_proof);
                    const r1cs_auxiliary_input<FieldT_B> translation_step_auxiliary_input =
                        mp_translation_step_pcd_circuit.get_auxiliary_input();

                    const typename r1cs_ppzksnark<curve_B_pp>::proof_type translation_step_proof =
                        r1cs_ppzksnark<curve_B_pp>::prover(pk.translation_step_r1cs_pks[compliance_predicate_idx],
                                                           translation_step_primary_input,
                                                           translation_step_auxiliary_input);

#ifdef DEBUG
                    const bool translation_step_ok = r1cs_ppzksnark<curve_B_pp>::verifier_strong_input_consistency(
                        pk.translation_step_r1cs_vks[compliance_predicate_idx],
                        translation_step_primary_input,
                        translation_step_proof);
                    assert(translation_step_ok);
#endif

                    r1cs_mp_ppzkpcd_proof<PCD_ppT> result;
                    result.compliance_predicate_idx = compliance_predicate_idx;
                    result.r1cs_proof = translation_step_proof;
                    return result;
                }

                template<typename PCD_ppT>
                bool r1cs_mp_ppzkpcd_online_verifier(const r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> &pvk,
                                                     const r1cs_mp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                                     const r1cs_mp_ppzkpcd_proof<PCD_ppT> &proof) {
                    typedef typename PCD_ppT::curve_B_pp curve_B_pp;

                    std::cout << "Call to r1cs_mp_ppzkpcd_online_verifier" << std::endl;
                    const r1cs_primary_input<typename curve_B_pp::scalar_field_type> r1cs_input =
                        get_mp_translation_step_pcd_circuit_input<curve_B_pp>(
                            pvk.commitment_to_translation_step_r1cs_vks, primary_input);
                    const bool result = r1cs_ppzksnark::online_verifier_strong_input_consistency(
                        pvk.translation_step_r1cs_pvks[proof.compliance_predicate_idx], r1cs_input, proof.r1cs_proof);

                    return result;
                }

                template<typename PCD_ppT>
                r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT>
                    r1cs_mp_ppzkpcd_process_vk(const r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &vk) {
                    typedef typename PCD_ppT::curve_A_pp curve_A_pp;
                    typedef typename PCD_ppT::curve_B_pp curve_B_pp;

                    std::cout << "Call to r1cs_mp_ppzkpcd_processed_verification_key" << std::endl;

                    r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> result;
                    result.commitment_to_translation_step_r1cs_vks = vk.commitment_to_translation_step_r1cs_vks;

                    for (std::size_t i = 0; i < vk.compliance_step_r1cs_vks.size(); ++i) {
                        const typename r1cs_ppzksnark<curve_A_pp>::processed_verification_key_type
                            compliance_step_r1cs_pvk =
                                r1cs_ppzksnark<curve_A_pp>::verifier_process_vk(vk.compliance_step_r1cs_vks[i]);
                        const typename r1cs_ppzksnark<curve_B_pp>::processed_verification_key
                            translation_step_r1cs_pvk =
                                r1cs_ppzksnark<curve_B_pp>::verifier_process_vk(vk.translation_step_r1cs_vks[i]);

                        result.compliance_step_r1cs_pvks.emplace_back(compliance_step_r1cs_pvk);
                        result.translation_step_r1cs_pvks.emplace_back(translation_step_r1cs_pvk);
                    }

                    return result;
                }

                template<typename PCD_ppT>
                bool r1cs_mp_ppzkpcd_verifier(const r1cs_mp_ppzkpcd_verification_key<PCD_ppT> &vk,
                                              const r1cs_mp_ppzkpcd_primary_input<PCD_ppT> &primary_input,
                                              const r1cs_mp_ppzkpcd_proof<PCD_ppT> &proof) {
                    std::cout << "Call to r1cs_mp_ppzkpcd_verifier" << std::endl;
                    r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> pvk = r1cs_mp_ppzkpcd_process_vk(vk);
                    const bool result = r1cs_mp_ppzkpcd_online_verifier(pvk, primary_input, proof);

                    return result;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_MP_PPZKPCD_HPP
