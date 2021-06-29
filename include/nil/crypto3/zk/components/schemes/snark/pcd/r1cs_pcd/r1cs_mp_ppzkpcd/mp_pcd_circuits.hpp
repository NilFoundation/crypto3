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
// @file Declaration of functionality for creating and using the two PCD circuits in
// a multi-predicate PCD construction.
//
// The implementation follows, extends, and optimizes the approach described
// in \[CTV15]. At high level, there is a "compliance step" circuit and a
// "translation step" circuit, for each compliance predicate. For more details,
// see \[CTV15].
//
//
// References:
//
// \[CTV15]:
// "Cluster Computing in Zero Knowledge",
// Alessandro Chiesa, Eran Tromer, Madars Virza
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_MP_PCD_CIRCUITS_HPP
#define CRYPTO3_ZK_BLUEPRINT_MP_PCD_CIRCUITS_HPP

#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/component_from_r1cs.hpp>
#include <nil/crypto3/zk/components/hashes/crh_component.hpp>
#include <nil/crypto3/zk/components/schemes/set_commitment/set_commitment_component.hpp>
#include <nil/crypto3/zk/components/schemes/snark/verifiers/r1cs_pp_zksnark/verifier.hpp>
#include <nil/crypto3/zk/components/schemes/snark/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**************************** Compliance step ********************************/

                /**
                 * A compliance-step PCD circuit.
                 *
                 * The circuit is an R1CS that checks compliance (for the given compliance predicate)
                 * and validity of previous proofs.
                 */
                template<typename CurveType>
                class mp_compliance_step_pcd_circuit_maker {

                    // for now all CRH components are knapsack CRH's; can be easily extended
                    // later to more expressive selector types.
                    template<typename FieldType>
                    using crh_with_field_out_component = knapsack_crh_with_field_out_component<FieldType>;

                    template<typename FieldType>
                    using crh_with_bit_out_component = knapsack_crh_with_bit_out_component<FieldType>;

                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    r1cs_pcd_compliance_predicate<FieldType> compliance_predicate;

                    blueprint<FieldType> bp;

                    blueprint_variable<FieldType> zero;

                    std::shared_ptr<block_variable<FieldType>> block_for_outgoing_message;
                    std::shared_ptr<crh_with_field_out_component<FieldType>> hash_outgoing_message;

                    std::vector<block_variable<FieldType>> block_for_incoming_messages;
                    std::vector<blueprint_variable_vector<FieldType>> commitment_and_incoming_message_digests;
                    std::vector<multipacking_component<FieldType>> unpack_commitment_and_incoming_message_digests;
                    std::vector<blueprint_variable_vector<FieldType>> commitment_and_incoming_messages_digest_bits;
                    std::vector<crh_with_field_out_component<FieldType>> hash_incoming_messages;

                    std::vector<r1cs_ppzksnark_verification_key_variable<CurveType>> translation_step_vks;
                    std::vector<blueprint_variable_vector<FieldType>> translation_step_vks_bits;

                    blueprint_variable<FieldType> outgoing_message_type;
                    blueprint_variable_vector<FieldType> outgoing_message_payload;
                    blueprint_variable_vector<FieldType> outgoing_message_vars;

                    blueprint_variable<FieldType> arity;
                    std::vector<blueprint_variable<FieldType>> incoming_message_types;
                    std::vector<blueprint_variable_vector<FieldType>> incoming_message_payloads;
                    std::vector<blueprint_variable_vector<FieldType>> incoming_message_vars;

                    blueprint_variable_vector<FieldType> local_data;
                    blueprint_variable_vector<FieldType> cp_witness;
                    std::shared_ptr<component_from_r1cs<FieldType>> compliance_predicate_as_component;

                    blueprint_variable_vector<FieldType> outgoing_message_bits;
                    std::shared_ptr<multipacking_component<FieldType>> unpack_outgoing_message;

                    std::vector<blueprint_variable_vector<FieldType>> incoming_messages_bits;
                    std::vector<multipacking_component<FieldType>> unpack_incoming_messages;

                    blueprint_variable_vector<FieldType> mp_compliance_step_pcd_circuit_input;
                    blueprint_variable_vector<FieldType> padded_translation_step_vk_and_outgoing_message_digest;
                    std::vector<blueprint_variable_vector<FieldType>> padded_commitment_and_incoming_messages_digest;

                    std::shared_ptr<set_commitment_variable<FieldType, crh_with_bit_out_component<FieldType>>>
                        commitment;
                    std::vector<set_membership_proof_variable<FieldType, crh_with_bit_out_component<FieldType>>>
                        membership_proofs;
                    std::vector<set_commitment_component<FieldType, crh_with_bit_out_component<FieldType>>>
                        membership_checkers;
                    blueprint_variable_vector<FieldType> membership_check_results;
                    blueprint_variable<FieldType> common_type;
                    blueprint_variable_vector<FieldType> common_type_check_aux;

                    std::vector<blueprint_variable_vector<FieldType>> verifier_input;
                    std::vector<r1cs_ppzksnark_proof_variable<CurveType>> proof;
                    blueprint_variable_vector<FieldType> verification_results;
                    std::vector<r1cs_ppzksnark_verifier_component<CurveType>> verifier;

                    mp_compliance_step_pcd_circuit_maker(
                        const r1cs_pcd_compliance_predicate<FieldType> &compliance_predicate,
                        const std::size_t max_number_of_predicates);
                    void generate_r1cs_constraints();
                    snark::r1cs_constraint_system<FieldType> get_circuit() const;

                    void generate_r1cs_witness(
                        const set_commitment &commitment_to_translation_step_r1cs_vks,
                        const std::vector<r1cs_ppzksnark_verification_key<other_curve<CurveType>>>
                            &mp_translation_step_pcd_circuit_vks,
                        const std::vector<set_membership_proof> &vk_membership_proofs,
                        const r1cs_pcd_compliance_predicate_primary_input<FieldType>
                            &compliance_predicate_primary_input,
                        const r1cs_pcd_compliance_predicate_auxiliary_input<FieldType>
                            &compliance_predicate_auxiliary_input,
                        const std::vector<r1cs_ppzksnark_proof<other_curve<CurveType>>> &translation_step_proofs);
                    snark::r1cs_primary_input<FieldType> get_primary_input() const;
                    snark::r1cs_auxiliary_input<FieldType> get_auxiliary_input() const;

                    static std::size_t field_logsize();
                    static std::size_t field_capacity();
                    static std::size_t input_size_in_elts();
                    static std::size_t input_capacity_in_bits();
                    static std::size_t input_size_in_bits();
                };

                /*************************** Translation step ********************************/

                /**
                 * A translation-step PCD circuit.
                 *
                 * The circuit is an R1CS that checks validity of previous proofs.
                 */
                template<typename CurveType>
                class mp_translation_step_pcd_circuit_maker {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    blueprint<FieldType> bp;

                    blueprint_variable_vector<FieldType> mp_translation_step_pcd_circuit_input;
                    blueprint_variable_vector<FieldType> unpacked_mp_translation_step_pcd_circuit_input;
                    blueprint_variable_vector<FieldType> verifier_input;
                    std::shared_ptr<multipacking_component<FieldType>> unpack_mp_translation_step_pcd_circuit_input;

                    std::shared_ptr<r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType>>
                        hardcoded_compliance_step_vk;
                    std::shared_ptr<r1cs_ppzksnark_proof_variable<CurveType>> proof;
                    std::shared_ptr<r1cs_ppzksnark_online_verifier_component<CurveType>> online_verifier;

                    mp_translation_step_pcd_circuit_maker(
                        const r1cs_ppzksnark_verification_key<other_curve<CurveType>> &compliance_step_vk);
                    void generate_r1cs_constraints();
                    snark::r1cs_constraint_system<FieldType> get_circuit() const;

                    void generate_r1cs_witness(const snark::r1cs_primary_input<typename CurveType::scalar_field_type>
                                                   translation_step_input,
                                               const r1cs_ppzksnark_proof<other_curve<CurveType>> &prev_proof);
                    snark::r1cs_primary_input<FieldType> get_primary_input() const;
                    snark::r1cs_auxiliary_input<FieldType> get_auxiliary_input() const;

                    static std::size_t field_logsize();
                    static std::size_t field_capacity();
                    static std::size_t input_size_in_elts();
                    static std::size_t input_capacity_in_bits();
                    static std::size_t input_size_in_bits();
                };

                /****************************** Input maps ***********************************/

                /**
                 * Obtain the primary input for a compliance-step PCD circuit.
                 */
                template<typename CurveType>
                snark::r1cs_primary_input<typename CurveType::scalar_field_type>
                    get_mp_compliance_step_pcd_circuit_input(
                        const set_commitment &commitment_to_translation_step_r1cs_vks,
                        const r1cs_pcd_compliance_predicate_primary_input<typename CurveType::scalar_field_type>
                            &primary_input);

                /**
                 * Obtain the primary input for a translation-step PCD circuit.
                 */
                template<typename CurveType>
                snark::r1cs_primary_input<typename CurveType::scalar_field_type>
                    get_mp_translation_step_pcd_circuit_input(
                        const set_commitment &commitment_to_translation_step_r1cs_vks,
                        const r1cs_pcd_compliance_predicate_primary_input<other_curve<CurveType>::scalar_field_type>
                            &primary_input);

                template<typename CurveType>
                mp_compliance_step_pcd_circuit_maker<CurveType>::mp_compliance_step_pcd_circuit_maker(
                    const r1cs_pcd_compliance_predicate<FieldType> &compliance_predicate,
                    const std::size_t max_number_of_predicates) :
                    compliance_predicate(compliance_predicate) {
                    /* calculate some useful sizes */
                    const std::size_t digest_size = crh_with_field_out_component<FieldType>::get_digest_len();
                    const std::size_t outgoing_msg_size_in_bits =
                        field_logsize() * (1 + compliance_predicate.outgoing_message_payload_length);
                    assert(compliance_predicate.has_equal_input_lengths());
                    const std::size_t translation_step_vk_size_in_bits =
                        r1cs_ppzksnark_verification_key_variable<CurveType>::size_in_bits(
                            mp_translation_step_pcd_circuit_maker<other_curve<CurveType>>::input_size_in_elts());
                    const std::size_t padded_verifier_input_size =
                        mp_translation_step_pcd_circuit_maker<other_curve<CurveType>>::input_capacity_in_bits();
                    const std::size_t commitment_size =
                        set_commitment_component<FieldType, crh_with_bit_out_component<FieldType>>::root_size_in_bits();

                    const std::size_t output_block_size = commitment_size + outgoing_msg_size_in_bits;
                    const std::size_t max_incoming_payload_length =
                        *std::max_element(compliance_predicate.incoming_message_payload_lengths.begin(),
                                          compliance_predicate.incoming_message_payload_lengths.end());
                    const std::size_t max_input_block_size =
                        commitment_size + field_logsize() * (1 + max_incoming_payload_length);

                    crh_with_bit_out_component<FieldType>::sample_randomness(
                        std::max(output_block_size, max_input_block_size));

                    /* allocate input of the compliance MP_PCD circuit */
                    mp_compliance_step_pcd_circuit_input.allocate(bp, input_size_in_elts());

                    /* allocate inputs to the compliance predicate */
                    outgoing_message_type.allocate(bp);
                    outgoing_message_payload.allocate(bp, compliance_predicate.outgoing_message_payload_length);

                    outgoing_message_vars.insert(outgoing_message_vars.end(), outgoing_message_type);
                    outgoing_message_vars.insert(outgoing_message_vars.end(), outgoing_message_payload.begin(),
                                                 outgoing_message_payload.end());

                    arity.allocate(bp);

                    incoming_message_types.resize(compliance_predicate.max_arity);
                    incoming_message_payloads.resize(compliance_predicate.max_arity);
                    incoming_message_vars.resize(compliance_predicate.max_arity);
                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        incoming_message_types[i].allocate(bp);
                        incoming_message_payloads[i].allocate(bp,
                                                              compliance_predicate.incoming_message_payload_lengths[i]);

                        incoming_message_vars[i].insert(incoming_message_vars[i].end(), incoming_message_types[i]);
                        incoming_message_vars[i].insert(incoming_message_vars[i].end(),
                                                        incoming_message_payloads[i].begin(),
                                                        incoming_message_payloads[i].end());
                    }

                    local_data.allocate(bp, compliance_predicate.local_data_length);
                    cp_witness.allocate(bp, compliance_predicate.witness_length);

                    /* convert compliance predicate from a constraint system into a component */
                    blueprint_variable_vector<FieldType> incoming_messages_concat;
                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        incoming_messages_concat.insert(incoming_messages_concat.end(),
                                                        incoming_message_vars[i].begin(),
                                                        incoming_message_vars[i].end());
                    }

                    compliance_predicate_as_component.reset(new component_from_r1cs<FieldType>(
                        bp,
                        {outgoing_message_vars, blueprint_variable_vector<FieldType>(1, arity),
                         incoming_messages_concat, local_data, cp_witness},
                        compliance_predicate.constraint_system));

                    /* unpack messages to bits */
                    outgoing_message_bits.allocate(bp, outgoing_msg_size_in_bits);
                    unpack_outgoing_message.reset(new multipacking_component<FieldType>(
                        bp, outgoing_message_bits, outgoing_message_vars, field_logsize()));

                    incoming_messages_bits.resize(compliance_predicate.max_arity);
                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        const std::size_t incoming_msg_size_in_bits =
                            field_logsize() * (1 + compliance_predicate.incoming_message_payload_lengths[i]);

                        incoming_messages_bits[i].allocate(bp, incoming_msg_size_in_bits);
                        unpack_incoming_messages.emplace_back(multipacking_component<FieldType>(
                            bp, incoming_messages_bits[i], incoming_message_vars[i], field_logsize()));
                    }

                    /* allocate digests */
                    commitment_and_incoming_message_digests.resize(compliance_predicate.max_arity);
                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        commitment_and_incoming_message_digests[i].allocate(bp, digest_size);
                    }

                    /* allocate commitment, verification key(s) and membership checker(s)/proof(s) */
                    commitment.reset(new set_commitment_variable<FieldType, crh_with_bit_out_component<FieldType>>(
                        bp, commitment_size));

                    if (compliance_predicate.relies_on_same_type_inputs) {
                        /* only one set_commitment_component is needed */
                        common_type.allocate(bp);
                        common_type_check_aux.allocate(bp, compliance_predicate.accepted_input_types.size());

                        translation_step_vks_bits.resize(1);
                        translation_step_vks_bits[0].allocate(bp, translation_step_vk_size_in_bits);
                        membership_check_results.allocate(bp, 1);

                        membership_proofs.emplace_back(
                            set_membership_proof_variable<FieldType, crh_with_bit_out_component<FieldType>>(
                                bp, max_number_of_predicates));
                        membership_checkers.emplace_back(
                            set_commitment_component<FieldType, crh_with_bit_out_component<FieldType>>(
                                bp, max_number_of_predicates, translation_step_vks_bits[0], *commitment,
                                membership_proofs[0], membership_check_results[0]));
                    } else {
                        /* check for max_arity possibly different VKs */
                        translation_step_vks_bits.resize(compliance_predicate.max_arity);
                        membership_check_results.allocate(bp, compliance_predicate.max_arity);

                        for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                            translation_step_vks_bits[i].allocate(bp, translation_step_vk_size_in_bits);

                            membership_proofs.emplace_back(
                                set_membership_proof_variable<FieldType, crh_with_bit_out_component<FieldType>>(
                                    bp, max_number_of_predicates));
                            membership_checkers.emplace_back(
                                set_commitment_component<FieldType, crh_with_bit_out_component<FieldType>>(
                                    bp,
                                    max_number_of_predicates,
                                    translation_step_vks_bits[i],
                                    *commitment,
                                    membership_proofs[i],
                                    membership_check_results[i]));
                        }
                    }

                    /* allocate blocks */
                    block_for_outgoing_message.reset(
                        new block_variable<FieldType>(bp, {commitment->bits, outgoing_message_bits}));

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        block_for_incoming_messages.emplace_back(
                            block_variable<FieldType>(bp, {commitment->bits, incoming_messages_bits[i]}));
                    }

                    /* allocate hash checkers */
                    hash_outgoing_message.reset(new crh_with_field_out_component<FieldType>(
                        bp, output_block_size, *block_for_outgoing_message, mp_compliance_step_pcd_circuit_input));

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        const std::size_t input_block_size = commitment_size + incoming_messages_bits[i].size();
                        hash_incoming_messages.emplace_back(crh_with_field_out_component<FieldType>(
                            bp, input_block_size, block_for_incoming_messages[i],
                            commitment_and_incoming_message_digests[i]));
                    }

                    /* allocate useful zero variable */
                    zero.allocate(bp);

                    /* prepare arguments for the verifier */
                    if (compliance_predicate.relies_on_same_type_inputs) {
                        translation_step_vks.emplace_back(r1cs_ppzksnark_verification_key_variable<CurveType>(
                            bp, translation_step_vks_bits[0],
                            mp_translation_step_pcd_circuit_maker<other_curve<CurveType>>::input_size_in_elts()));
                    } else {
                        for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                            translation_step_vks.emplace_back(r1cs_ppzksnark_verification_key_variable<CurveType>(
                                bp, translation_step_vks_bits[i],
                                mp_translation_step_pcd_circuit_maker<other_curve<CurveType>>::input_size_in_elts()));
                        }
                    }

                    verification_results.allocate(bp, compliance_predicate.max_arity);
                    commitment_and_incoming_messages_digest_bits.resize(compliance_predicate.max_arity);

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        commitment_and_incoming_messages_digest_bits[i].allocate(bp, digest_size * field_logsize());
                        unpack_commitment_and_incoming_message_digests.emplace_back(
                            multipacking_component<FieldType>(bp,
                                                              commitment_and_incoming_messages_digest_bits[i],
                                                              commitment_and_incoming_message_digests[i],
                                                              field_logsize()));

                        verifier_input.emplace_back(commitment_and_incoming_messages_digest_bits[i]);
                        while (verifier_input[i].size() < padded_verifier_input_size) {
                            verifier_input[i].emplace_back(zero);
                        }

                        proof.emplace_back(r1cs_ppzksnark_proof_variable<CurveType>(bp));
                        const r1cs_ppzksnark_verification_key_variable<CurveType> &vk_to_be_used =
                            (compliance_predicate.relies_on_same_type_inputs ? translation_step_vks[0] :
                                                                               translation_step_vks[i]);
                        verifier.emplace_back(r1cs_ppzksnark_verifier_component<CurveType>(
                            bp,
                            vk_to_be_used,
                            verifier_input[i],
                            mp_translation_step_pcd_circuit_maker<other_curve<CurveType>>::field_capacity(),
                            proof[i],
                            verification_results[i]));
                    }

                    bp.set_input_sizes(input_size_in_elts());
                }

                template<typename CurveType>
                void mp_compliance_step_pcd_circuit_maker<CurveType>::generate_r1cs_constraints() {
                    const std::size_t digest_size = crh_with_bit_out_component<FieldType>::get_digest_len();
                    const std::size_t dimension = knapsack_dimension<FieldType>::dimension;
                    unpack_outgoing_message->generate_r1cs_constraints(true);

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        unpack_incoming_messages[i].generate_r1cs_constraints(true);
                    }

                    for (std::size_t i = 0; i < translation_step_vks.size(); ++i) {
                        translation_step_vks[i].generate_r1cs_constraints(true);
                    }

                    hash_outgoing_message->generate_r1cs_constraints();

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        hash_incoming_messages[i].generate_r1cs_constraints();
                    }

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        unpack_commitment_and_incoming_message_digests[i].generate_r1cs_constraints(true);
                    }

                    for (auto &membership_proof : membership_proofs) {
                        membership_proof.generate_r1cs_constraints();
                    }

                    for (auto &membership_checker : membership_checkers) {
                        membership_checker.generate_r1cs_constraints();
                    }

                    compliance_predicate_as_component->generate_r1cs_constraints();

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        proof[i].generate_r1cs_constraints();
                    }

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        verifier[i].generate_r1cs_constraints();
                    }

                    generate_r1cs_equals_const_constraint<FieldType>(bp, zero, FieldType::value_type::zero());

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        generate_boolean_r1cs_constraint<FieldType>(bp, verification_results[i]);
                    }

                    /* either type = 0 or proof verified w.r.t. a valid verification key */
                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(incoming_message_types[i],
                                                                                 1 - verification_results[i], 0));
                    }

                    if (compliance_predicate.relies_on_same_type_inputs) {

                        for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                            bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                incoming_message_types[i], incoming_message_types[i] - common_type, 0));
                        }

                        bp.add_r1cs_constraint(
                            snark::r1cs_constraint<FieldType>(common_type, 1 - membership_check_results[0], 0));

                        auto it = compliance_predicate.accepted_input_types.begin();
                        for (std::size_t i = 0; i < compliance_predicate.accepted_input_types.size(); ++i, ++it) {
                            bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                (i == 0 ? common_type : common_type_check_aux[i - 1]),
                                common_type - typename FieldType::value_type(*it),
                                (i == compliance_predicate.accepted_input_types.size() - 1 ?
                                     0 * blueprint_variable<FieldType>(0) :
                                     common_type_check_aux[i])));
                        }
                    } else {
                        for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                            bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                incoming_message_types[i], 1 - membership_check_results[i], 0));
                        }
                    }
                    bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                        1, outgoing_message_type, typename FieldType::value_type(compliance_predicate.type)));
                }

                template<typename CurveType>
                snark::r1cs_constraint_system<typename CurveType::scalar_field_type>
                    mp_compliance_step_pcd_circuit_maker<CurveType>::get_circuit() const {
                    return bp.get_constraint_system();
                }

                template<typename CurveType>
                snark::r1cs_primary_input<typename CurveType::scalar_field_type>
                    mp_compliance_step_pcd_circuit_maker<CurveType>::get_primary_input() const {
                    return bp.primary_input();
                }

                template<typename CurveType>
                snark::r1cs_auxiliary_input<typename CurveType::scalar_field_type>
                    mp_compliance_step_pcd_circuit_maker<CurveType>::get_auxiliary_input() const {
                    return bp.auxiliary_input();
                }

                template<typename CurveType>
                void mp_compliance_step_pcd_circuit_maker<CurveType>::generate_r1cs_witness(
                    const set_commitment &commitment_to_translation_step_r1cs_vks,
                    const std::vector<r1cs_ppzksnark_verification_key<other_curve<CurveType>>>
                        &mp_translation_step_pcd_circuit_vks,
                    const std::vector<set_membership_proof> &vk_membership_proofs,
                    const r1cs_pcd_compliance_predicate_primary_input<FieldType> &compliance_predicate_primary_input,
                    const r1cs_pcd_compliance_predicate_auxiliary_input<FieldType>
                        &compliance_predicate_auxiliary_input,
                    const std::vector<r1cs_ppzksnark_proof<other_curve<CurveType>>> &translation_step_proofs) {

                    this->bp.clear_values();
                    this->bp.val(zero) = FieldType::value_type::zero();

                    compliance_predicate_as_component->generate_r1cs_witness(
                        compliance_predicate_primary_input.as_r1cs_primary_input(),
                        compliance_predicate_auxiliary_input.as_r1cs_auxiliary_input(
                            compliance_predicate.incoming_message_payload_lengths));

                    unpack_outgoing_message->generate_r1cs_witness_from_packed();
                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        unpack_incoming_messages[i].generate_r1cs_witness_from_packed();
                    }

                    for (std::size_t i = 0; i < translation_step_vks.size(); ++i) {
                        translation_step_vks[i].generate_r1cs_witness(mp_translation_step_pcd_circuit_vks[i]);
                    }

                    commitment->generate_r1cs_witness(commitment_to_translation_step_r1cs_vks);

                    if (compliance_predicate.relies_on_same_type_inputs) {
                        /* all messages (except base case) must be of the same type */
                        this->bp.val(common_type) = FieldType::value_type::zero();
                        std::size_t nonzero_type_idx = 0;
                        for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                            if (this->bp.val(incoming_message_types[i]) == 0) {
                                continue;
                            }

                            if (this->bp.val(common_type).is_zero()) {
                                this->bp.val(common_type) = this->bp.val(incoming_message_types[i]);
                                nonzero_type_idx = i;
                            } else {
                                assert(this->bp.val(common_type) == this->bp.val(incoming_message_types[i]));
                            }
                        }

                        this->bp.val(membership_check_results[0]) =
                            (this->bp.val(common_type).is_zero() ? FieldType::value_type::zero() :
                                                                   FieldType::value_type::zero());
                        membership_proofs[0].generate_r1cs_witness(vk_membership_proofs[nonzero_type_idx]);
                        membership_checkers[0].generate_r1cs_witness();

                        auto it = compliance_predicate.accepted_input_types.begin();
                        for (std::size_t i = 0; i < compliance_predicate.accepted_input_types.size(); ++i, ++it) {
                            bp.val(common_type_check_aux[i]) =
                                ((i == 0 ? bp.val(common_type) : bp.val(common_type_check_aux[i - 1])) *
                                 (bp.val(common_type) - typename FieldType::value_type(*it)));
                        }

                    } else {
                        for (std::size_t i = 0; i < membership_checkers.size(); ++i) {
                            this->bp.val(membership_check_results[i]) =
                                (this->bp.val(incoming_message_types[i]).is_zero() ? FieldType::value_type::zero() :
                                                                                     FieldType::value_type::zero());
                            membership_proofs[i].generate_r1cs_witness(vk_membership_proofs[i]);
                            membership_checkers[i].generate_r1cs_witness();
                        }
                    }

                    hash_outgoing_message->generate_r1cs_witness();
                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        hash_incoming_messages[i].generate_r1cs_witness();
                        unpack_commitment_and_incoming_message_digests[i].generate_r1cs_witness_from_packed();
                    }

                    for (std::size_t i = 0; i < compliance_predicate.max_arity; ++i) {
                        proof[i].generate_r1cs_witness(translation_step_proofs[i]);
                        verifier[i].generate_r1cs_witness();
                    }
                }

                template<typename CurveType>
                std::size_t mp_compliance_step_pcd_circuit_maker<CurveType>::field_logsize() {
                    return typename CurveType::scalar_field_type::value_bits;
                }

                template<typename CurveType>
                std::size_t mp_compliance_step_pcd_circuit_maker<CurveType>::field_capacity() {
                    return typename CurveType::scalar_field_type::capacity();
                }

                template<typename CurveType>
                std::size_t mp_compliance_step_pcd_circuit_maker<CurveType>::input_size_in_elts() {
                    const std::size_t digest_size = crh_with_field_out_component<FieldType>::get_digest_len();
                    return digest_size;
                }

                template<typename CurveType>
                std::size_t mp_compliance_step_pcd_circuit_maker<CurveType>::input_capacity_in_bits() {
                    return input_size_in_elts() * field_capacity();
                }

                template<typename CurveType>
                std::size_t mp_compliance_step_pcd_circuit_maker<CurveType>::input_size_in_bits() {
                    return input_size_in_elts() * field_logsize();
                }

                template<typename CurveType>
                mp_translation_step_pcd_circuit_maker<CurveType>::mp_translation_step_pcd_circuit_maker(
                    const r1cs_ppzksnark_verification_key<other_curve<CurveType>> &compliance_step_vk) {
                    /* allocate input of the translation MP_PCD circuit */
                    mp_translation_step_pcd_circuit_input.allocate(bp, input_size_in_elts());

                    /* unpack translation step MP_PCD circuit input */
                    unpacked_mp_translation_step_pcd_circuit_input.allocate(
                        bp, mp_compliance_step_pcd_circuit_maker<other_curve<CurveType>>::input_size_in_bits());
                    unpack_mp_translation_step_pcd_circuit_input.reset(
                        new multipacking_component<FieldType>(bp, unpacked_mp_translation_step_pcd_circuit_input,
                                                              mp_translation_step_pcd_circuit_input, field_capacity()));

                    /* prepare arguments for the verifier */
                    hardcoded_compliance_step_vk.reset(
                        new r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType>(
                            bp, compliance_step_vk));
                    proof.reset(new r1cs_ppzksnark_proof_variable<CurveType>(bp));

                    /* verify previous proof */
                    online_verifier.reset(new r1cs_ppzksnark_online_verifier_component<CurveType>(
                        bp,
                        *hardcoded_compliance_step_vk,
                        unpacked_mp_translation_step_pcd_circuit_input,
                        mp_compliance_step_pcd_circuit_maker<other_curve<CurveType>>::field_logsize(),
                        *proof,
                        blueprint_variable<FieldType>(0)));

                    bp.set_input_sizes(input_size_in_elts());
                }

                template<typename CurveType>
                void mp_translation_step_pcd_circuit_maker<CurveType>::generate_r1cs_constraints() {
                    unpack_mp_translation_step_pcd_circuit_input->generate_r1cs_constraints(true);

                    proof->generate_r1cs_constraints();

                    online_verifier->generate_r1cs_constraints();
                }

                template<typename CurveType>
                snark::r1cs_constraint_system<typename CurveType::scalar_field_type>
                    mp_translation_step_pcd_circuit_maker<CurveType>::get_circuit() const {
                    return bp.get_constraint_system();
                }

                template<typename CurveType>
                void mp_translation_step_pcd_circuit_maker<CurveType>::generate_r1cs_witness(
                    const snark::r1cs_primary_input<typename CurveType::scalar_field_type>
                        translation_step_input,
                    const r1cs_ppzksnark_proof<other_curve<CurveType>> &prev_proof) {
                    this->bp.clear_values();
                    mp_translation_step_pcd_circuit_input.fill_with_field_elements(bp, translation_step_input);
                    unpack_mp_translation_step_pcd_circuit_input->generate_r1cs_witness_from_packed();

                    proof->generate_r1cs_witness(prev_proof);
                    online_verifier->generate_r1cs_witness();
                }

                template<typename CurveType>
                snark::r1cs_primary_input<typename CurveType::scalar_field_type>
                    mp_translation_step_pcd_circuit_maker<CurveType>::get_primary_input() const {
                    return bp.primary_input();
                }

                template<typename CurveType>
                snark::r1cs_auxiliary_input<typename CurveType::scalar_field_type>
                    mp_translation_step_pcd_circuit_maker<CurveType>::get_auxiliary_input() const {
                    return bp.auxiliary_input();
                }

                template<typename CurveType>
                std::size_t mp_translation_step_pcd_circuit_maker<CurveType>::field_logsize() {
                    return typename CurveType::scalar_field_type::value_bits;
                }

                template<typename CurveType>
                std::size_t mp_translation_step_pcd_circuit_maker<CurveType>::field_capacity() {
                    return typename CurveType::scalar_field_type::capacity();
                }

                template<typename CurveType>
                std::size_t mp_translation_step_pcd_circuit_maker<CurveType>::input_size_in_elts() {
                    return algebra::div_ceil(
                        mp_compliance_step_pcd_circuit_maker<other_curve<CurveType>>::input_size_in_bits(),
                        mp_translation_step_pcd_circuit_maker<CurveType>::field_capacity());
                }

                template<typename CurveType>
                std::size_t mp_translation_step_pcd_circuit_maker<CurveType>::input_capacity_in_bits() {
                    return input_size_in_elts() * field_capacity();
                }

                template<typename CurveType>
                std::size_t mp_translation_step_pcd_circuit_maker<CurveType>::input_size_in_bits() {
                    return input_size_in_elts() * field_logsize();
                }

                template<typename CurveType>
                snark::r1cs_primary_input<typename CurveType::scalar_field_type>
                    get_mp_compliance_step_pcd_circuit_input(
                        const set_commitment &commitment_to_translation_step_r1cs_vks,
                        const r1cs_pcd_compliance_predicate_primary_input<typename CurveType::scalar_field_type>
                            &primary_input) {
                    typedef typename CurveType::scalar_field_type FieldType;

                    const snark::r1cs_variable_assignment<FieldType> outgoing_message_as_va =
                        primary_input.outgoing_message->as_r1cs_variable_assignment();
                    std::vector<bool> msg_bits;
                    for (const typename FieldType::value_type &elt : outgoing_message_as_va) {
                        const std::vector<bool> elt_bits = algebra::convert_field_element_to_bit_vector(elt);
                        msg_bits.insert(msg_bits.end(), elt_bits.begin(), elt_bits.end());
                    }

                    std::vector<bool> block;
                    block.insert(block.end(), commitment_to_translation_step_r1cs_vks.begin(),
                                 commitment_to_translation_step_r1cs_vks.end());
                    block.insert(block.end(), msg_bits.begin(), msg_bits.end());

                    crh_with_field_out_component<FieldType>::sample_randomness(block.size());

                    const std::vector<typename FieldType::value_type> digest =
                        crh_with_field_out_component<FieldType>::get_hash(block);

                    return digest;
                }

                template<typename CurveType>
                snark::r1cs_primary_input<typename CurveType::scalar_field_type>
                    get_mp_translation_step_pcd_circuit_input(
                        const set_commitment &commitment_to_translation_step_r1cs_vks,
                        const r1cs_pcd_compliance_predicate_primary_input <
                                other_curve<CurveType>::scalar_field_type::value_type &
                            primary_input) {
                    typedef typename CurveType::scalar_field_type FieldType;

                    const std::vector <
                        other_curve<CurveType>::scalar_field_type::value_type mp_compliance_step_pcd_circuit_input =
                        get_mp_compliance_step_pcd_circuit_input<other_curve<CurveType>>(
                            commitment_to_translation_step_r1cs_vks, primary_input);
                    std::vector<bool> mp_compliance_step_pcd_circuit_input_bits;
                    for (const other_curve<CurveType>::scalar_field_type::value_type &elt :
                         mp_compliance_step_pcd_circuit_input) {
                        const std::vector<bool> elt_bits = algebra::convert_field_element_to_bit_vector <
                                                           other_curve<CurveType>::scalar_field_type::value_type(elt);
                        mp_compliance_step_pcd_circuit_input_bits.insert(
                            mp_compliance_step_pcd_circuit_input_bits.end(), elt_bits.begin(), elt_bits.end());
                    }

                    mp_compliance_step_pcd_circuit_input_bits.resize(
                        mp_translation_step_pcd_circuit_maker<CurveType>::input_capacity_in_bits(), false);

                    const snark::r1cs_primary_input<FieldType> result =
                        algebra::pack_bit_vector_into_field_element_vector<FieldType>(
                            mp_compliance_step_pcd_circuit_input_bits,
                            mp_translation_step_pcd_circuit_maker<CurveType>::field_capacity());
                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_MP_PCD_CIRCUITS_HPP
