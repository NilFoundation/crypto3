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
// a single-predicate PCD construction.
//
// The implementation follows, extends, and optimizes the approach described
// in \[BCTV14]. At high level, there is a "compliance step" circuit and a
// "translation step" circuit. For more details see Section 4 of \[BCTV14].
//
//
// References:
//
// \[BCTV14]:
// "Scalable Zero Knowledge via Cycles of Elliptic Curves",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// CRYPTO 2014,
// <http://eprint.iacr.org/2014/595>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_SP_PCD_CIRCUITS_HPP
#define CRYPTO3_ZK_SP_PCD_CIRCUITS_HPP

#include <nil/crypto3/zk/snark/components/component_from_r1cs.hpp>
#include <nil/crypto3/zk/snark/components/hashes/crh_component.hpp>
#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>
#include <nil/crypto3/zk/snark/components/verifiers/r1cs_ppzksnark_verifier_component.hpp>

#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp>

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
                class sp_compliance_step_pcd_circuit_maker {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    r1cs_pcd_compliance_predicate<FieldType> compliance_predicate;

                    blueprint<FieldType> bp;

                    variable<FieldType> zero;

                    std::shared_ptr<block_variable<FieldType>> block_for_outgoing_message;
                    std::shared_ptr<crh_with_field_out_component<FieldType>> hash_outgoing_message;

                    std::vector<block_variable<FieldType>> blocks_for_incoming_messages;
                    std::vector<blueprint_variable_vector<FieldType>>
                        sp_translation_step_vk_and_incoming_message_payload_digests;
                    std::vector<multipacking_component<FieldType>>
                        unpack_sp_translation_step_vk_and_incoming_message_payload_digests;
                    std::vector<blueprint_variable_vector<FieldType>>
                        sp_translation_step_vk_and_incoming_message_payload_digest_bits;
                    std::vector<crh_with_field_out_component<FieldType>> hash_incoming_messages;

                    std::shared_ptr<r1cs_ppzksnark_verification_key_variable<CurveType>> sp_translation_step_vk;
                    blueprint_variable_vector<FieldType> sp_translation_step_vk_bits;

                    variable<FieldType> outgoing_message_type;
                    blueprint_variable_vector<FieldType> outgoing_message_payload;
                    blueprint_variable_vector<FieldType> outgoing_message_vars;

                    variable<FieldType> arity;
                    std::vector<variable<FieldType>> incoming_message_types;
                    std::vector<blueprint_variable_vector<FieldType>> incoming_message_payloads;
                    std::vector<blueprint_variable_vector<FieldType>> incoming_message_vars;

                    blueprint_variable_vector<FieldType> local_data;
                    blueprint_variable_vector<FieldType> cp_witness;
                    std::shared_ptr<component_from_r1cs<FieldType>> compliance_predicate_as_component;

                    blueprint_variable_vector<FieldType> outgoing_message_bits;
                    std::shared_ptr<multipacking_component<FieldType>> unpack_outgoing_message;

                    std::vector<blueprint_variable_vector<FieldType>> incoming_messages_bits;
                    std::vector<multipacking_component<FieldType>> unpack_incoming_messages;

                    blueprint_variable_vector<FieldType> sp_compliance_step_pcd_circuit_input;
                    blueprint_variable_vector<FieldType> padded_translation_step_vk_and_outgoing_message_digest;
                    std::vector<blueprint_variable_vector<FieldType>>
                        padded_translation_step_vk_and_incoming_messages_digests;

                    std::vector<blueprint_variable_vector<FieldType>> verifier_input;
                    std::vector<r1cs_ppzksnark_proof_variable<CurveType>> proof;
                    variable<FieldType> verification_result;
                    std::vector<r1cs_ppzksnark_verifier_component<CurveType>> verifiers;

                    sp_compliance_step_pcd_circuit_maker(
                        const r1cs_pcd_compliance_predicate<FieldType> &compliance_predicate);
                    void generate_r1cs_constraints();
                    r1cs_constraint_system<FieldType> get_circuit() const;

                    void generate_r1cs_witness(
                        const r1cs_ppzksnark_verification_key<other_curve<CurveType>> &translation_step_pcd_circuit_vk,
                        const r1cs_pcd_compliance_predicate_primary_input<FieldType>
                            &compliance_predicate_primary_input,
                        const r1cs_pcd_compliance_predicate_auxiliary_input<FieldType>
                            &compliance_predicate_auxiliary_input,
                        const std::vector<r1cs_ppzksnark_proof<other_curve<CurveType>>> &incoming_proofs);
                    r1cs_primary_input<FieldType> get_primary_input() const;
                    r1cs_auxiliary_input<FieldType> get_auxiliary_input() const;

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
                class sp_translation_step_pcd_circuit_maker {
                public:
                    typedef typename CurveType::scalar_field_type FieldType;

                    blueprint<FieldType> bp;

                    blueprint_variable_vector<FieldType> sp_translation_step_pcd_circuit_input;
                    blueprint_variable_vector<FieldType> unpacked_sp_translation_step_pcd_circuit_input;
                    blueprint_variable_vector<FieldType> verifier_input;
                    std::shared_ptr<multipacking_component<FieldType>> unpack_sp_translation_step_pcd_circuit_input;

                    std::shared_ptr<r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType>>
                        hardcoded_sp_compliance_step_vk;
                    std::shared_ptr<r1cs_ppzksnark_proof_variable<CurveType>> proof;
                    std::shared_ptr<r1cs_ppzksnark_online_verifier_component<CurveType>> online_verifier;

                    sp_translation_step_pcd_circuit_maker(
                        const r1cs_ppzksnark_verification_key<other_curve<CurveType>> &compliance_step_vk);
                    void generate_r1cs_constraints();
                    r1cs_constraint_system<FieldType> get_circuit() const;

                    void generate_r1cs_witness(
                        const r1cs_primary_input<typename CurveType::scalar_field_type>
                            translation_step_input,
                        const r1cs_ppzksnark_proof<other_curve<CurveType>> &compliance_step_proof);
                    r1cs_primary_input<FieldType> get_primary_input() const;
                    r1cs_auxiliary_input<FieldType> get_auxiliary_input() const;

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
                r1cs_primary_input<typename CurveType::scalar_field_type> get_sp_compliance_step_pcd_circuit_input(
                    const std::vector<bool> &sp_translation_step_vk_bits,
                    const r1cs_pcd_compliance_predicate_primary_input<typename CurveType::scalar_field_type>
                        &primary_input);

                /**
                 * Obtain the primary input for a translation-step PCD circuit.
                 */
                template<typename CurveType>
                r1cs_primary_input<typename CurveType::scalar_field_type> get_sp_translation_step_pcd_circuit_input(
                    const std::vector<bool> &sp_translation_step_vk_bits,
                    const r1cs_pcd_compliance_predicate_primary_input<
                        other_curve<CurveType>::scalar_field_type::value_type> &primary_input);

                template<typename CurveType>
                sp_compliance_step_pcd_circuit_maker<CurveType>::sp_compliance_step_pcd_circuit_maker(
                    const r1cs_pcd_compliance_predicate<FieldType> &compliance_predicate) :
                    compliance_predicate(compliance_predicate) {
                    /* calculate some useful sizes */
                    assert(compliance_predicate.is_well_formed());
                    assert(compliance_predicate.has_equal_input_and_output_lengths());

                    const std::size_t compliance_predicate_arity = compliance_predicate.max_arity;
                    const std::size_t digest_size = crh_with_field_out_component<FieldType>::get_digest_len();
                    const std::size_t msg_size_in_bits =
                        field_logsize() * (1 + compliance_predicate.outgoing_message_payload_length);
                    const std::size_t sp_translation_step_vk_size_in_bits =
                        r1cs_ppzksnark_verification_key_variable<CurveType>::size_in_bits(
                            sp_translation_step_pcd_circuit_maker<other_curve<CurveType>>::input_size_in_elts());
                    const std::size_t padded_verifier_input_size =
                        sp_translation_step_pcd_circuit_maker<other_curve<CurveType>>::input_capacity_in_bits();

                    const std::size_t block_size = msg_size_in_bits + sp_translation_step_vk_size_in_bits;
                    crh_with_bit_out_component<FieldType>::sample_randomness(block_size);

                    /* allocate input of the compliance PCD circuit */
                    sp_compliance_step_pcd_circuit_input.allocate(bp, input_size_in_elts());

                    /* allocate inputs to the compliance predicate */
                    outgoing_message_type.allocate(bp);
                    outgoing_message_payload.allocate(bp, compliance_predicate.outgoing_message_payload_length);

                    outgoing_message_vars.insert(outgoing_message_vars.end(), outgoing_message_type);
                    outgoing_message_vars.insert(outgoing_message_vars.end(), outgoing_message_payload.begin(),
                                                 outgoing_message_payload.end());

                    arity.allocate(bp);

                    incoming_message_types.resize(compliance_predicate_arity);
                    incoming_message_payloads.resize(compliance_predicate_arity);
                    incoming_message_vars.resize(compliance_predicate_arity);
                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        incoming_message_types[i].allocate(bp);
                        incoming_message_payloads[i].allocate(bp, compliance_predicate.outgoing_message_payload_length);

                        incoming_message_vars[i].insert(incoming_message_vars[i].end(), incoming_message_types[i]);
                        incoming_message_vars[i].insert(incoming_message_vars[i].end(),
                                                        incoming_message_payloads[i].begin(),
                                                        incoming_message_payloads[i].end());
                    }

                    local_data.allocate(bp, compliance_predicate.local_data_length);
                    cp_witness.allocate(bp, compliance_predicate.witness_length);

                    /* convert compliance predicate from a constraint system into a component */
                    blueprint_variable_vector<FieldType> incoming_messages_concat;
                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
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
                    outgoing_message_bits.allocate(bp, msg_size_in_bits);
                    unpack_outgoing_message.reset(new multipacking_component<FieldType>(
                        bp, outgoing_message_bits, outgoing_message_vars, field_logsize()));

                    incoming_messages_bits.resize(compliance_predicate_arity);
                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        incoming_messages_bits[i].allocate(bp, msg_size_in_bits);
                        unpack_incoming_messages.emplace_back(multipacking_component<FieldType>(
                            bp, incoming_messages_bits[i], incoming_message_vars[i], field_logsize()));
                    }

                    /* allocate digests */
                    sp_translation_step_vk_and_incoming_message_payload_digests.resize(compliance_predicate_arity);
                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        sp_translation_step_vk_and_incoming_message_payload_digests[i].allocate(bp, digest_size);
                    }

                    /* allocate blocks */
                    sp_translation_step_vk_bits.allocate(bp, sp_translation_step_vk_size_in_bits);

                    block_for_outgoing_message.reset(
                        new block_variable<FieldType>(bp, {sp_translation_step_vk_bits, outgoing_message_bits}));

                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        blocks_for_incoming_messages.emplace_back(
                            block_variable<FieldType>(bp, {sp_translation_step_vk_bits, incoming_messages_bits[i]}));
                    }

                    /* allocate hash checkers */
                    hash_outgoing_message.reset(new crh_with_field_out_component<FieldType>(
                        bp, block_size, *block_for_outgoing_message, sp_compliance_step_pcd_circuit_input));

                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        hash_incoming_messages.emplace_back(crh_with_field_out_component<FieldType>(
                            bp, block_size, blocks_for_incoming_messages[i],
                            sp_translation_step_vk_and_incoming_message_payload_digests[i]));
                    }

                    /* allocate useful zero variable */
                    zero.allocate(bp);

                    /* prepare arguments for the verifier */
                    sp_translation_step_vk.reset(new r1cs_ppzksnark_verification_key_variable<CurveType>(
                        bp, sp_translation_step_vk_bits,
                        sp_translation_step_pcd_circuit_maker<other_curve<CurveType>>::input_size_in_elts()));

                    verification_result.allocate(bp);
                    sp_translation_step_vk_and_incoming_message_payload_digest_bits.resize(compliance_predicate_arity);

                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        sp_translation_step_vk_and_incoming_message_payload_digest_bits[i].allocate(
                            bp, digest_size * field_logsize());
                        unpack_sp_translation_step_vk_and_incoming_message_payload_digests.emplace_back(
                            multipacking_component<FieldType>(
                                bp,
                                sp_translation_step_vk_and_incoming_message_payload_digest_bits[i],
                                sp_translation_step_vk_and_incoming_message_payload_digests[i],
                                field_logsize()));

                        verifier_input.emplace_back(sp_translation_step_vk_and_incoming_message_payload_digest_bits[i]);
                        while (verifier_input[i].size() < padded_verifier_input_size) {
                            verifier_input[i].emplace_back(zero);
                        }

                        proof.emplace_back(r1cs_ppzksnark_proof_variable<CurveType>(bp));
                        verifiers.emplace_back(r1cs_ppzksnark_verifier_component<CurveType>(
                            bp,
                            *sp_translation_step_vk,
                            verifier_input[i],
                            sp_translation_step_pcd_circuit_maker<other_curve<CurveType>>::field_capacity(),
                            proof[i],
                            verification_result));
                    }

                    bp.set_input_sizes(input_size_in_elts());
                }

                template<typename CurveType>
                void sp_compliance_step_pcd_circuit_maker<CurveType>::generate_r1cs_constraints() {
                    const std::size_t digest_size = crh_with_bit_out_component<FieldType>::get_digest_len();
                    const std::size_t dimension = knapsack_dimension<FieldType>::dimension;
                    const std::size_t compliance_predicate_arity = compliance_predicate.max_arity;
                    unpack_outgoing_message->generate_r1cs_constraints(true);

                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        unpack_incoming_messages[i].generate_r1cs_constraints(true);
                    }

                    sp_translation_step_vk->generate_r1cs_constraints(true);

                    hash_outgoing_message->generate_r1cs_constraints();

                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        hash_incoming_messages[i].generate_r1cs_constraints();
                    }

                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        unpack_sp_translation_step_vk_and_incoming_message_payload_digests[i].generate_r1cs_constraints(
                            true);
                    }

                    compliance_predicate_as_component->generate_r1cs_constraints();

                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        proof[i].generate_r1cs_constraints();
                    }

                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        verifiers[i].generate_r1cs_constraints();
                    }

                    generate_r1cs_equals_const_constraint<FieldType>(bp, zero, FieldType::value_type::zero());
                    generate_boolean_r1cs_constraint<FieldType>(bp, verification_result);

                    /* type * (1-verification_result) = 0 */
                    bp.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(incoming_message_types[0], 1 - verification_result, 0));

                    /* all types equal */
                    for (std::size_t i = 1; i < compliance_predicate.max_arity; ++i) {
                        bp.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(1, incoming_message_types[0], incoming_message_types[i]));
                    }

                    bp.add_r1cs_constraint(r1cs_constraint<FieldType>(1, arity, compliance_predicate_arity));
                    bp.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        1, outgoing_message_type, typename FieldType::value_type(compliance_predicate.type)));
                }

                template<typename CurveType>
                r1cs_constraint_system<typename CurveType::scalar_field_type>
                    sp_compliance_step_pcd_circuit_maker<CurveType>::get_circuit() const {
                    return bp.get_constraint_system();
                }

                template<typename CurveType>
                r1cs_primary_input<typename CurveType::scalar_field_type>
                    sp_compliance_step_pcd_circuit_maker<CurveType>::get_primary_input() const {
                    return bp.primary_input();
                }

                template<typename CurveType>
                r1cs_auxiliary_input<typename CurveType::scalar_field_type>
                    sp_compliance_step_pcd_circuit_maker<CurveType>::get_auxiliary_input() const {
                    return bp.auxiliary_input();
                }

                template<typename CurveType>
                void sp_compliance_step_pcd_circuit_maker<CurveType>::generate_r1cs_witness(
                    const r1cs_ppzksnark_verification_key<other_curve<CurveType>> &sp_translation_step_pcd_circuit_vk,
                    const r1cs_pcd_compliance_predicate_primary_input<FieldType> &compliance_predicate_primary_input,
                    const r1cs_pcd_compliance_predicate_auxiliary_input<FieldType>
                        &compliance_predicate_auxiliary_input,
                    const std::vector<r1cs_ppzksnark_proof<other_curve<CurveType>>> &incoming_proofs) {
                    const std::size_t compliance_predicate_arity = compliance_predicate.max_arity;
                    this->bp.clear_values();
                    this->bp.val(zero) = FieldType::value_type::zero();

                    compliance_predicate_as_component->generate_r1cs_witness(
                        compliance_predicate_primary_input.as_r1cs_primary_input(),
                        compliance_predicate_auxiliary_input.as_r1cs_auxiliary_input(
                            compliance_predicate.incoming_message_payload_lengths));
                    this->bp.val(arity) = typename FieldType::value_type(compliance_predicate_arity);
                    unpack_outgoing_message->generate_r1cs_witness_from_packed();
                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        unpack_incoming_messages[i].generate_r1cs_witness_from_packed();
                    }

                    sp_translation_step_vk->generate_r1cs_witness(sp_translation_step_pcd_circuit_vk);
                    hash_outgoing_message->generate_r1cs_witness();
                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        hash_incoming_messages[i].generate_r1cs_witness();
                        unpack_sp_translation_step_vk_and_incoming_message_payload_digests[i]
                            .generate_r1cs_witness_from_packed();
                    }

                    for (std::size_t i = 0; i < compliance_predicate_arity; ++i) {
                        proof[i].generate_r1cs_witness(incoming_proofs[i]);
                        verifiers[i].generate_r1cs_witness();
                    }

                    if (this->bp.val(incoming_message_types[0]) != FieldType::value_type::zero()) {
                        this->bp.val(verification_result) = FieldType::value_type::zero();
                    }
                }

                template<typename CurveType>
                std::size_t sp_compliance_step_pcd_circuit_maker<CurveType>::field_logsize() {
                    return typename CurveType::scalar_field_type::value_bits;
                }

                template<typename CurveType>
                std::size_t sp_compliance_step_pcd_circuit_maker<CurveType>::field_capacity() {
                    return typename CurveType::scalar_field_type::capacity();
                }

                template<typename CurveType>
                std::size_t sp_compliance_step_pcd_circuit_maker<CurveType>::input_size_in_elts() {
                    const std::size_t digest_size = crh_with_field_out_component<FieldType>::get_digest_len();
                    return digest_size;
                }

                template<typename CurveType>
                std::size_t sp_compliance_step_pcd_circuit_maker<CurveType>::input_capacity_in_bits() {
                    return input_size_in_elts() * field_capacity();
                }

                template<typename CurveType>
                std::size_t sp_compliance_step_pcd_circuit_maker<CurveType>::input_size_in_bits() {
                    return input_size_in_elts() * field_logsize();
                }

                template<typename CurveType>
                sp_translation_step_pcd_circuit_maker<CurveType>::sp_translation_step_pcd_circuit_maker(
                    const r1cs_ppzksnark_verification_key<other_curve<CurveType>> &sp_compliance_step_vk) {
                    /* allocate input of the translation PCD circuit */
                    sp_translation_step_pcd_circuit_input.allocate(bp, input_size_in_elts());

                    /* unpack translation step PCD circuit input */
                    unpacked_sp_translation_step_pcd_circuit_input.allocate(
                        bp, sp_compliance_step_pcd_circuit_maker<other_curve<CurveType>>::input_size_in_bits());
                    unpack_sp_translation_step_pcd_circuit_input.reset(
                        new multipacking_component<FieldType>(bp, unpacked_sp_translation_step_pcd_circuit_input,
                                                              sp_translation_step_pcd_circuit_input, field_capacity()));

                    /* prepare arguments for the verifier */
                    hardcoded_sp_compliance_step_vk.reset(
                        new r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<CurveType>(
                            bp, sp_compliance_step_vk));
                    proof.reset(new r1cs_ppzksnark_proof_variable<CurveType>(bp));

                    /* verify previous proof */
                    online_verifier.reset(new r1cs_ppzksnark_online_verifier_component<CurveType>(
                        bp,
                        *hardcoded_sp_compliance_step_vk,
                        unpacked_sp_translation_step_pcd_circuit_input,
                        sp_compliance_step_pcd_circuit_maker<other_curve<CurveType>>::field_logsize(),
                        *proof,
                        variable<FieldType>(0)));
                    bp.set_input_sizes(input_size_in_elts());
                }

                template<typename CurveType>
                void sp_translation_step_pcd_circuit_maker<CurveType>::generate_r1cs_constraints() {
                    unpack_sp_translation_step_pcd_circuit_input->generate_r1cs_constraints(true);

                    proof->generate_r1cs_constraints();

                    online_verifier->generate_r1cs_constraints();
                }

                template<typename CurveType>
                r1cs_constraint_system<typename CurveType::scalar_field_type>
                    sp_translation_step_pcd_circuit_maker<CurveType>::get_circuit() const {
                    return bp.get_constraint_system();
                }

                template<typename CurveType>
                void sp_translation_step_pcd_circuit_maker<CurveType>::generate_r1cs_witness(
                    const r1cs_primary_input<typename CurveType::scalar_field_type>
                        sp_translation_step_input,
                    const r1cs_ppzksnark_proof<other_curve<CurveType>> &compliance_step_proof) {
                    this->bp.clear_values();
                    sp_translation_step_pcd_circuit_input.fill_with_field_elements(bp, sp_translation_step_input);
                    unpack_sp_translation_step_pcd_circuit_input->generate_r1cs_witness_from_packed();

                    proof->generate_r1cs_witness(compliance_step_proof);
                    online_verifier->generate_r1cs_witness();
                }

                template<typename CurveType>
                r1cs_primary_input<typename CurveType::scalar_field_type>
                    sp_translation_step_pcd_circuit_maker<CurveType>::get_primary_input() const {
                    return bp.primary_input();
                }

                template<typename CurveType>
                r1cs_auxiliary_input<typename CurveType::scalar_field_type>
                    sp_translation_step_pcd_circuit_maker<CurveType>::get_auxiliary_input() const {
                    return bp.auxiliary_input();
                }

                template<typename CurveType>
                std::size_t sp_translation_step_pcd_circuit_maker<CurveType>::field_logsize() {
                    return typename CurveType::scalar_field_type::value_bits;
                }

                template<typename CurveType>
                std::size_t sp_translation_step_pcd_circuit_maker<CurveType>::field_capacity() {
                    return typename CurveType::scalar_field_type::capacity();
                }

                template<typename CurveType>
                std::size_t sp_translation_step_pcd_circuit_maker<CurveType>::input_size_in_elts() {
                    return algebra::div_ceil(
                        sp_compliance_step_pcd_circuit_maker<other_curve<CurveType>>::input_size_in_bits(),
                        sp_translation_step_pcd_circuit_maker<CurveType>::field_capacity());
                }

                template<typename CurveType>
                std::size_t sp_translation_step_pcd_circuit_maker<CurveType>::input_capacity_in_bits() {
                    return input_size_in_elts() * field_capacity();
                }

                template<typename CurveType>
                std::size_t sp_translation_step_pcd_circuit_maker<CurveType>::input_size_in_bits() {
                    return input_size_in_elts() * field_logsize();
                }

                template<typename CurveType>
                r1cs_primary_input<typename CurveType::scalar_field_type> get_sp_compliance_step_pcd_circuit_input(
                    const std::vector<bool> &sp_translation_step_vk_bits,
                    const r1cs_pcd_compliance_predicate_primary_input<typename CurveType::scalar_field_type>
                        &primary_input) {
                    typedef typename CurveType::scalar_field_type FieldType;

                    const r1cs_variable_assignment<FieldType> outgoing_message_as_va =
                        primary_input.outgoing_message->as_r1cs_variable_assignment();
                    std::vector<bool> msg_bits;
                    for (const typename FieldType::value_type &elt : outgoing_message_as_va) {
                        const std::vector<bool> elt_bits = algebra::convert_field_element_to_bit_vector(elt);
                        msg_bits.insert(msg_bits.end(), elt_bits.begin(), elt_bits.end());
                    }

                    std::vector<bool> block;
                    block.insert(block.end(), sp_translation_step_vk_bits.begin(), sp_translation_step_vk_bits.end());
                    block.insert(block.end(), msg_bits.begin(), msg_bits.end());

                    crh_with_field_out_component<FieldType>::sample_randomness(block.size());

                    const std::vector<typename FieldType::value_type> digest =
                        crh_with_field_out_component<FieldType>::get_hash(block);

                    return digest;
                }

                template<typename CurveType>
                r1cs_primary_input<typename CurveType::scalar_field_type> get_sp_translation_step_pcd_circuit_input(
                    const std::vector<bool> &sp_translation_step_vk_bits,
                    const r1cs_pcd_compliance_predicate_primary_input<
                        other_curve<CurveType>::scalar_field_type::value_type> &primary_input) {
                    typedef typename CurveType::scalar_field_type FieldType;

                    const std::vector<other_curve<CurveType>::scalar_field_type::value_type>
                        sp_compliance_step_pcd_circuit_input =
                            get_sp_compliance_step_pcd_circuit_input<other_curve<CurveType>>(
                                sp_translation_step_vk_bits, primary_input);
                    std::vector<bool> sp_compliance_step_pcd_circuit_input_bits;
                    for (const other_curve<CurveType>::scalar_field_type::value_type &elt :
                         sp_compliance_step_pcd_circuit_input) {
                        const std::vector<bool> elt_bits = algebra::convert_field_element_to_bit_vector<
                            other_curve<CurveType>::scalar_field_type::value_type>(elt);
                        sp_compliance_step_pcd_circuit_input_bits.insert(
                            sp_compliance_step_pcd_circuit_input_bits.end(), elt_bits.begin(), elt_bits.end());
                    }

                    sp_compliance_step_pcd_circuit_input_bits.resize(
                        sp_translation_step_pcd_circuit_maker<CurveType>::input_capacity_in_bits(), false);

                    const r1cs_primary_input<FieldType> result =
                        algebra::pack_bit_vector_into_field_element_vector<FieldType>(
                            sp_compliance_step_pcd_circuit_input_bits,
                            sp_translation_step_pcd_circuit_maker<CurveType>::field_capacity());

                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SP_PCD_CIRCUITS_HPP
