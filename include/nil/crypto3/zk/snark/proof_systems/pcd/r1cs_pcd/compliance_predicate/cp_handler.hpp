//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a compliance predicate handler.
//
// A compliance predicate handler is a base class for creating compliance predicates.
// It relies on classes declared in gadgets.
//---------------------------------------------------------------------------//

#ifndef CP_HANDLER_HPP_
#define CP_HANDLER_HPP_

#include <numeric>

#include <nil/crypto3/zk/snark/gadget.hpp>
#include <nil/crypto3/zk/snark/protoboard.hpp>
#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /***************************** Message variable ******************************/

                /**
                 * A variable to represent an r1cs_pcd_message.
                 */
                template<typename FieldType>
                class r1cs_pcd_message_variable : public gadget<FieldType> {
                protected:
                    std::size_t num_vars_at_construction;

                public:
                    pb_variable<FieldType> type;

                    pb_variable_array<FieldType> all_vars;

                    r1cs_pcd_message_variable(protoboard<FieldType> &pb);
                    void update_all_vars();

                    void generate_r1cs_witness(const std::shared_ptr<r1cs_pcd_message<FieldType>> &message);
                    virtual std::shared_ptr<r1cs_pcd_message<FieldType>> get_message() const = 0;

                    virtual ~r1cs_pcd_message_variable() = default;
                };
                /*************************** Local data variable *****************************/

                /**
                 * A variable to represent an r1cs_pcd_local_data.
                 */
                template<typename FieldType>
                class r1cs_pcd_local_data_variable : public gadget<FieldType> {
                protected:
                    std::size_t num_vars_at_construction;

                public:
                    pb_variable_array<FieldType> all_vars;

                    r1cs_pcd_local_data_variable(protoboard<FieldType> &pb);
                    void update_all_vars();

                    void generate_r1cs_witness(const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data);

                    virtual ~r1cs_pcd_local_data_variable() = default;
                };

                /*********************** Compliance predicate handler ************************/

                /**
                 * A base class for creating compliance predicates.
                 */
                template<typename FieldType, typename protoboardT>
                class compliance_predicate_handler {
                protected:
                    protoboardT pb;

                    std::shared_ptr<r1cs_pcd_message_variable<FieldType>> outgoing_message;
                    pb_variable<FieldType> arity;
                    std::vector<std::shared_ptr<r1cs_pcd_message_variable<FieldType>>> incoming_messages;
                    std::shared_ptr<r1cs_pcd_local_data_variable<FieldType>> local_data;

                public:
                    const std::size_t name;
                    const std::size_t type;
                    const std::size_t max_arity;
                    const bool relies_on_same_type_inputs;
                    const std::set<std::size_t> accepted_input_types;

                    compliance_predicate_handler(const protoboardT &pb,
                                                 const std::size_t name,
                                                 const std::size_t type,
                                                 const std::size_t max_arity,
                                                 const bool relies_on_same_type_inputs,
                                                 const std::set<std::size_t> accepted_input_types = std::set<std::size_t>());
                    virtual void generate_r1cs_constraints() = 0;
                    virtual void generate_r1cs_witness(
                        const std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> &incoming_message_values,
                        const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data_value);

                    r1cs_pcd_compliance_predicate<FieldType> get_compliance_predicate() const;
                    r1cs_variable_assignment<FieldType> get_full_variable_assignment() const;

                    std::shared_ptr<r1cs_pcd_message<FieldType>> get_outgoing_message() const;
                    std::size_t get_arity() const;
                    std::shared_ptr<r1cs_pcd_message<FieldType>> get_incoming_message(const std::size_t message_idx) const;
                    std::shared_ptr<r1cs_pcd_local_data<FieldType>> get_local_data() const;
                    r1cs_variable_assignment<FieldType> get_witness() const;
                };

                template<typename FieldType>
                r1cs_pcd_message_variable<FieldType>::r1cs_pcd_message_variable(protoboard<FieldType> &pb) :
                    gadget<FieldType>(pb) {
                    type.allocate(pb);
                    all_vars.emplace_back(type);

                    num_vars_at_construction = pb.num_variables();
                }

                template<typename FieldType>
                void r1cs_pcd_message_variable<FieldType>::update_all_vars() {
                    /* NOTE: this assumes that r1cs_pcd_message_variable has been the
                     * only gadget allocating variables on the protoboard and needs to
                     * be updated, e.g., in multicore variable allocation scenario. */

                    for (std::size_t var_idx = num_vars_at_construction + 1; var_idx <= this->pb.num_variables();
                         ++var_idx) {
                        all_vars.emplace_back(pb_variable<FieldType>(var_idx));
                    }
                }

                template<typename FieldType>
                void r1cs_pcd_message_variable<FieldType>::generate_r1cs_witness(
                    const std::shared_ptr<r1cs_pcd_message<FieldType>> &message) {
                    all_vars.fill_with_field_elements(this->pb, message->as_r1cs_variable_assignment());
                }

                template<typename FieldType>
                r1cs_pcd_local_data_variable<FieldType>::r1cs_pcd_local_data_variable(protoboard<FieldType> &pb) :
                    gadget<FieldType>(pb) {
                    num_vars_at_construction = pb.num_variables();
                }

                template<typename FieldType>
                void r1cs_pcd_local_data_variable<FieldType>::update_all_vars() {
                    /* (the same NOTE as for r1cs_message_variable applies) */

                    for (std::size_t var_idx = num_vars_at_construction + 1; var_idx <= this->pb.num_variables();
                         ++var_idx) {
                        all_vars.emplace_back(pb_variable<FieldType>(var_idx));
                    }
                }

                template<typename FieldType>
                void r1cs_pcd_local_data_variable<FieldType>::generate_r1cs_witness(
                    const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data) {
                    all_vars.fill_with_field_elements(this->pb, local_data->as_r1cs_variable_assignment());
                }

                template<typename FieldType, typename protoboardT>
                compliance_predicate_handler<FieldType, protoboardT>::compliance_predicate_handler(
                    const protoboardT &pb,
                    const std::size_t name,
                    const std::size_t type,
                    const std::size_t max_arity,
                    const bool relies_on_same_type_inputs,
                    const std::set<std::size_t> &accepted_input_types) :
                    pb(pb),
                    name(name), type(type), max_arity(max_arity),
                    relies_on_same_type_inputs(relies_on_same_type_inputs), accepted_input_types(accepted_input_types) {
                    incoming_messages.resize(max_arity);
                }

                template<typename FieldType, typename protoboardT>
                void compliance_predicate_handler<FieldType, protoboardT>::generate_r1cs_witness(
                    const std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> &incoming_message_values,
                    const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data_value) {
                    pb.clear_values();
                    pb.val(outgoing_message->type) = FieldType(type);
                    pb.val(arity) = FieldType(incoming_message_values.size());

                    for (std::size_t i = 0; i < incoming_message_values.size(); ++i) {
                        incoming_messages[i]->generate_r1cs_witness(incoming_message_values[i]);
                    }

                    local_data->generate_r1cs_witness(local_data_value);
                }

                template<typename FieldType, typename protoboardT>
                r1cs_pcd_compliance_predicate<FieldType>
                    compliance_predicate_handler<FieldType, protoboardT>::get_compliance_predicate() const {
                    assert(incoming_messages.size() == max_arity);

                    const std::size_t outgoing_message_payload_length = outgoing_message->all_vars.size() - 1;

                    std::vector<std::size_t> incoming_message_payload_lengths(max_arity);
                    std::transform(incoming_messages.begin(), incoming_messages.end(),
                                   incoming_message_payload_lengths.begin(),
                                   [](const std::shared_ptr<r1cs_pcd_message_variable<FieldType>> &msg) {
                                       return msg->all_vars.size() - 1;
                                   });

                    const std::size_t local_data_length = local_data->all_vars.size();

                    const std::size_t all_but_witness_length =
                        ((1 + outgoing_message_payload_length) + 1 +
                         (max_arity + std::accumulate(incoming_message_payload_lengths.begin(),
                                                      incoming_message_payload_lengths.end(), 0)) +
                         local_data_length);
                    const std::size_t witness_length = pb.num_variables() - all_but_witness_length;

                    r1cs_constraint_system<FieldType> constraint_system = pb.get_constraint_system();
                    constraint_system.primary_input_size = 1 + outgoing_message_payload_length;
                    constraint_system.auxiliary_input_size = pb.num_variables() - constraint_system.primary_input_size;

                    return r1cs_pcd_compliance_predicate<FieldType>(name,
                                                                    type,
                                                                    constraint_system,
                                                                    outgoing_message_payload_length,
                                                                    max_arity,
                                                                    incoming_message_payload_lengths,
                                                                    local_data_length,
                                                                    witness_length,
                                                                    relies_on_same_type_inputs,
                                                                    accepted_input_types);
                }

                template<typename FieldType, typename protoboardT>
                r1cs_variable_assignment<FieldType>
                    compliance_predicate_handler<FieldType, protoboardT>::get_full_variable_assignment() const {
                    return pb.full_variable_assignment();
                }

                template<typename FieldType, typename protoboardT>
                std::shared_ptr<r1cs_pcd_message<FieldType>>
                    compliance_predicate_handler<FieldType, protoboardT>::get_outgoing_message() const {
                    return outgoing_message->get_message();
                }

                template<typename FieldType, typename protoboardT>
                std::size_t compliance_predicate_handler<FieldType, protoboardT>::get_arity() const {
                    return pb.val(arity).as_ulong();
                }

                template<typename FieldType, typename protoboardT>
                std::shared_ptr<r1cs_pcd_message<FieldType>>
                    compliance_predicate_handler<FieldType, protoboardT>::get_incoming_message(
                        const std::size_t message_idx) const {
                    assert(message_idx < max_arity);
                    return incoming_messages[message_idx]->get_message();
                }

                template<typename FieldType, typename protoboardT>
                std::shared_ptr<r1cs_pcd_local_data<FieldType>>
                    compliance_predicate_handler<FieldType, protoboardT>::get_local_data() const {
                    return local_data->get_local_data();
                }

                template<typename FieldType, typename protoboardT>
                r1cs_pcd_witness<FieldType> compliance_predicate_handler<FieldType, protoboardT>::get_witness() const {
                    const r1cs_variable_assignment<FieldType> va = pb.full_variable_assignment();
                    // outgoing_message + arity + incoming_messages + local_data
                    const std::size_t witness_pos =
                        (outgoing_message->all_vars.size() + 1 +
                         std::accumulate(
                             incoming_messages.begin(), incoming_messages.end(), 0,
                             [](std::size_t acc, const std::shared_ptr<r1cs_pcd_message_variable<FieldType>> &msg) {
                                 return acc + msg->all_vars.size();
                             }) +
                         local_data->all_vars.size());

                    return r1cs_variable_assignment<FieldType>(va.begin() + witness_pos, va.end());
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CP_HANDLER_HPP_
