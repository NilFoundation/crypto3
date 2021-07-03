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
// @file Declaration of interfaces for a compliance predicate for R1CS PCD.
//
// A compliance predicate specifies a local invariant to be enforced, by PCD,
// throughout a dynamic distributed computation. A compliance predicate
// receives input messages, local data, and an output message (and perhaps some
// other auxiliary information), and then either accepts or rejects.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_COMPLIANCE_PREDICATE_HPP
#define CRYPTO3_ZK_COMPLIANCE_PREDICATE_HPP

#include <memory>
#include <set>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /********************************* Message ***********************************/

                /**
                 * A message for R1CS PCD.
                 *
                 * It is a pair, consisting of
                 * - a type (a positive integer), and
                 * - a payload (a vector of field elements).
                 */
                template<typename FieldType>
                struct r1cs_pcd_message {
                    std::size_t type;

                    r1cs_pcd_message(std::size_t type) : type(type) {
                    }
                    virtual r1cs_variable_assignment<FieldType> payload_as_r1cs_variable_assignment() const = 0;
                    r1cs_variable_assignment<FieldType> as_r1cs_variable_assignment() const {
                        r1cs_variable_assignment<FieldType> result = this->payload_as_r1cs_variable_assignment();
                        result.insert(result.begin(), typename FieldType::value_type(this->type));
                        return result;
                    }

                    virtual ~r1cs_pcd_message() = default;
                };

                /******************************* Local data **********************************/

                /**
                 * A local data for R1CS PCD.
                 */
                template<typename FieldType>
                struct r1cs_pcd_local_data {
                    r1cs_pcd_local_data() = default;
                    virtual r1cs_variable_assignment<FieldType> as_r1cs_variable_assignment() const = 0;
                    virtual ~r1cs_pcd_local_data() = default;
                };

                /******************************** Witness ************************************/

                template<typename FieldType>
                using r1cs_pcd_witness = std::vector<typename FieldType::value_type>;

                /*************************** Compliance predicate ****************************/

                /**
                 * A compliance predicate for R1CS PCD.
                 *
                 * It is a wrapper around R1CS that also specifies how to parse a
                 * variable assignment as:
                 * - output message (the input)
                 * - some number of input messages (part of the witness)
                 * - local data (also part of the witness)
                 * - auxiliary information (the remaining variables of the witness)
                 *
                 * A compliance predicate also has a type, allegedly the same
                 * as the type of the output message.
                 *
                 * The input wires of R1CS appear in the following order:
                 * - (1 + outgoing_message_payload_length) wires for outgoing message
                 * - 1 wire for arity (allegedly, 0 <= arity <= max_arity)
                 * - for i = 0, ..., max_arity-1:
                 * - (1 + incoming_message_payload_lengths[i]) wires for i-th message of
                 *   the input (in the array that's padded to max_arity messages)
                 * - local_data_length wires for local data
                 *
                 * The rest witness_length wires of the R1CS constitute the witness.
                 *
                 * To allow for optimizations, the compliance predicate also
                 * specififies a flag, called relies_on_same_type_inputs, denoting
                 * whether the predicate works under the assumption that all input
                 * messages have the same type. In such case a member
                 * accepted_input_types lists all types accepted by the predicate
                 * (accepted_input_types has no meaning if
                 * relies_on_same_type_inputs=false).
                 */

                template<typename FieldType>
                class r1cs_pcd_compliance_predicate {
                public:
                    std::size_t name;
                    std::size_t type;

                    r1cs_constraint_system<FieldType> constraint_system;

                    std::size_t outgoing_message_payload_length;
                    std::size_t max_arity;
                    std::vector<std::size_t> incoming_message_payload_lengths;
                    std::size_t local_data_length;
                    std::size_t witness_length;

                    bool relies_on_same_type_inputs;
                    std::set<std::size_t> accepted_input_types;

                    r1cs_pcd_compliance_predicate() = default;
                    r1cs_pcd_compliance_predicate(r1cs_pcd_compliance_predicate<FieldType> &&other) = default;
                    r1cs_pcd_compliance_predicate(const r1cs_pcd_compliance_predicate<FieldType> &other) = default;
                    r1cs_pcd_compliance_predicate(
                        std::size_t name,
                        std::size_t type,
                        const r1cs_constraint_system<FieldType> &constraint_system,
                        std::size_t outgoing_message_payload_length,
                        std::size_t max_arity,
                        const std::vector<std::size_t> &incoming_message_payload_lengths,
                        std::size_t local_data_length,
                        std::size_t witness_length,
                        bool relies_on_same_type_inputs,
                        const std::set<std::size_t> &accepted_input_types = std::set<std::size_t>());

                    r1cs_pcd_compliance_predicate<FieldType> &
                        operator=(const r1cs_pcd_compliance_predicate<FieldType> &other) = default;

                    bool is_well_formed() const;
                    bool has_equal_input_and_output_lengths() const;
                    bool has_equal_input_lengths() const;

                    bool
                        is_satisfied(const std::shared_ptr<r1cs_pcd_message<FieldType>> &outgoing_message,
                                     const std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> &incoming_messages,
                                     const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data,
                                     const r1cs_pcd_witness<FieldType> &witness) const;

                    bool operator==(const r1cs_pcd_compliance_predicate<FieldType> &other) const;
                };

                template<typename FieldType>
                class r1cs_pcd_compliance_predicate_primary_input;

                template<typename FieldType>
                class r1cs_pcd_compliance_predicate_auxiliary_input;

                template<typename FieldType>
                r1cs_pcd_compliance_predicate<FieldType>::r1cs_pcd_compliance_predicate(
                    std::size_t name,
                    std::size_t type,
                    const r1cs_constraint_system<FieldType> &constraint_system,
                    std::size_t outgoing_message_payload_length,
                    std::size_t max_arity,
                    const std::vector<std::size_t> &incoming_message_payload_lengths,
                    std::size_t local_data_length,
                    std::size_t witness_length,
                    bool relies_on_same_type_inputs,
                    const std::set<std::size_t> &accepted_input_types) :
                    name(name),
                    type(type), constraint_system(constraint_system),
                    outgoing_message_payload_length(outgoing_message_payload_length), max_arity(max_arity),
                    incoming_message_payload_lengths(incoming_message_payload_lengths),
                    local_data_length(local_data_length), witness_length(witness_length),
                    relies_on_same_type_inputs(relies_on_same_type_inputs), accepted_input_types(accepted_input_types) {
                    assert(max_arity == incoming_message_payload_lengths.size());
                }

                template<typename FieldType>
                bool r1cs_pcd_compliance_predicate<FieldType>::is_well_formed() const {
                    const bool type_not_zero = (type != 0);
                    const bool incoming_message_payload_lengths_well_specified =
                        (incoming_message_payload_lengths.size() == max_arity);

                    std::size_t all_message_payload_lengths = outgoing_message_payload_length;
                    for (std::size_t i = 0; i < incoming_message_payload_lengths.size(); ++i) {
                        all_message_payload_lengths += incoming_message_payload_lengths[i];
                    }
                    const std::size_t type_vec_length = max_arity + 1;
                    const std::size_t arity_length = 1;

                    const bool correct_num_inputs =
                        ((outgoing_message_payload_length + 1) == constraint_system.num_inputs());
                    const bool correct_num_variables =
                        ((all_message_payload_lengths + local_data_length + type_vec_length + arity_length +
                          witness_length) == constraint_system.num_variables());

                    return (type_not_zero && incoming_message_payload_lengths_well_specified && correct_num_inputs &&
                            correct_num_variables);
                }

                template<typename FieldType>
                bool r1cs_pcd_compliance_predicate<FieldType>::has_equal_input_and_output_lengths() const {
                    for (std::size_t i = 0; i < incoming_message_payload_lengths.size(); ++i) {
                        if (incoming_message_payload_lengths[i] != outgoing_message_payload_length) {
                            return false;
                        }
                    }

                    return true;
                }

                template<typename FieldType>
                bool r1cs_pcd_compliance_predicate<FieldType>::has_equal_input_lengths() const {
                    for (std::size_t i = 1; i < incoming_message_payload_lengths.size(); ++i) {
                        if (incoming_message_payload_lengths[i] != incoming_message_payload_lengths[0]) {
                            return false;
                        }
                    }

                    return true;
                }

                template<typename FieldType>
                bool r1cs_pcd_compliance_predicate<FieldType>::operator==(
                    const r1cs_pcd_compliance_predicate<FieldType> &other) const {
                    return (this->name == other.name && this->type == other.type &&
                            this->constraint_system == other.constraint_system &&
                            this->outgoing_message_payload_length == other.outgoing_message_payload_length &&
                            this->max_arity == other.max_arity &&
                            this->incoming_message_payload_lengths == other.incoming_message_payload_lengths &&
                            this->local_data_length == other.local_data_length &&
                            this->witness_length == other.witness_length &&
                            this->relies_on_same_type_inputs == other.relies_on_same_type_inputs &&
                            this->accepted_input_types == other.accepted_input_types);
                }

                template<typename FieldType>
                bool r1cs_pcd_compliance_predicate<FieldType>::is_satisfied(
                    const std::shared_ptr<r1cs_pcd_message<FieldType>> &outgoing_message,
                    const std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> &incoming_messages,
                    const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data,
                    const r1cs_pcd_witness<FieldType> &witness) const {
                    assert(outgoing_message.payload_as_r1cs_variable_assignment().size() ==
                           outgoing_message_payload_length);
                    assert(incoming_messages.size() <= max_arity);
                    for (std::size_t i = 0; i < incoming_messages.size(); ++i) {
                        assert(incoming_messages[i].payload_as_r1cs_variable_assignment().size() ==
                               incoming_message_payload_lengths[i]);
                    }
                    assert(local_data.as_r1cs_variable_assignment().size() == local_data_length);

                    r1cs_pcd_compliance_predicate_primary_input<FieldType> cp_primary_input(outgoing_message);
                    r1cs_pcd_compliance_predicate_auxiliary_input<FieldType> cp_auxiliary_input(incoming_messages,
                                                                                                local_data, witness);

                    return constraint_system.is_satisfied(
                        cp_primary_input.as_r1cs_primary_input(),
                        cp_auxiliary_input.as_r1cs_auxiliary_input(incoming_message_payload_lengths));
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // COMPLIANCE_PREDICATE_HPP
