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

#ifndef CRYPTO3_ZK_R1CS_PCD_PARAMS_HPP
#define CRYPTO3_ZK_R1CS_PCD_PARAMS_HPP

#include <memory>
#include <vector>

#include <nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class r1cs_pcd_compliance_predicate_primary_input {
                public:
                    std::shared_ptr<r1cs_pcd_message<FieldType>> outgoing_message;

                    r1cs_pcd_compliance_predicate_primary_input(
                        const std::shared_ptr<r1cs_pcd_message<FieldType>> &outgoing_message) :
                        outgoing_message(outgoing_message) {
                    }
                    r1cs_primary_input<FieldType> as_r1cs_primary_input() const {
                        return outgoing_message->as_r1cs_variable_assignment();
                    }
                };

                template<typename FieldType>
                class r1cs_pcd_compliance_predicate_auxiliary_input {
                public:
                    std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> incoming_messages;
                    std::shared_ptr<r1cs_pcd_local_data<FieldType>> local_data;
                    r1cs_pcd_witness<FieldType> witness;

                    r1cs_pcd_compliance_predicate_auxiliary_input(
                        const std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> &incoming_messages,
                        const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data,
                        const r1cs_pcd_witness<FieldType> &witness) :
                        incoming_messages(incoming_messages),
                        local_data(local_data), witness(witness) {
                    }

                    r1cs_auxiliary_input<FieldType> as_r1cs_auxiliary_input(
                        const std::vector<std::size_t> &incoming_message_payload_lengths) const {

                        const std::size_t arity = incoming_messages.size();

                        r1cs_auxiliary_input<FieldType> result;
                        result.emplace_back(typename FieldType::value_type(arity));

                        const std::size_t max_arity = incoming_message_payload_lengths.size();
                        assert(arity <= max_arity);

                        for (std::size_t i = 0; i < arity; ++i) {
                            const r1cs_variable_assignment<FieldType> msg_as_r1cs_va =
                                incoming_messages[i]->as_r1cs_variable_assignment();
                            assert(msg_as_r1cs_va.size() == (1 + incoming_message_payload_lengths[i]));
                            result.insert(result.end(), msg_as_r1cs_va.begin(), msg_as_r1cs_va.end());
                        }

                        /* pad with dummy messages of appropriate size */
                        for (std::size_t i = arity; i < max_arity; ++i) {
                            result.resize(result.size() + (1 + incoming_message_payload_lengths[i]),
                                          FieldType::value_type::zero());
                        }

                        const r1cs_variable_assignment<FieldType> local_data_as_r1cs_va =
                            local_data->as_r1cs_variable_assignment();
                        result.insert(result.end(), local_data_as_r1cs_va.begin(), local_data_as_r1cs_va.end());
                        result.insert(result.end(), witness.begin(), witness.end());

                        return result;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // R1CS_PCD_PARAMS_HPP
