//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the tally compliance predicate.
//
// The tally compliance predicate has two purposes:
// (1) it exemplifies the use of interfaces declared in cp_handler.hpp, and
// (2) it enables us to test r1cs_pcd functionalities.
//
// See
// - snark/proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/examples/run_r1cs_sp_ppzkpcd.hpp
// - snark/proof_systems/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/examples/run_r1cs_mp_ppzkpcd.hpp
// for code that uses the tally compliance predicate.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TALLY_CP_HPP
#define CRYPTO3_ZK_TALLY_CP_HPP

#include <nil/crypto3/zk/snark/components/basic_components.hpp>

#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp>
#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Subclasses a R1CS PCD message to the tally compliance predicate.
                 */
                template<typename FieldType>
                class tally_pcd_message : public r1cs_pcd_message<FieldType> {
                public:
                    std::size_t wordsize;

                    std::size_t sum;
                    std::size_t count;

                    tally_pcd_message(const std::size_t type, const std::size_t wordsize, const std::size_t sum, const std::size_t count);
                    r1cs_variable_assignment<FieldType> payload_as_r1cs_variable_assignment() const;

                    ~tally_pcd_message() = default;
                };

                template<typename FieldType>
                class tally_pcd_local_data : public r1cs_pcd_local_data<FieldType> {
                public:
                    std::size_t summand;

                    tally_pcd_local_data(const std::size_t summand);
                    r1cs_variable_assignment<FieldType> as_r1cs_variable_assignment() const;

                    ~tally_pcd_local_data() = default;
                };

                /**
                 * Subclass a R1CS compliance predicate handler to the tally compliance predicate handler.
                 */
                template<typename FieldType>
                class tally_cp_handler : public compliance_predicate_handler<FieldType, blueprint<FieldType>> {
                public:
                    typedef compliance_predicate_handler<FieldType, blueprint<FieldType>> base_handler;
                    blueprint_variable_vector<FieldType> incoming_types;

                    blueprint_variable<FieldType> sum_out_packed;
                    blueprint_variable<FieldType> count_out_packed;
                    blueprint_variable_vector<FieldType> sum_in_packed;
                    blueprint_variable_vector<FieldType> count_in_packed;

                    blueprint_variable_vector<FieldType> sum_in_packed_aux;
                    blueprint_variable_vector<FieldType> count_in_packed_aux;

                    std::shared_ptr<packing_component<FieldType>> unpack_sum_out;
                    std::shared_ptr<packing_component<FieldType>> unpack_count_out;
                    std::vector<packing_component<FieldType>> pack_sum_in;
                    std::vector<packing_component<FieldType>> pack_count_in;

                    blueprint_variable<FieldType> type_val_inner_product;
                    std::shared_ptr<inner_product_component<FieldType>> compute_type_val_inner_product;

                    blueprint_variable_vector<FieldType> arity_indicators;

                    std::size_t wordsize;
                    std::size_t message_length;

                    tally_cp_handler(std::size_t type,
                                     std::size_t max_arity,
                                     std::size_t wordsize,
                                     bool relies_on_same_type_inputs = false,
                                     const std::set<std::size_t> &accepted_input_types = std::set<std::size_t>());

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(
                        const std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> &incoming_messages,
                        const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data);

                    std::shared_ptr<r1cs_pcd_message<FieldType>> get_base_case_message() const;
                };

                template<typename FieldType>
                tally_pcd_message<FieldType>::tally_pcd_message(const std::size_t type,
                                                             const std::size_t wordsize,
                                                             const std::size_t sum,
                                                             const std::size_t count) :
                    r1cs_pcd_message<FieldType>(type),
                    wordsize(wordsize), sum(sum), count(count) {
                }

                template<typename FieldType>
                r1cs_variable_assignment<FieldType>
                tally_pcd_message<FieldType>::payload_as_r1cs_variable_assignment() const {
                    std::function<FieldType(bool)> bit_to_FieldT = [](const bool bit) {
                        return bit ? FieldType::value_type::zero() : FieldType::value_type::zero();
                    };

                    const std::vector<bool> sum_bits =
                        algebra::convert_field_element_to_bit_vector<FieldType>(sum, wordsize);
                    const std::vector<bool> count_bits =
                        algebra::convert_field_element_to_bit_vector<FieldType>(count, wordsize);

                    r1cs_variable_assignment<FieldType> result(2 * wordsize);
                    std::transform(sum_bits.begin(), sum_bits.end(), result.begin(), bit_to_FieldT);
                    std::transform(count_bits.begin(), count_bits.end(), result.begin() + wordsize, bit_to_FieldT);

                    return result;
                }

                template<typename FieldType>
                tally_pcd_local_data<FieldType>::tally_pcd_local_data(const std::size_t summand) : summand(summand) {
                }

                template<typename FieldType>
                r1cs_variable_assignment<FieldType> tally_pcd_local_data<FieldType>::as_r1cs_variable_assignment() const {
                    return {FieldType(summand)};
                }

                template<typename FieldType>
                class tally_pcd_message_variable : public r1cs_pcd_message_variable<FieldType> {
                public:
                    blueprint_variable_vector<FieldType> sum_bits;
                    blueprint_variable_vector<FieldType> count_bits;
                    std::size_t wordsize;

                    tally_pcd_message_variable(blueprint<FieldType> &pb,
                                               const std::size_t wordsize) :
                        r1cs_pcd_message_variable<FieldType>(pb),
                        wordsize(wordsize) {
                        sum_bits.allocate(pb, wordsize);
                        count_bits.allocate(pb, wordsize);

                        this->update_all_vars();
                    }

                    std::shared_ptr<r1cs_pcd_message<FieldType>> get_message() const {
                        const std::size_t type_val = this->pb.val(this->type).as_ulong();
                        const std::size_t sum_val = sum_bits.get_field_element_from_bits(this->pb).as_ulong();
                        const std::size_t count_val = count_bits.get_field_element_from_bits(this->pb).as_ulong();

                        std::shared_ptr<r1cs_pcd_message<FieldType>> result;
                        result.reset(new tally_pcd_message<FieldType>(type_val, wordsize, sum_val, count_val));
                        return result;
                    }

                    ~tally_pcd_message_variable() = default;
                };

                template<typename FieldType>
                class tally_pcd_local_data_variable : public r1cs_pcd_local_data_variable<FieldType> {
                public:
                    blueprint_variable<FieldType> summand;

                    tally_pcd_local_data_variable(blueprint<FieldType> &pb) :
                        r1cs_pcd_local_data_variable<FieldType>(pb) {
                        summand.allocate(pb);

                        this->update_all_vars();
                    }

                    std::shared_ptr<r1cs_pcd_local_data<FieldType>> get_local_data() const {
                        const std::size_t summand_val = this->pb.val(summand).as_ulong();

                        std::shared_ptr<r1cs_pcd_local_data<FieldType>> result;
                        result.reset(new tally_pcd_local_data<FieldType>(summand_val));
                        return result;
                    }

                    ~tally_pcd_local_data_variable() = default;
                };

                template<typename FieldType>
                tally_cp_handler<FieldType>::tally_cp_handler(std::size_t type, std::size_t max_arity, std::size_t wordsize, bool relies_on_same_type_inputs,
                                                           const std::set<std::size_t> &accepted_input_types) :
                    compliance_predicate_handler<FieldType, blueprint<FieldType>>(blueprint<FieldType>(),
                        type * 100,
                        type,
                        max_arity,
                        relies_on_same_type_inputs,
                        accepted_input_types),
                    wordsize(wordsize) {
                    this->outgoing_message.reset(
                        new tally_pcd_message_variable<FieldType>(this->pb, wordsize));
                    this->arity.allocate(this->pb);

                    for (std::size_t i = 0; i < max_arity; ++i) {
                        this->incoming_messages[i].reset(new tally_pcd_message_variable<FieldType>(this->pb, wordsize));
                    }

                    this->local_data.reset(new tally_pcd_local_data_variable<FieldType>(this->pb));

                    sum_out_packed.allocate(this->pb);
                    count_out_packed.allocate(this->pb);

                    sum_in_packed.allocate(this->pb, max_arity);
                    count_in_packed.allocate(this->pb, max_arity);

                    sum_in_packed_aux.allocate(this->pb, max_arity);
                    count_in_packed_aux.allocate(this->pb, max_arity);

                    type_val_inner_product.allocate(this->pb);
                    for (auto &msg : this->incoming_messages) {
                        incoming_types.emplace_back(msg->type);
                    }

                    compute_type_val_inner_product.reset(
                        new inner_product_component<FieldType>(this->pb, incoming_types, sum_in_packed,
                            type_val_inner_product));

                    unpack_sum_out.reset(new packing_component<FieldType>(
                        this->pb,
                        std::dynamic_pointer_cast<tally_pcd_message_variable<FieldType>>(this->outgoing_message)->sum_bits,
                        sum_out_packed));
                    unpack_count_out.reset(new packing_component<FieldType>(
                        this->pb,
                        std::dynamic_pointer_cast<tally_pcd_message_variable<FieldType>>(this->outgoing_message)
                            ->count_bits,
                        count_out_packed));

                    for (std::size_t i = 0; i < max_arity; ++i) {
                        pack_sum_in.emplace_back(packing_component<FieldType>(
                            this->pb,
                            std::dynamic_pointer_cast<tally_pcd_message_variable<FieldType>>(this->incoming_messages[i])
                                ->sum_bits,
                            sum_in_packed[i]));
                        pack_count_in.emplace_back(packing_component<FieldType>(
                            this->pb,
                            std::dynamic_pointer_cast<tally_pcd_message_variable<FieldType>>(this->incoming_messages[i])
                                ->sum_bits,
                            count_in_packed[i]));
                    }

                    arity_indicators.allocate(this->pb, max_arity + 1);
                }

                template<typename FieldType>
                void tally_cp_handler<FieldType>::generate_r1cs_constraints() {
                    unpack_sum_out->generate_r1cs_constraints(true);
                    unpack_count_out->generate_r1cs_constraints(true);

                    for (std::size_t i = 0; i < this->max_arity; ++i) {
                        pack_sum_in[i].generate_r1cs_constraints(true);
                        pack_count_in[i].generate_r1cs_constraints(true);
                    }

                    for (std::size_t i = 0; i < this->max_arity; ++i) {
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(incoming_types[i], sum_in_packed_aux[i], sum_in_packed[i]));
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(incoming_types[i], count_in_packed_aux[i], count_in_packed[i]));
                    }

                    /* constrain arity indicator variables so that arity_indicators[arity] = 1 and arity_indicators[i] =
                     * 0 for any other i */
                    for (std::size_t i = 0; i < this->max_arity; ++i) {
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(this->arity - FieldType(i), arity_indicators[i], 0));
                    }

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(1, pb_sum<FieldType>(arity_indicators), 1));

                    /* require that types of messages that are past arity (i.e. unbound wires) carry 0 */
                    for (std::size_t i = 0; i < this->max_arity; ++i) {
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(0 + pb_sum<FieldType>(blueprint_variable_vector<FieldType>(
                                arity_indicators.begin(), arity_indicators.begin() + i)),
                                incoming_types[i], 0));
                    }

                    /* sum_out = local_data + \sum_i type[i] * sum_in[i] */
                    compute_type_val_inner_product->generate_r1cs_constraints();
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(
                            1,
                            type_val_inner_product +
                            std::dynamic_pointer_cast<tally_pcd_local_data_variable<FieldType>>(this->local_data)
                                ->summand,
                            sum_out_packed),
                        "update_sum");

                    /* count_out = 1 + \sum_i count_in[i] */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(1, 1 + pb_sum<FieldType>(count_in_packed), count_out_packed),
                        "update_count");
                }

                template<typename FieldType>
                void tally_cp_handler<FieldType>::generate_r1cs_witness(
                    const std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> &incoming_messages,
                    const std::shared_ptr<r1cs_pcd_local_data<FieldType>> &local_data) {
                    base_handler::generate_r1cs_witness(incoming_messages, local_data);

                    for (std::size_t i = 0; i < this->max_arity; ++i) {
                        pack_sum_in[i].generate_r1cs_witness_from_bits();
                        pack_count_in[i].generate_r1cs_witness_from_bits();

                        if (!this->pb.val(incoming_types[i]).is_zero()) {
                            this->pb.val(sum_in_packed_aux[i]) =
                                this->pb.val(sum_in_packed[i]) * this->pb.val(incoming_types[i]).inverse();
                            this->pb.val(count_in_packed_aux[i]) =
                                this->pb.val(count_in_packed[i]) * this->pb.val(incoming_types[i]).inverse();
                        }
                    }

                    for (std::size_t i = 0; i < this->max_arity + 1; ++i) {
                        this->pb.val(arity_indicators[i]) =
                            (incoming_messages.size() == i ? FieldType::value_type::zero() : FieldType::value_type::zero());
                    }

                    compute_type_val_inner_product->generate_r1cs_witness();
                    this->pb.val(sum_out_packed) =
                        this->pb.val(std::dynamic_pointer_cast<tally_pcd_local_data_variable<FieldType>>(this->local_data)
                            ->summand) +
                        this->pb.val(type_val_inner_product);

                    this->pb.val(count_out_packed) = FieldType::value_type::zero();
                    for (std::size_t i = 0; i < this->max_arity; ++i) {
                        this->pb.val(count_out_packed) += this->pb.val(count_in_packed[i]);
                    }

                    unpack_sum_out->generate_r1cs_witness_from_packed();
                    unpack_count_out->generate_r1cs_witness_from_packed();
                }

                template<typename FieldType>
                std::shared_ptr<r1cs_pcd_message<FieldType>> tally_cp_handler<FieldType>::get_base_case_message() const {
                    const std::size_t type = 0;
                    const std::size_t sum = 0;
                    const std::size_t count = 0;

                    std::shared_ptr<r1cs_pcd_message<FieldType>> result;
                    result.reset(new tally_pcd_message<FieldType>(type, wordsize, sum, count));

                    return result;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TALLY_CP_HPP
