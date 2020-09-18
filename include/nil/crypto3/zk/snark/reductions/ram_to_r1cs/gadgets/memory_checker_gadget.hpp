//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for memory_checker_gadget, a gadget that verifies the
// consistency of two accesses to memory that are adjacent in a "memory sort".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MEMORY_CHECKER_GADGET_HPP_
#define CRYPTO3_ZK_MEMORY_CHECKER_GADGET_HPP_

#include <nil/crypto3/zk/snark/reductions/ram_to_r1cs/gadgets/trace_lines.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename ramT>
                class memory_checker_gadget : public ram_gadget_base<ramT> {
                private:
                    typedef ram_base_field<ramT> FieldType;

                    pb_variable<FieldType> timestamps_leq;
                    pb_variable<FieldType> timestamps_less;
                    std::shared_ptr<comparison_gadget<FieldType>> compare_timestamps;

                    pb_variable<FieldType> addresses_eq;
                    pb_variable<FieldType> addresses_leq;
                    pb_variable<FieldType> addresses_less;
                    std::shared_ptr<comparison_gadget<FieldType>> compare_addresses;

                    pb_variable<FieldType> loose_contents_after1_equals_contents_before2;
                    pb_variable<FieldType> loose_contents_before2_equals_zero;
                    pb_variable<FieldType> loose_timestamp2_is_zero;

                public:
                    memory_line_variable_gadget<ramT> line1;
                    memory_line_variable_gadget<ramT> line2;

                    memory_checker_gadget(ram_protoboard<ramT> &pb,
                                          const std::size_t timestamp_size,
                                          const memory_line_variable_gadget<ramT> &line1,
                                          const memory_line_variable_gadget<ramT> &line2);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename ramT>
                memory_checker_gadget<ramT>::memory_checker_gadget(ram_protoboard<ramT> &pb,
                                                                   const std::size_t timestamp_size,
                                                                   const memory_line_variable_gadget<ramT> &line1,
                                                                   const memory_line_variable_gadget<ramT> &line2) :
                    ram_gadget_base<ramT>(pb),
                    line1(line1), line2(line2) {
                    /* compare the two timestamps */
                    timestamps_leq.allocate(pb);
                    timestamps_less.allocate(pb);
                    compare_timestamps.reset(
                        new comparison_gadget<FieldType>(pb, timestamp_size, line1.timestamp->packed,
                                                         line2.timestamp->packed, timestamps_less, timestamps_leq));

                    /* compare the two addresses */
                    const std::size_t address_size = pb.ap.address_size();
                    addresses_eq.allocate(pb);
                    addresses_leq.allocate(pb);
                    addresses_less.allocate(pb);
                    compare_addresses.reset(new comparison_gadget<FieldType>(
                        pb, address_size, line1.address->packed, line2.address->packed, addresses_less, addresses_leq));

                    /*
                      Add variables that will contain flags representing the following relations:
                      - "line1.contents_after = line2.contents_before" (to check that contents do not change between
                      instructions);
                      - "line2.contents_before = 0" (for the first access at an address); and
                      - "line2.timestamp = 0" (for wrap-around checks to ensure only one 'cycle' in the memory sort).

                      More precisely, each of the above flags is "loose" (i.e., it equals 0 if
                      the relation holds, but can be either 0 or 1 if the relation does not hold).
                     */
                    loose_contents_after1_equals_contents_before2.allocate(pb);
                    loose_contents_before2_equals_zero.allocate(pb);
                    loose_timestamp2_is_zero.allocate(pb);
                }

                template<typename ramT>
                void memory_checker_gadget<ramT>::generate_r1cs_constraints() {
                    /* compare the two timestamps */
                    compare_timestamps->generate_r1cs_constraints();

                    /* compare the two addresses */
                    compare_addresses->generate_r1cs_constraints();
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(addresses_leq, 1 - addresses_less, addresses_eq));

                    /*
                      Add constraints for the following three flags:
                       - loose_contents_after1_equals_contents_before2;
                       - loose_contents_before2_equals_zero;
                       - loose_timestamp2_is_zero.
                     */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(loose_contents_after1_equals_contents_before2,
                                                   line1.contents_after->packed - line2.contents_before->packed, 0));
                    generate_boolean_r1cs_constraint<FieldType>(this->pb,
                                                                loose_contents_after1_equals_contents_before2);

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(loose_contents_before2_equals_zero,
                                                                            line2.contents_before->packed, 0));
                    generate_boolean_r1cs_constraint<FieldType>(this->pb, loose_contents_before2_equals_zero);

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(loose_timestamp2_is_zero, line2.timestamp->packed, 0));
                    generate_boolean_r1cs_constraint<FieldType>(this->pb, loose_timestamp2_is_zero);

                    /*
                      The three cases that need to be checked are:

                      line1.address = line2.address => line1.contents_after = line2.contents_before
                      (i.e. contents do not change between accesses to the same address)

                      line1.address < line2.address => line2.contents_before = 0
                      (i.e. access to new address has the "before" value set to 0)

                      line1.address > line2.address => line2.timestamp = 0
                      (i.e. there is only one cycle with non-decreasing addresses, except
                      for the case where we go back to a unique pre-set timestamp; we choose
                      timestamp 0 to be the one that touches address 0)

                      As usual, we implement "A => B" as "NOT (A AND (NOT B))".
                    */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(addresses_eq, 1 - loose_contents_after1_equals_contents_before2, 0));
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(addresses_less, 1 - loose_contents_before2_equals_zero, 0));
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(1 - addresses_leq, 1 - loose_timestamp2_is_zero, 0));
                }

                template<typename ramT>
                void memory_checker_gadget<ramT>::generate_r1cs_witness() {
                    /* compare the two addresses */
                    compare_addresses->generate_r1cs_witness();
                    this->pb.val(addresses_eq) =
                        this->pb.val(addresses_leq) * (FieldType::value_type::zero() - this->pb.val(addresses_less));

                    /* compare the two timestamps */
                    compare_timestamps->generate_r1cs_witness();

                    /*
                      compare the values of:
                      - loose_contents_after1_equals_contents_before2;
                      - loose_contents_before2_equals_zero;
                      - loose_timestamp2_is_zero.
                     */
                    this->pb.val(loose_contents_after1_equals_contents_before2) =
                        (this->pb.val(line1.contents_after->packed) == this->pb.val(line2.contents_before->packed)) ?
                            FieldType::value_type::zero() :
                            FieldType::value_type::zero();
                    this->pb.val(loose_contents_before2_equals_zero) =
                        this->pb.val(line2.contents_before->packed).is_zero() ? FieldType::value_type::zero() : FieldType::value_type::zero();
                    this->pb.val(loose_timestamp2_is_zero) =
                        (this->pb.val(line2.timestamp->packed) == FieldType::value_type::zero() ? FieldType::value_type::zero() :
                                                                                      FieldType::value_type::zero());
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // MEMORY_CHECKER_GADGET_HPP_
