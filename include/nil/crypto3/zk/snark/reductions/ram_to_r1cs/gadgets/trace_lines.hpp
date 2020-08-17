//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for trace-line variables.
//---------------------------------------------------------------------------//

#ifndef TRACE_LINES_HPP_
#define TRACE_LINES_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A memory line contains variables for the following:
                 * - timestamp
                 * - address
                 * - contents_before
                 * - contents_after
                 *
                 * Memory lines are used by memory_checker_gadget.
                 */
                template<typename ramT>
                class memory_line_variable_gadget : public ram_gadget_base<ramT> {
                public:
                    typedef ram_base_field<ramT> FieldType;

                    std::shared_ptr<dual_variable_gadget<FieldType>> timestamp;
                    std::shared_ptr<dual_variable_gadget<FieldType>> address;
                    std::shared_ptr<dual_variable_gadget<FieldType>> contents_before;
                    std::shared_ptr<dual_variable_gadget<FieldType>> contents_after;

                public:
                    memory_line_variable_gadget(ram_protoboard<ramT> &pb,
                                                const std::size_t timestamp_size,
                                                const ram_architecture_params<ramT> &ap);

                    void generate_r1cs_constraints(const bool enforce_bitness = false);
                    void generate_r1cs_witness_from_bits();
                    void generate_r1cs_witness_from_packed();

                    pb_variable_array<FieldType> all_vars() const;
                };

                /**
                 * An execution line inherits from a memory line and, in addition, contains
                 * variables for a CPU state and for a flag denoting if the machine has accepted.
                 *
                 * Execution lines are used by execution_checker_gadget.
                 */
                template<typename ramT>
                class execution_line_variable_gadget : public memory_line_variable_gadget<ramT> {
                public:
                    typedef ram_base_field<ramT> FieldType;

                    pb_variable_array<FieldType> cpu_state;
                    pb_variable<FieldType> has_accepted;

                    execution_line_variable_gadget(ram_protoboard<ramT> &pb,
                                                   const std::size_t timestamp_size,
                                                   const ram_architecture_params<ramT> &ap);
                };

                template<typename ramT>
                memory_line_variable_gadget<ramT>::memory_line_variable_gadget(
                    ram_protoboard<ramT> &pb,
                    const std::size_t timestamp_size,
                    const ram_architecture_params<ramT> &ap) :
                    ram_gadget_base<ramT>(pb) {
                    const std::size_t address_size = ap.address_size();
                    const std::size_t value_size = ap.value_size();

                    timestamp.reset(new dual_variable_gadget<FieldType>(pb, timestamp_size));
                    address.reset(new dual_variable_gadget<FieldType>(pb, address_size));
                    contents_before.reset(new dual_variable_gadget<FieldType>(pb, value_size));
                    contents_after.reset(new dual_variable_gadget<FieldType>(pb, value_size));
                }

                template<typename ramT>
                void memory_line_variable_gadget<ramT>::generate_r1cs_constraints(const bool enforce_bitness) {
                    timestamp->generate_r1cs_constraints(enforce_bitness);
                    address->generate_r1cs_constraints(enforce_bitness);
                    contents_before->generate_r1cs_constraints(enforce_bitness);
                    contents_after->generate_r1cs_constraints(enforce_bitness);
                }

                template<typename ramT>
                void memory_line_variable_gadget<ramT>::generate_r1cs_witness_from_bits() {
                    timestamp->generate_r1cs_witness_from_bits();
                    address->generate_r1cs_witness_from_bits();
                    contents_before->generate_r1cs_witness_from_bits();
                    contents_after->generate_r1cs_witness_from_bits();
                }

                template<typename ramT>
                void memory_line_variable_gadget<ramT>::generate_r1cs_witness_from_packed() {
                    timestamp->generate_r1cs_witness_from_packed();
                    address->generate_r1cs_witness_from_packed();
                    contents_before->generate_r1cs_witness_from_packed();
                    contents_after->generate_r1cs_witness_from_packed();
                }

                template<typename ramT>
                pb_variable_array<ram_base_field<ramT>> memory_line_variable_gadget<ramT>::all_vars() const {
                    pb_variable_array<FieldType> r;
                    r.insert(r.end(), timestamp->bits.begin(), timestamp->bits.end());
                    r.insert(r.end(), address->bits.begin(), address->bits.end());
                    r.insert(r.end(), contents_before->bits.begin(), contents_before->bits.end());
                    r.insert(r.end(), contents_after->bits.begin(), contents_after->bits.end());

                    return r;
                }

                template<typename ramT>
                execution_line_variable_gadget<ramT>::execution_line_variable_gadget(
                    ram_protoboard<ramT> &pb,
                    const std::size_t timestamp_size,
                    const ram_architecture_params<ramT> &ap) :
                    memory_line_variable_gadget<ramT>(pb, timestamp_size, ap) {
                    const std::size_t cpu_state_size = ap.cpu_state_size();

                    cpu_state.allocate(pb, cpu_state_size);
                    has_accepted.allocate(pb);
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // TRACE_LINES_HPP_
