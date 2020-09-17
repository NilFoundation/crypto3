//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a RAM-to-R1CS reduction, that is, constructing
// a R1CS ("Rank-1 Constraint System") from a RAM ("Random-Access Machine").
//
// The implementation is a thin layer around a "RAM universal gadget", which is
// where most of the work is done. See gadgets/ram_universal_gadget.hpp for details.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_RAM_TO_R1CS_HPP_
#define CRYPTO3_ZK_RAM_TO_R1CS_HPP_

#include <nil/crypto3/zk/snark/reductions/ram_to_r1cs/gadgets/ram_universal_gadget.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename ramT>
                class ram_to_r1cs {
                public:
                    typedef ram_base_field<ramT> FieldType;

                    std::size_t boot_trace_size_bound;

                    ram_protoboard<ramT> main_protoboard;
                    pb_variable_array<FieldType> r1cs_input;
                    std::shared_ptr<ram_universal_gadget<ramT>> universal_gadget;

                    ram_to_r1cs(const ram_architecture_params<ramT> &ap,
                                const std::size_t boot_trace_size_bound,
                                const std::size_t time_bound);
                    void instance_map();
                    r1cs_constraint_system<FieldType> get_constraint_system() const;
                    r1cs_auxiliary_input<FieldType> auxiliary_input_map(const ram_boot_trace<ramT> &boot_trace,
                                                                        const ram_input_tape<ramT> &auxiliary_input);

                    /* both methods assume that auxiliary_input_map has been called */
                    void print_execution_trace() const;
                    void print_memory_trace() const;

                    static std::vector<ram_base_field<ramT>>
                        pack_primary_input_address_and_value(const ram_architecture_params<ramT> &ap,
                                                             const address_and_value &av);

                    static r1cs_primary_input<ram_base_field<ramT>>
                        primary_input_map(const ram_architecture_params<ramT> &ap,
                                          const std::size_t boot_trace_size_bound,
                                          const ram_boot_trace<ramT> &boot_trace);
                };

                template<typename ramT>
                ram_to_r1cs<ramT>::ram_to_r1cs(const ram_architecture_params<ramT> &ap,
                                               const std::size_t boot_trace_size_bound,
                                               const std::size_t time_bound) :
                    boot_trace_size_bound(boot_trace_size_bound),
                    main_protoboard(ap) {
                    const std::size_t r1cs_input_size =
                        ram_universal_gadget<ramT>::packed_input_size(ap, boot_trace_size_bound);
                    r1cs_input.allocate(main_protoboard, r1cs_input_size);
                    universal_gadget.reset(new ram_universal_gadget<ramT>(
                        main_protoboard, boot_trace_size_bound, time_bound, r1cs_input));
                    main_protoboard.set_input_sizes(r1cs_input_size);
                }

                template<typename ramT>
                void ram_to_r1cs<ramT>::instance_map() {
                    universal_gadget->generate_r1cs_constraints();
                }

                template<typename ramT>
                r1cs_constraint_system<ram_base_field<ramT>> ram_to_r1cs<ramT>::get_constraint_system() const {
                    return main_protoboard.get_constraint_system();
                }

                template<typename ramT>
                r1cs_primary_input<ram_base_field<ramT>>
                    ram_to_r1cs<ramT>::auxiliary_input_map(const ram_boot_trace<ramT> &boot_trace,
                                                           const ram_input_tape<ramT> &auxiliary_input) {
                    universal_gadget->generate_r1cs_witness(boot_trace, auxiliary_input);
                    return main_protoboard.auxiliary_input();
                }

                template<typename ramT>
                void ram_to_r1cs<ramT>::print_execution_trace() const {
                    universal_gadget->print_execution_trace();
                }

                template<typename ramT>
                void ram_to_r1cs<ramT>::print_memory_trace() const {
                    universal_gadget->print_memory_trace();
                }

                template<typename ramT>
                std::vector<ram_base_field<ramT>>
                    ram_to_r1cs<ramT>::pack_primary_input_address_and_value(const ram_architecture_params<ramT> &ap,
                                                                            const address_and_value &av) {
                    typedef ram_base_field<ramT> FieldType;

                    const std::size_t address = av.first;
                    const std::size_t contents = av.second;

                    const std::vector<bool> address_bits = algebra::convert_field_element_to_bit_vector<FieldType>(
                        typename FieldType::value_type(address, true), ap.address_size());
                    const std::vector<bool> contents_bits = algebra::convert_field_element_to_bit_vector<FieldType>(
                        typename FieldType::value_type(contents, true), ap.value_size());

                    std::vector<bool> trace_element_bits;
                    trace_element_bits.insert(trace_element_bits.end(), address_bits.begin(), address_bits.end());
                    trace_element_bits.insert(trace_element_bits.end(), contents_bits.begin(), contents_bits.end());

                    const std::vector<typename FieldType::value_type> trace_element =
                        algebra::pack_bit_vector_into_field_element_vector<FieldType>(trace_element_bits);

                    return trace_element;
                }

                template<typename ramT>
                r1cs_primary_input<ram_base_field<ramT>>
                    ram_to_r1cs<ramT>::primary_input_map(const ram_architecture_params<ramT> &ap,
                                                         const std::size_t boot_trace_size_bound,
                                                         const ram_boot_trace<ramT> &boot_trace) {
                    typedef ram_base_field<ramT> FieldType;

                    const std::size_t packed_input_element_size = ram_universal_gadget<ramT>::packed_input_element_size(ap);
                    r1cs_primary_input<FieldType> result(
                        ram_universal_gadget<ramT>::packed_input_size(ap, boot_trace_size_bound));

                    std::set<std::size_t> bound_input_locations;

                    for (auto it : boot_trace.get_all_trace_entries()) {
                        const std::size_t input_pos = it.first;
                        const address_and_value av = it.second;

                        assert(input_pos < boot_trace_size_bound);
                        assert(bound_input_locations.find(input_pos) == bound_input_locations.end());

                        const std::vector<typename FieldType::value_type> packed_input_element =
                            ram_to_r1cs<ramT>::pack_primary_input_address_and_value(ap, av);
                        std::copy(packed_input_element.begin(),
                                  packed_input_element.end(),
                                  result.begin() + packed_input_element_size * (boot_trace_size_bound - 1 - input_pos));

                        bound_input_locations.insert(input_pos);
                    }

                    return result;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RAM_TO_R1CS_HPP_
