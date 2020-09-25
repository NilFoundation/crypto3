//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for ram_universal_component.
//
// Given bounds on a RAM computation size (program size bound, primary input
// size bound, and time bound), the "RAM universal component" checks the correct
// execution of any RAM computation that fits the bounds.
//
// The implementation follows, extends, and optimizes the approach described
// in \[BCTV14] (itself building on \[BCGTV13]). The code is parameterized by
// the template parameter RAMType, in order to support any RAM that fits certain
// abstract interfaces.
//
// Roughly, the component has three main components:
// - For each time step, a copy of a *execution checker* (which is the RAM CPU checker).
// - For each time step, a copy of a *memory checker* (which verifies memory consistency
//   between two 'memory lines' that are adjacent in a memory sort).
// - A single *routing network* (specifically, an arbitrary-size Waksman network),
//   which is used check that memory accesses are permutated according to some permutation.
//
// References:
//
// \[BCGTV13]:
// "SNARKs for C: verifying program executions succinctly and in zero knowledge",
// Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Eran Tromer, Madars Virza,
// CRYPTO 2014,
// <http://eprint.iacr.org/2013/507>
//
// \[BCTV14]:
// "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// USENIX Security 2014,
// <http://eprint.iacr.org/2013/879>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_RAM_UNIVERSAL_COMPONENT_HPP_
#define CRYPTO3_ZK_RAM_UNIVERSAL_COMPONENT_HPP_

#include <nil/crypto3/zk/snark/components/routing/as_waksman_components.hpp>
#include <nil/crypto3/zk/snark/reductions/ram_to_r1cs/components/memory_checker_component.hpp>
#include <nil/crypto3/zk/snark/reductions/ram_to_r1cs/components/trace_lines.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/memory/ra_memory.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /*
                  Memory layout for our reduction is as follows:

                  (1) An initial execution line carrying the initial state (set
                      to all zeros)
                  (2) program_size_bound + primary_input_size_bound memory lines for
                      storing input and program (boot)
                  (3) time_bound pairs for (fetch instruction memory line, execute
                      instruction execution line)

                  Memory line stores address, previous value and the next value of the
                  memory cell specified by the address. An execution line additionally
                  carries the CPU state.

                  Our memory handling technique has a technical requirement that
                  address 0 must be accessed. We fulfill this by requiring the initial
                  execution line to act as "store 0 to address 0".

                  ---

                  As an implementation detail if less than program_size_bound +
                  primary_input_size_bound are used in the initial memory map, then we
                  pre-pend (!) them with "store 0 to address 0" lines. This
                  pre-pending means that memory maps that have non-zero value at
                  address 0 will still be handled correctly.

                  The R1CS input packs the memory map starting from the last entry to
                  the first. This way, the prepended zeros arrive at the end of R1CS
                  input and thus can be ignored by the "weak" input consistency R1CS
                  verifier.
                */

                template<typename RAMType>
                class ram_universal_component : public ram_component_base<RAMType> {
                public:
                    typedef ram_base_field<RAMType> FieldType;

                    std::size_t num_memory_lines;

                    std::vector<memory_line_variable_component<RAMType>> boot_lines;
                    std::vector<blueprint_variable_vector<FieldType>> boot_line_bits;
                    std::vector<multipacking_component<FieldType>> unpack_boot_lines;

                    std::vector<memory_line_variable_component<RAMType>> load_instruction_lines;
                    std::vector<execution_line_variable_component<RAMType>>
                        execution_lines; /* including the initial execution line */

                    std::vector<memory_line_variable_component<RAMType> *> unrouted_memory_lines;
                    std::vector<memory_line_variable_component<RAMType>> routed_memory_lines;

                    std::vector<ram_cpu_checker<RAMType>> execution_checkers;
                    std::vector<memory_checker_component<RAMType>> memory_checkers;

                    std::vector<blueprint_variable_vector<FieldType>> routing_inputs;
                    std::vector<blueprint_variable_vector<FieldType>> routing_outputs;

                    std::shared_ptr<as_waksman_routing_component<FieldType>> routing_network;

                public:
                    std::size_t boot_trace_size_bound;
                    std::size_t time_bound;
                    blueprint_variable_vector<FieldType> packed_input;

                    ram_universal_component(ram_blueprint<RAMType> &pb,
                                            const std::size_t boot_trace_size_bound,
                                            const std::size_t time_bound,
                                            const blueprint_variable_vector<FieldType> &packed_input);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(const ram_boot_trace<RAMType> &boot_trace,
                                               const ram_input_tape<RAMType> &auxiliary_input);

                    /* both methods assume that generate_r1cs_witness has been called */
                    void print_execution_trace() const;
                    void print_memory_trace() const;

                    static std::size_t packed_input_value_bits(const ram_architecture_params<RAMType> &ap);
                    static std::size_t packed_input_size(const ram_architecture_params<RAMType> &ap,
                                                         const std::size_t boot_trace_size_bound);
                };

                template<typename RAMType>
                ram_universal_component<RAMType>::ram_universal_component(
                    ram_blueprint<RAMType> &pb,
                    const std::size_t boot_trace_size_bound,
                    const std::size_t time_bound,
                    const blueprint_variable_vector<FieldType> &packed_input) :
                    ram_component_base<RAMType>(pb),
                    boot_trace_size_bound(boot_trace_size_bound), time_bound(time_bound), packed_input(packed_input) {
                    num_memory_lines = boot_trace_size_bound + (time_bound + 1) +
                                       time_bound; /* boot lines, (time_bound + 1) execution lines (including initial)
                                                      and time_bound load instruction lines */
                    const std::size_t timestamp_size = static_cast<std::size_t>(std::ceil(std::log2(num_memory_lines)));

                    /* allocate all lines on the execution side of the routing network */
                    execution_lines.reserve(1 + time_bound);
                    execution_lines.emplace_back(execution_line_variable_component<RAMType>(pb, timestamp_size, pb.ap));
                    unrouted_memory_lines.emplace_back(&execution_lines[0]);

                    boot_lines.reserve(boot_trace_size_bound);
                    for (std::size_t i = 0; i < boot_trace_size_bound; ++i) {
                        boot_lines.emplace_back(memory_line_variable_component<RAMType>(pb, timestamp_size, pb.ap));
                        unrouted_memory_lines.emplace_back(&boot_lines[i]);
                    }

                    load_instruction_lines.reserve(time_bound +
                                                   1); /* the last line is NOT a memory line, but here just for uniform
                                                          coding (i.e. the (unused) result of next PC) */
                    for (std::size_t i = 0; i < time_bound; ++i) {
                        load_instruction_lines.emplace_back(
                            memory_line_variable_component<RAMType>(pb, timestamp_size, pb.ap));
                        unrouted_memory_lines.emplace_back(&load_instruction_lines[i]);

                        execution_lines.emplace_back(
                            execution_line_variable_component<RAMType>(pb, timestamp_size, pb.ap));
                        unrouted_memory_lines.emplace_back(&execution_lines[i + 1]);
                    }
                    load_instruction_lines.emplace_back(
                        memory_line_variable_component<RAMType>(pb, timestamp_size, pb.ap));

                    /* deal with packing of the input */
                    const std::size_t line_size_bits = pb.ap.address_size() + pb.ap.value_size();
                    const std::size_t max_chunk_size = FieldType::capacity();
                    const std::size_t packed_line_size = (line_size_bits + (max_chunk_size - 1)) / max_chunk_size;
                    assert(packed_input.size() == packed_line_size * boot_trace_size_bound);

                    auto input_it = packed_input.begin();
                    for (std::size_t i = 0; i < boot_trace_size_bound; ++i) {
                        /* note the reversed order */
                        blueprint_variable_vector<FieldType> boot_line_bits;
                        boot_line_bits.insert(boot_line_bits.end(),
                                              boot_lines[boot_trace_size_bound - 1 - i].address->bits.begin(),
                                              boot_lines[boot_trace_size_bound - 1 - i].address->bits.end());
                        boot_line_bits.insert(boot_line_bits.end(),
                                              boot_lines[boot_trace_size_bound - 1 - i].contents_after->bits.begin(),
                                              boot_lines[boot_trace_size_bound - 1 - i].contents_after->bits.end());

                        blueprint_variable_vector<FieldType> packed_boot_line =
                            blueprint_variable_vector<FieldType>(input_it, input_it + packed_line_size);
                        std::advance(input_it, packed_line_size);

                        unpack_boot_lines.emplace_back(
                            multipacking_component<FieldType>(pb, boot_line_bits, packed_boot_line, max_chunk_size));
                    }

                    /* deal with routing */
                    for (std::size_t i = 0; i < num_memory_lines; ++i) {
                        routed_memory_lines.emplace_back(
                            memory_line_variable_component<RAMType>(pb, timestamp_size, pb.ap));
                    }

                    routing_inputs.reserve(num_memory_lines);
                    routing_outputs.reserve(num_memory_lines);

                    for (std::size_t i = 0; i < num_memory_lines; ++i) {
                        routing_inputs.emplace_back(unrouted_memory_lines[i]->all_vars());
                        routing_outputs.emplace_back(routed_memory_lines[i].all_vars());
                    }

                    routing_network.reset(new as_waksman_routing_component<FieldType>(pb, num_memory_lines,
                                                                                      routing_inputs, routing_outputs));

                    /* deal with all checkers */
                    execution_checkers.reserve(time_bound);
                    for (std::size_t i = 0; i < time_bound; ++i) {
                        execution_checkers.emplace_back(
                            ram_cpu_checker<RAMType>(pb,
                                                     load_instruction_lines[i].address->bits,           // prev_pc_addr
                                                     load_instruction_lines[i].contents_after->bits,    // prev_pc_val
                                                     execution_lines[i].cpu_state,                      // prev_state
                                                     execution_lines[i + 1].address->bits,              // ls_addr,
                                                     execution_lines[i + 1].contents_before->bits,      // ls_prev_val
                                                     execution_lines[i + 1].contents_after->bits,       // ls_next_val
                                                     execution_lines[i + 1].cpu_state,                  // next_state
                                                     load_instruction_lines[i + 1].address->bits,       // next_pc_addr
                                                     execution_lines[i + 1].has_accepted    // next_has_accepted
                                                     ));
                    }

                    memory_checkers.reserve(num_memory_lines);
                    for (std::size_t i = 0; i < num_memory_lines; ++i) {
                        memory_checkers.emplace_back(memory_checker_component<RAMType>(
                            pb, timestamp_size, *unrouted_memory_lines[i], routed_memory_lines[i]));
                    }
                    /* done */
                }

                template<typename RAMType>
                void ram_universal_component<RAMType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < boot_trace_size_bound; ++i) {
                        unpack_boot_lines[i].generate_r1cs_constraints(false);
                    }

                    /* ensure that we start with all zeros state */
                    for (std::size_t i = 0; i < this->pb.ap.cpu_state_size(); ++i) {
                        generate_r1cs_equals_const_constraint<FieldType>(this->pb, execution_lines[0].cpu_state[i],
                                                                         FieldType::value_type::zero());
                    }

                    /* ensure increasing timestamps */
                    for (std::size_t i = 0; i < num_memory_lines; ++i) {
                        generate_r1cs_equals_const_constraint<FieldType>(
                            this->pb, unrouted_memory_lines[i]->timestamp->packed, typename FieldType::value_type(i));
                    }

                    /* ensure bitness of trace lines on the time side */
                    for (std::size_t i = 0; i < boot_trace_size_bound; ++i) {
                        boot_lines[i].generate_r1cs_constraints(true);
                    }

                    execution_lines[0].generate_r1cs_constraints(true);
                    for (std::size_t i = 0; i < time_bound; ++i) {
                        load_instruction_lines[i].generate_r1cs_constraints(true);
                        execution_lines[i + 1].generate_r1cs_constraints(true);
                    }

                    /* ensure bitness of trace lines on the memory side */
                    for (std::size_t i = 0; i < num_memory_lines; ++i) {
                        routed_memory_lines[i].generate_r1cs_constraints();
                    }

                    /* ensure that load instruction lines really do loads */
                    for (std::size_t i = 0; i < time_bound; ++i) {
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(1, load_instruction_lines[i].contents_before->packed,
                                                       load_instruction_lines[i].contents_after->packed));
                    }

                    /* ensure correct execution */
                    for (std::size_t i = 0; i < time_bound; ++i) {
                        execution_checkers[i].generate_r1cs_constraints();
                    }

                    /* check memory */
                    routing_network->generate_r1cs_constraints();

                    for (std::size_t i = 0; i < num_memory_lines; ++i) {
                        memory_checkers[i].generate_r1cs_constraints();
                    }

                    /* ensure that PC started at the prescribed value */
                    generate_r1cs_equals_const_constraint<FieldType>(
                        this->pb, load_instruction_lines[0].address->packed,
                        typename FieldType::value_type(this->pb.ap.initial_pc_addr()));

                    /* ensure that the last state was an accepting one */
                    generate_r1cs_equals_const_constraint<FieldType>(this->pb, execution_lines[time_bound].has_accepted,
                                                                     FieldType::value_type::zero());

                    /* print constraint profiling */
                    const std::size_t num_constraints = this->pb.num_constraints();
                    const std::size_t num_variables = this->pb.num_variables();
                }

                template<typename RAMType>
                void ram_universal_component<RAMType>::generate_r1cs_witness(
                    const ram_boot_trace<RAMType> &boot_trace,
                    const ram_input_tape<RAMType> &auxiliary_input) {
                    /* assign correct timestamps to all lines */
                    for (std::size_t i = 0; i < num_memory_lines; ++i) {
                        this->pb.val(unrouted_memory_lines[i]->timestamp->packed) = typename FieldType::value_type(i);
                        unrouted_memory_lines[i]->timestamp->generate_r1cs_witness_from_packed();
                    }

                    /* fill in the initial state */
                    const ram_cpu_state<RAMType> initial_state = this->pb.ap.initial_cpu_state();
                    execution_lines[0].cpu_state.fill_with_bits(this->pb, initial_state);

                    /* fill in the boot section */
                    memory_contents memory_after_boot;

                    for (auto it : boot_trace.get_all_trace_entries()) {
                        const std::size_t boot_pos = it.first;
                        assert(boot_pos < boot_trace_size_bound);
                        const std::size_t address = it.second.first;
                        const std::size_t contents = it.second.second;

                        this->pb.val(boot_lines[boot_pos].address->packed) =
                            typename FieldType::value_type(address, true);
                        this->pb.val(boot_lines[boot_pos].contents_after->packed) =
                            typename FieldType::value_type(contents, true);
                        boot_lines[boot_pos].generate_r1cs_witness_from_packed();

                        memory_after_boot[address] = contents;
                    }

                    /* do the actual execution */
                    ra_memory mem_backend(1ul << (this->pb.ap.address_size()), this->pb.ap.value_size(),
                                          memory_after_boot);
                    typename ram_input_tape<RAMType>::const_iterator auxiliary_input_it = auxiliary_input.begin();

                    this->pb.val(load_instruction_lines[0].address->packed) =
                        typename FieldType::value_type(this->pb.ap.initial_pc_addr(), true);
                    load_instruction_lines[0].address->generate_r1cs_witness_from_packed();

                    for (std::size_t i = 0; i < time_bound; ++i) {
                        /* load instruction */
                        const std::size_t pc_addr = this->pb.val(load_instruction_lines[i].address->packed).as_ulong();
                        const std::size_t pc_val = mem_backend.get_value(pc_addr);

                        this->pb.val(load_instruction_lines[i].contents_before->packed) =
                            typename FieldType::value_type(pc_val, true);
                        this->pb.val(load_instruction_lines[i].contents_after->packed) =
                            typename FieldType::value_type(pc_val, true);
                        load_instruction_lines[i].generate_r1cs_witness_from_packed();

                        /* first fetch the address part of the memory */
                        execution_checkers[i].generate_r1cs_witness_address();
                        execution_lines[i + 1].address->generate_r1cs_witness_from_bits();

                        /* fill it in */
                        const std::size_t load_store_addr =
                            this->pb.val(execution_lines[i + 1].address->packed).as_ulong();
                        const std::size_t load_store_prev_val = mem_backend.get_value(load_store_addr);

                        this->pb.val(execution_lines[i + 1].contents_before->packed) =
                            typename FieldType::value_type(load_store_prev_val, true);
                        execution_lines[i + 1].contents_before->generate_r1cs_witness_from_packed();

                        /* then execute the rest of the instruction */
                        execution_checkers[i].generate_r1cs_witness_other(auxiliary_input_it, auxiliary_input.end());

                        /* update the memory possibly changed by the CPU checker */
                        execution_lines[i + 1].contents_after->generate_r1cs_witness_from_bits();
                        const std::size_t load_store_next_val =
                            this->pb.val(execution_lines[i + 1].contents_after->packed).as_ulong();
                        mem_backend.set_value(load_store_addr, load_store_next_val);

                        /* the next PC address was passed in a bit form, so maintain packed form as well */
                        load_instruction_lines[i + 1].address->generate_r1cs_witness_from_bits();
                    }

                    /*
                      Get the correct memory permutation.

                      We sort all memory accesses by address breaking ties by
                      timestamp. In our routing configuration we pair each memory
                      access with subsequent access in this ordering.

                      That way num_memory_pairs of memory checkers will do a full
                      cycle over all memory accesses, enforced by the proper ordering
                      property.
                    */

                    typedef std::pair<std::size_t, std::size_t> mem_pair; /* a pair of address, timestamp */
                    std::vector<mem_pair> mem_pairs;

                    for (std::size_t i = 0; i < this->num_memory_lines; ++i) {
                        mem_pairs.emplace_back(
                            std::make_pair(this->pb.val(unrouted_memory_lines[i]->address->packed).as_ulong(),
                                           this->pb.val(unrouted_memory_lines[i]->timestamp->packed).as_ulong()));
                    }

                    std::sort(mem_pairs.begin(), mem_pairs.end());

                    integer_permutation pi(this->num_memory_lines);
                    for (std::size_t i = 0; i < this->num_memory_lines; ++i) {
                        const std::size_t timestamp =
                            this->pb.val(unrouted_memory_lines[i]->timestamp->packed).as_ulong();
                        const std::size_t address = this->pb.val(unrouted_memory_lines[i]->address->packed).as_ulong();

                        const auto it =
                            std::upper_bound(mem_pairs.begin(), mem_pairs.end(), std::make_pair(address, timestamp));
                        const std::size_t prev = (it == mem_pairs.end() ? 0 : it->second);
                        pi.set(prev, i);
                    }

                    /* route according to the memory permutation */
                    routing_network->generate_r1cs_witness(pi);

                    for (std::size_t i = 0; i < this->num_memory_lines; ++i) {
                        routed_memory_lines[i].generate_r1cs_witness_from_bits();
                    }

                    /* generate witness for memory checkers */
                    for (std::size_t i = 0; i < this->num_memory_lines; ++i) {
                        memory_checkers[i].generate_r1cs_witness();
                    }

                    /* repack back the input */
                    for (std::size_t i = 0; i < boot_trace_size_bound; ++i) {
                        unpack_boot_lines[i].generate_r1cs_witness_from_bits();
                    }
                }

                template<typename RAMType>
                void ram_universal_component<RAMType>::print_execution_trace() const {
                    for (std::size_t i = 0; i < boot_trace_size_bound; ++i) {
                        printf("Boot process at t=#%zu: store %zu at %zu\n",
                               i,
                               this->pb.val(boot_lines[i].contents_after->packed).as_ulong(),
                               this->pb.val(boot_lines[i].address->packed).as_ulong());
                    }

                    for (std::size_t i = 0; i < time_bound; ++i) {
                        printf("Execution step %zu:\n", i);
                        printf("  Loaded instruction %zu from address %zu (ts = %zu)\n",
                               this->pb.val(load_instruction_lines[i].contents_after->packed).as_ulong(),
                               this->pb.val(load_instruction_lines[i].address->packed).as_ulong(),
                               this->pb.val(load_instruction_lines[i].timestamp->packed).as_ulong());

                        printf("  Debugging information from the transition function:\n");
                        execution_checkers[i].dump();

                        printf(
                            "  Memory operation executed: addr = %zu, contents_before = %zu, contents_after = %zu "
                            "(ts_before = "
                            "%zu, ts_after = %zu)\n",
                            this->pb.val(execution_lines[i + 1].address->packed).as_ulong(),
                            this->pb.val(execution_lines[i + 1].contents_before->packed).as_ulong(),
                            this->pb.val(execution_lines[i + 1].contents_after->packed).as_ulong(),
                            this->pb.val(execution_lines[i].timestamp->packed).as_ulong(),
                            this->pb.val(execution_lines[i + 1].timestamp->packed).as_ulong());
                    }
                }

                template<typename RAMType>
                void ram_universal_component<RAMType>::print_memory_trace() const {
                    for (std::size_t i = 0; i < num_memory_lines; ++i) {
                        printf("Memory access #%zu:\n", i);
                        printf("  Time side  : ts = %zu, address = %zu, contents_before = %zu, contents_after = %zu\n",
                               this->pb.val(unrouted_memory_lines[i]->timestamp->packed).as_ulong(),
                               this->pb.val(unrouted_memory_lines[i]->address->packed).as_ulong(),
                               this->pb.val(unrouted_memory_lines[i]->contents_before->packed).as_ulong(),
                               this->pb.val(unrouted_memory_lines[i]->contents_after->packed).as_ulong());
                        printf("  Memory side: ts = %zu, address = %zu, contents_before = %zu, contents_after = %zu\n",
                               this->pb.val(routed_memory_lines[i].timestamp->packed).as_ulong(),
                               this->pb.val(routed_memory_lines[i].address->packed).as_ulong(),
                               this->pb.val(routed_memory_lines[i].contents_before->packed).as_ulong(),
                               this->pb.val(routed_memory_lines[i].contents_after->packed).as_ulong());
                    }
                }

                template<typename RAMType>
                std::size_t ram_universal_component<RAMType>::packed_input_value_bits(
                    const ram_architecture_params<RAMType> &ap) {
                    const std::size_t line_size_bits = ap.address_size() + ap.value_size();
                    const std::size_t max_chunk_size = FieldType::capacity();
                    const std::size_t packed_line_size = (line_size_bits + (max_chunk_size - 1)) / max_chunk_size;

                    return packed_line_size;
                }

                template<typename RAMType>
                std::size_t
                    ram_universal_component<RAMType>::packed_input_size(const ram_architecture_params<RAMType> &ap,
                                                                        const std::size_t boot_trace_size_bound) {
                    return packed_input_value_bits(ap) * boot_trace_size_bound;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RAM_UNIVERSAL_COMPONENT_HPP_
