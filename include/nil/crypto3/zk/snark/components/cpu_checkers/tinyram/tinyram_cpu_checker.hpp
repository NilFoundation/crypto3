//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the TinyRAM CPU checker gadget.
//
// The gadget checks the correct operation for the CPU of the TinyRAM architecture.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TINYRAM_CPU_CHECKER_HPP
#define CRYPTO3_ZK_TINYRAM_CPU_CHECKER_HPP

#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/alu_component.hpp>
#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/argument_decoder_component.hpp>
#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/consistency_enforcer_component.hpp>
#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/memory_masking_component.hpp>
#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/tinyram_blueprint.hpp>
#include <nil/crypto3/zk/snark/components/cpu_checkers/tinyram/components/word_variable_component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class tinyram_cpu_checker : public tinyram_standard_component<FieldType> {
                private:
                    pb_variable_array<FieldType> opcode;
                    variable<FieldType> arg2_is_imm;
                    pb_variable_array<FieldType> desidx;
                    pb_variable_array<FieldType> arg1idx;
                    pb_variable_array<FieldType> arg2idx;

                    std::vector<word_variable_component<FieldType>> prev_registers;
                    std::vector<word_variable_component<FieldType>> next_registers;
                    variable<FieldType> prev_flag;
                    variable<FieldType> next_flag;
                    variable<FieldType> prev_tape1_exhausted;
                    variable<FieldType> next_tape1_exhausted;

                    std::shared_ptr<word_variable_component<FieldType>> prev_pc_addr_as_word_variable;
                    std::shared_ptr<word_variable_component<FieldType>> desval;
                    std::shared_ptr<word_variable_component<FieldType>> arg1val;
                    std::shared_ptr<word_variable_component<FieldType>> arg2val;

                    std::shared_ptr<argument_decoder_component<FieldType>> decode_arguments;
                    pb_variable_array<FieldType> opcode_indicators;
                    std::shared_ptr<ALU_component<FieldType>> ALU;

                    std::shared_ptr<doubleword_variable_component<FieldType>> ls_prev_val_as_doubleword_variable;
                    std::shared_ptr<doubleword_variable_component<FieldType>> ls_next_val_as_doubleword_variable;
                    std::shared_ptr<dual_variable_component<FieldType>> memory_subaddress;
                    variable<FieldType> memory_subcontents;
                    pb_linear_combination<FieldType> memory_access_is_word;
                    pb_linear_combination<FieldType> memory_access_is_byte;
                    std::shared_ptr<memory_masking_component<FieldType>> check_memory;

                    std::shared_ptr<word_variable_component<FieldType>> next_pc_addr_as_word_variable;
                    std::shared_ptr<consistency_enforcer_component<FieldType>> consistency_enforcer;

                    pb_variable_array<FieldType> instruction_results;
                    pb_variable_array<FieldType> instruction_flags;

                    variable<FieldType> read_not1;

                public:
                    pb_variable_array<FieldType> prev_pc_addr;
                    pb_variable_array<FieldType> prev_pc_val;
                    pb_variable_array<FieldType> prev_state;
                    pb_variable_array<FieldType> ls_addr;
                    pb_variable_array<FieldType> ls_prev_val;
                    pb_variable_array<FieldType> ls_next_val;
                    pb_variable_array<FieldType> next_state;
                    pb_variable_array<FieldType> next_pc_addr;
                    variable<FieldType> next_has_accepted;

                    tinyram_cpu_checker(tinyram_blueprint<FieldType> &pb,
                                        pb_variable_array<FieldType> &prev_pc_addr,
                                        pb_variable_array<FieldType> &prev_pc_val,
                                        pb_variable_array<FieldType> &prev_state,
                                        pb_variable_array<FieldType> &ls_addr,
                                        pb_variable_array<FieldType> &ls_prev_val,
                                        pb_variable_array<FieldType> &ls_next_val,
                                        pb_variable_array<FieldType> &next_state,
                                        pb_variable_array<FieldType> &next_pc_addr,
                                        variable<FieldType> &next_has_accepted);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness() {
                        assert(0);
                    }
                    void generate_r1cs_witness_address();
                    void generate_r1cs_witness_other(tinyram_input_tape_iterator &aux_it,
                                                     const tinyram_input_tape_iterator &aux_end);
                    void dump() const;
                };

                template<typename FieldType>
                tinyram_cpu_checker<FieldType>::tinyram_cpu_checker(tinyram_blueprint<FieldType> &pb,
                                                                    pb_variable_array<FieldType> &prev_pc_addr,
                                                                    pb_variable_array<FieldType> &prev_pc_val,
                                                                    pb_variable_array<FieldType> &prev_state,
                                                                    pb_variable_array<FieldType> &ls_addr,
                                                                    pb_variable_array<FieldType> &ls_prev_val,
                                                                    pb_variable_array<FieldType> &ls_next_val,
                                                                    pb_variable_array<FieldType> &next_state,
                                                                    pb_variable_array<FieldType> &next_pc_addr,
                                                                    variable<FieldType> &next_has_accepted) :
                    tinyram_standard_component<FieldType>(pb),
                    prev_pc_addr(prev_pc_addr), prev_pc_val(prev_pc_val), prev_state(prev_state), ls_addr(ls_addr),
                    ls_prev_val(ls_prev_val), ls_next_val(ls_next_val), next_state(next_state),
                    next_pc_addr(next_pc_addr), next_has_accepted(next_has_accepted) {
                    /* parse previous PC value as an instruction (note that we start
                       parsing from LSB of the instruction doubleword and go to the
                       MSB) */
                    auto pc_val_it = prev_pc_val.begin();

                    arg2idx = pb_variable_array<FieldType>(pc_val_it, pc_val_it + pb.ap.reg_arg_or_imm_width());
                    std::advance(pc_val_it, pb.ap.reg_arg_or_imm_width());
                    std::advance(pc_val_it, pb.ap.instruction_padding_width());
                    arg1idx = pb_variable_array<FieldType>(pc_val_it, pc_val_it + pb.ap.reg_arg_width());
                    std::advance(pc_val_it, pb.ap.reg_arg_width());
                    desidx = pb_variable_array<FieldType>(pc_val_it, pc_val_it + pb.ap.reg_arg_width());
                    std::advance(pc_val_it, pb.ap.reg_arg_width());
                    arg2_is_imm = *pc_val_it;
                    std::advance(pc_val_it, 1);
                    opcode = pb_variable_array<FieldType>(pc_val_it, pc_val_it + pb.ap.opcode_width());
                    std::advance(pc_val_it, pb.ap.opcode_width());

                    assert(pc_val_it == prev_pc_val.end());

                    /* parse state as registers + flags */
                    pb_variable_array<FieldType> packed_prev_registers, packed_next_registers;
                    for (std::size_t i = 0; i < pb.ap.k; ++i) {
                        prev_registers.emplace_back(word_variable_component<FieldType>(
                            pb,
                            pb_variable_array<FieldType>(prev_state.begin() + i * pb.ap.w,
                                                         prev_state.begin() + (i + 1) * pb.ap.w)));
                        next_registers.emplace_back(word_variable_component<FieldType>(
                            pb,
                            pb_variable_array<FieldType>(next_state.begin() + i * pb.ap.w,
                                                         next_state.begin() + (i + 1) * pb.ap.w)));

                        packed_prev_registers.emplace_back(prev_registers[i].packed);
                        packed_next_registers.emplace_back(next_registers[i].packed);
                    }
                    prev_flag = *(++prev_state.rbegin());
                    next_flag = *(++next_state.rbegin());
                    prev_tape1_exhausted = *(prev_state.rbegin());
                    next_tape1_exhausted = *(next_state.rbegin());

                    /* decode arguments */
                    prev_pc_addr_as_word_variable.reset(new word_variable_component<FieldType>(pb, prev_pc_addr));
                    desval.reset(new word_variable_component<FieldType>(pb));
                    arg1val.reset(new word_variable_component<FieldType>(pb));
                    arg2val.reset(new word_variable_component<FieldType>(pb));

                    decode_arguments.reset(new argument_decoder_component<FieldType>(
                        pb, arg2_is_imm, desidx, arg1idx, arg2idx, packed_prev_registers, desval->packed,
                        arg1val->packed, arg2val->packed));

                    /* create indicator variables for opcodes */
                    opcode_indicators.allocate(pb, 1ul << pb.ap.opcode_width());

                    /* perform the ALU operations */
                    instruction_results.allocate(pb, 1ul << pb.ap.opcode_width());
                    instruction_flags.allocate(pb, 1ul << pb.ap.opcode_width());

                    ALU.reset(new ALU_component<FieldType>(pb, opcode_indicators, *prev_pc_addr_as_word_variable, *desval,
                                                        *arg1val, *arg2val, prev_flag, instruction_results,
                                                        instruction_flags));

                    /* check correctness of memory operations */
                    ls_prev_val_as_doubleword_variable.reset(
                        new doubleword_variable_component<FieldType>(pb, ls_prev_val));
                    ls_next_val_as_doubleword_variable.reset(
                        new doubleword_variable_component<FieldType>(pb, ls_next_val));
                    memory_subaddress.reset(new dual_variable_component<FieldType>(
                        pb,
                        pb_variable_array<FieldType>(arg2val->bits.begin(),
                                                     arg2val->bits.begin() + pb.ap.subaddr_len())));

                    memory_subcontents.allocate(pb);
                    memory_access_is_word.assign(
                        pb, 1 - (opcode_indicators[tinyram_opcode_LOADB] + opcode_indicators[tinyram_opcode_STOREB]));
                    memory_access_is_byte.assign(pb, opcode_indicators[tinyram_opcode_LOADB] +
                                                         opcode_indicators[tinyram_opcode_STOREB]);

                    check_memory.reset(new memory_masking_component<FieldType>(pb,
                                                                            *ls_prev_val_as_doubleword_variable,
                                                                            *memory_subaddress,
                                                                            memory_subcontents,
                                                                            memory_access_is_word,
                                                                            memory_access_is_byte,
                                                                            *ls_next_val_as_doubleword_variable));

                    /* handle reads */
                    read_not1.allocate(pb);

                    /* check consistency of the states according to the ALU results */
                    next_pc_addr_as_word_variable.reset(new word_variable_component<FieldType>(pb, next_pc_addr));

                    consistency_enforcer.reset(new consistency_enforcer_component<FieldType>(
                        pb, opcode_indicators, instruction_results, instruction_flags, desidx,
                        prev_pc_addr_as_word_variable->packed, packed_prev_registers, desval->packed, prev_flag,
                        next_pc_addr_as_word_variable->packed, packed_next_registers, next_flag));
                }

                template<typename FieldType>
                void tinyram_cpu_checker<FieldType>::generate_r1cs_constraints() {
                    decode_arguments->generate_r1cs_constraints();

                    /* generate indicator variables for opcode */
                    for (std::size_t i = 0; i < 1ul << this->pb.ap.opcode_width(); ++i) {
                        this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldType>(opcode_indicators[i], pb_packing_sum<FieldType>(opcode) - i, 0));
                    }
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(1, pb_sum<FieldType>(opcode_indicators), 1));

                    /* consistency checks for repacked variables */
                    for (std::size_t i = 0; i < this->pb.ap.k; ++i) {
                        prev_registers[i].generate_r1cs_constraints(true);
                        next_registers[i].generate_r1cs_constraints(true);
                    }
                    prev_pc_addr_as_word_variable->generate_r1cs_constraints(true);
                    next_pc_addr_as_word_variable->generate_r1cs_constraints(true);
                    ls_prev_val_as_doubleword_variable->generate_r1cs_constraints(true);
                    ls_next_val_as_doubleword_variable->generate_r1cs_constraints(true);

                    /* main consistency checks */
                    decode_arguments->generate_r1cs_constraints();
                    ALU->generate_r1cs_constraints();
                    consistency_enforcer->generate_r1cs_constraints();

                    /* check correct access to memory */
                    ls_prev_val_as_doubleword_variable->generate_r1cs_constraints(false);
                    ls_next_val_as_doubleword_variable->generate_r1cs_constraints(false);
                    memory_subaddress->generate_r1cs_constraints(false);
                    check_memory->generate_r1cs_constraints();

                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        1,
                        pb_packing_sum<FieldType>(pb_variable_array<FieldType>(
                            arg2val->bits.begin() + this->pb.ap.subaddr_len(), arg2val->bits.end())),
                        pb_packing_sum<FieldType>(ls_addr)));

                    /* We require that if opcode is one of load.{b,w}, then
                       subcontents is appropriately stored in instruction_results. If
                       opcode is store.b we only take the necessary portion of arg1val
                       (i.e. last byte), and take entire arg1val for store.w.

                       Note that ls_addr is *always* going to be arg2val. If the
                       instruction is a non-memory instruction, we will treat it as a
                       load from that memory location. */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(opcode_indicators[tinyram_opcode_LOADB],
                                                   memory_subcontents - instruction_results[tinyram_opcode_LOADB],
                                                   0));
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(opcode_indicators[tinyram_opcode_LOADW],
                                                   memory_subcontents - instruction_results[tinyram_opcode_LOADW],
                                                   0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        opcode_indicators[tinyram_opcode_STOREB],
                        memory_subcontents - pb_packing_sum<FieldType>(pb_variable_array<FieldType>(
                                                 desval->bits.begin(), desval->bits.begin() + 8)),
                        0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(opcode_indicators[tinyram_opcode_STOREW],
                                                                            memory_subcontents - desval->packed, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        1 - (opcode_indicators[tinyram_opcode_STOREB] + opcode_indicators[tinyram_opcode_STOREW]),
                        ls_prev_val_as_doubleword_variable->packed - ls_next_val_as_doubleword_variable->packed,
                        0));

                    /* specify that accepting state implies opcode = answer && arg2val == 0 */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(next_has_accepted, 1 - opcode_indicators[tinyram_opcode_ANSWER], 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(next_has_accepted, arg2val->packed, 0));

                    /*
                       handle tapes:

                       we require that:
                       prev_tape1_exhausted implies next_tape1_exhausted,
                       prev_tape1_exhausted implies flag to be set
                       reads other than from tape 1 imply flag to be set
                       flag implies result to be 0
                    */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(prev_tape1_exhausted, 1 - next_tape1_exhausted, 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        prev_tape1_exhausted, 1 - instruction_flags[tinyram_opcode_READ], 0));
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(opcode_indicators[tinyram_opcode_READ], 1 - arg2val->packed,
                                                   read_not1)); /* will be nonzero for read X for X != 1 */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(read_not1, 1 - instruction_flags[tinyram_opcode_READ], 0));
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        instruction_flags[tinyram_opcode_READ], instruction_results[tinyram_opcode_READ], 0));
                }

                template<typename FieldType>
                void tinyram_cpu_checker<FieldType>::generate_r1cs_witness_address() {
                    /* decode instruction and arguments */
                    prev_pc_addr_as_word_variable->generate_r1cs_witness_from_bits();
                    for (std::size_t i = 0; i < this->pb.ap.k; ++i) {
                        prev_registers[i].generate_r1cs_witness_from_bits();
                    }

                    decode_arguments->generate_r1cs_witness();

                    desval->generate_r1cs_witness_from_packed();
                    arg1val->generate_r1cs_witness_from_packed();
                    arg2val->generate_r1cs_witness_from_packed();

                    /* clear out ls_addr and fill with everything of arg2val except the subaddress */
                    ls_addr.fill_with_bits_of_field_element(this->pb, this->pb.val(arg2val->packed).as_ulong() >>
                                                                          this->pb.ap.subaddr_len());
                }

                template<typename FieldType>
                void tinyram_cpu_checker<FieldType>::generate_r1cs_witness_other(
                    tinyram_input_tape_iterator &aux_it,
                    const tinyram_input_tape_iterator &aux_end) {
                    /* now ls_prev_val is filled with memory contents at ls_addr. we
                       now ensure consistency with its doubleword representation */
                    ls_prev_val_as_doubleword_variable->generate_r1cs_witness_from_bits();

                    /* fill in the opcode indicators */
                    const std::size_t opcode_val = opcode.get_field_element_from_bits(this->pb).as_ulong();
                    for (std::size_t i = 0; i < 1ul << this->pb.ap.opcode_width(); ++i) {
                        this->pb.val(opcode_indicators[i]) = (i == opcode_val ? FieldType::value_type::zero() : FieldType::value_type::zero());
                    }

                    /* execute the ALU */
                    ALU->generate_r1cs_witness();

                    /* fill memory_subaddress */
                    memory_subaddress->bits.fill_with_bits(
                        this->pb,
                        pb_variable_array<FieldType>(arg2val->bits.begin(),
                                                     arg2val->bits.begin() + +this->pb.ap.subaddr_len())
                            .get_bits(this->pb));
                    memory_subaddress->generate_r1cs_witness_from_bits();

                    /* we distinguish four cases for memory handling:
                       a) load.b
                       b) store.b
                       c) store.w
                       d) load.w or any non-memory instruction */
                    const std::size_t prev_doubleword =
                        this->pb.val(ls_prev_val_as_doubleword_variable->packed).as_ulong();
                    const std::size_t subaddress = this->pb.val(memory_subaddress->packed).as_ulong();

                    if (this->pb.val(opcode_indicators[tinyram_opcode_LOADB]) == FieldType::value_type::zero()) {
                        const std::size_t loaded_byte = (prev_doubleword >> (8u * subaddress)) & 0xFF;
                        this->pb.val(instruction_results[tinyram_opcode_LOADB]) =
                            typename FieldType::value_type(loaded_byte);
                        this->pb.val(memory_subcontents) = typename FieldType::value_type(loaded_byte);
                    } else if (this->pb.val(opcode_indicators[tinyram_opcode_STOREB]) == FieldType::value_type::zero()) {
                        const std::size_t stored_byte = (static_cast<unsigned long>(this->pb.val(desval->packed))
                                                                           ) & 0xFF;
                        this->pb.val(memory_subcontents) = typename FieldType::value_type(stored_byte);
                    } else if (this->pb.val(opcode_indicators[tinyram_opcode_STOREW]) == FieldType::value_type::zero()) {
                        const std::size_t stored_word = (static_cast<unsigned long>(this->pb.val(desval->packed)));
                        this->pb.val(memory_subcontents) = typename FieldType::value_type(stored_word);
                    } else {
                        const bool access_is_word0 =
                            (this->pb.val(*memory_subaddress->bits.rbegin()) == FieldType::value_type::zero());
                        const std::size_t loaded_word =
                            (prev_doubleword >> (access_is_word0 ? 0 : this->pb.ap.w)) & ((1ul << this->pb.ap.w) - 1);
                        this->pb.val(instruction_results[tinyram_opcode_LOADW]) = typename FieldType::value_type(
                            loaded_word); /* does not hurt even for non-memory instructions */
                        this->pb.val(memory_subcontents) = typename FieldType::value_type(loaded_word);
                    }

                    memory_access_is_word.evaluate(this->pb);
                    memory_access_is_byte.evaluate(this->pb);

                    check_memory->generate_r1cs_witness();

                    /* handle reads */
                    if (this->pb.val(prev_tape1_exhausted) == FieldType::value_type::zero()) {
                        /* if tape was exhausted before, it will always be
                           exhausted. we also need to only handle reads from tape 1,
                           so we can safely set flag here */
                        this->pb.val(next_tape1_exhausted) = FieldType::value_type::zero();
                        this->pb.val(instruction_flags[tinyram_opcode_READ]) = FieldType::value_type::zero();
                    }

                    this->pb.val(read_not1) = this->pb.val(opcode_indicators[tinyram_opcode_READ]) *
                                              (FieldType::value_type::zero() - this->pb.val(arg2val->packed));
                    if (this->pb.val(read_not1) != FieldType::value_type::zero()) {
                        /* reading from tape other than 0 raises the flag */
                        this->pb.val(instruction_flags[tinyram_opcode_READ]) = FieldType::value_type::zero();
                    } else {
                        /* otherwise perform the actual read */
                        if (aux_it != aux_end) {
                            this->pb.val(instruction_results[tinyram_opcode_READ]) = typename FieldType::value_type(*aux_it);
                            if (++aux_it == aux_end) {
                                /* tape has ended! */
                                this->pb.val(next_tape1_exhausted) = FieldType::value_type::zero();
                            }
                        } else {
                            /* handled above, so nothing to do here */
                        }
                    }

                    /* flag implies result zero */
                    if (this->pb.val(instruction_flags[tinyram_opcode_READ]) == FieldType::value_type::zero()) {
                        this->pb.val(instruction_results[tinyram_opcode_READ]) = FieldType::value_type::zero();
                    }

                    /* execute consistency enforcer */
                    consistency_enforcer->generate_r1cs_witness();
                    next_pc_addr_as_word_variable->generate_r1cs_witness_from_packed();

                    for (std::size_t i = 0; i < this->pb.ap.k; ++i) {
                        next_registers[i].generate_r1cs_witness_from_packed();
                    }

                    /* finally set has_accepted to 1 if both the opcode is ANSWER and arg2val is 0 */
                    this->pb.val(next_has_accepted) =
                        (this->pb.val(opcode_indicators[tinyram_opcode_ANSWER]) == FieldType::value_type::zero() &&
                         this->pb.val(arg2val->packed) == FieldType::value_type::zero()) ?
                            FieldType::value_type::zero() :
                            FieldType::value_type::zero();
                }

                template<typename FieldType>
                void tinyram_cpu_checker<FieldType>::dump() const {
                    printf("   pc = %lu, flag = %lu\n",
                        static_cast<unsigned long>(this->pb.val(prev_pc_addr_as_word_variable->packed)),
                        static_cast<unsigned long>(this->pb.val(prev_flag)));
                    printf("   ");

                    for (std::size_t j = 0; j < this->pb.ap.k; ++j) {
                        printf("r%zu = %2lu ", j, static_cast<unsigned long>(this->pb.val(prev_registers[j].packed)));
                    }
                    printf("\n");

                    std::size_t opcode_val = static_cast<unsigned long>(opcode.get_field_element_from_bits(this->pb));
                    printf("   %s r%lu, r%lu, %s%lu\n",
                           tinyram_opcode_names[static_cast<tinyram_opcode>(opcode_val)].c_str(),
                           desidx.get_field_element_from_bits(this->pb).as_ulong(),
                           arg1idx.get_field_element_from_bits(this->pb).as_ulong(),
                           (this->pb.val(arg2_is_imm) == FieldType::value_type::zero() ? "" : "r"),
                           arg2idx.get_field_element_from_bits(this->pb).as_ulong());
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TINYRAM_CPU_CHECKER_HPP
