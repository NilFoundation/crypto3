//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the TinyRAM consistency enforcer gadget.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_CONSISTENCY_ENFORCER_GADGET_HPP_
#define CRYPTO3_ZK_CONSISTENCY_ENFORCER_GADGET_HPP_

#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/tinyram_protoboard.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class consistency_enforcer_gadget : public tinyram_standard_gadget<FieldType> {
                private:
                    pb_variable<FieldType> is_register_instruction;
                    pb_variable<FieldType> is_control_flow_instruction;
                    pb_variable<FieldType> is_stall_instruction;

                    pb_variable<FieldType> packed_desidx;
                    std::shared_ptr<packing_gadget<FieldType>> pack_desidx;

                    pb_variable<FieldType> computed_result;
                    pb_variable<FieldType> computed_flag;
                    std::shared_ptr<inner_product_gadget<FieldType>> compute_computed_result;
                    std::shared_ptr<inner_product_gadget<FieldType>> compute_computed_flag;

                    pb_variable<FieldType> pc_from_cf_or_zero;

                    std::shared_ptr<loose_multiplexing_gadget<FieldType>> demux_packed_outgoing_desval;

                public:
                    pb_variable_array<FieldType> opcode_indicators;
                    pb_variable_array<FieldType> instruction_results;
                    pb_variable_array<FieldType> instruction_flags;
                    pb_variable_array<FieldType> desidx;
                    pb_variable<FieldType> packed_incoming_pc;
                    pb_variable_array<FieldType> packed_incoming_registers;
                    pb_variable<FieldType> packed_incoming_desval;
                    pb_variable<FieldType> incoming_flag;
                    pb_variable<FieldType> packed_outgoing_pc;
                    pb_variable_array<FieldType> packed_outgoing_registers;
                    pb_variable<FieldType> outgoing_flag;
                    pb_variable<FieldType> packed_outgoing_desval;

                    consistency_enforcer_gadget(tinyram_protoboard<FieldType> &pb,
                                                const pb_variable_array<FieldType> &opcode_indicators,
                                                const pb_variable_array<FieldType> &instruction_results,
                                                const pb_variable_array<FieldType> &instruction_flags,
                                                const pb_variable_array<FieldType> &desidx,
                                                const pb_variable<FieldType> &packed_incoming_pc,
                                                const pb_variable_array<FieldType> &packed_incoming_registers,
                                                const pb_variable<FieldType> &packed_incoming_desval,
                                                const pb_variable<FieldType> &incoming_flag,
                                                const pb_variable<FieldType> &packed_outgoing_pc,
                                                const pb_variable_array<FieldType> &packed_outgoing_registers,
                                                const pb_variable<FieldType> &outgoing_flag);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                consistency_enforcer_gadget<FieldType>::consistency_enforcer_gadget(
                    tinyram_protoboard<FieldType> &pb,
                    const pb_variable_array<FieldType> &opcode_indicators,
                    const pb_variable_array<FieldType> &instruction_results,
                    const pb_variable_array<FieldType> &instruction_flags,
                    const pb_variable_array<FieldType> &desidx,
                    const pb_variable<FieldType> &packed_incoming_pc,
                    const pb_variable_array<FieldType> &packed_incoming_registers,
                    const pb_variable<FieldType> &packed_incoming_desval,
                    const pb_variable<FieldType> &incoming_flag,
                    const pb_variable<FieldType> &packed_outgoing_pc,
                    const pb_variable_array<FieldType> &packed_outgoing_registers,
                    const pb_variable<FieldType> &outgoing_flag) :
                    tinyram_standard_gadget<FieldType>(pb),
                    opcode_indicators(opcode_indicators), instruction_results(instruction_results),
                    instruction_flags(instruction_flags), desidx(desidx), packed_incoming_pc(packed_incoming_pc),
                    packed_incoming_registers(packed_incoming_registers),
                    packed_incoming_desval(packed_incoming_desval), incoming_flag(incoming_flag),
                    packed_outgoing_pc(packed_outgoing_pc), packed_outgoing_registers(packed_outgoing_registers),
                    outgoing_flag(outgoing_flag) {
                    assert(desidx.size() == pb.ap.reg_arg_width());

                    packed_outgoing_desval.allocate(pb);
                    is_register_instruction.allocate(pb);
                    is_control_flow_instruction.allocate(pb);
                    is_stall_instruction.allocate(pb);

                    packed_desidx.allocate(pb);
                    pack_desidx.reset(new packing_gadget<FieldType>(pb, desidx, packed_desidx));

                    computed_result.allocate(pb);
                    computed_flag.allocate(pb);

                    compute_computed_result.reset(new inner_product_gadget<FieldType>(
                        pb, opcode_indicators, instruction_results, computed_result));
                    compute_computed_flag.reset(
                        new inner_product_gadget<FieldType>(pb, opcode_indicators, instruction_flags, computed_flag));

                    pc_from_cf_or_zero.allocate(pb);

                    demux_packed_outgoing_desval.reset(new loose_multiplexing_gadget<FieldType>(
                        pb, packed_outgoing_registers, packed_desidx, packed_outgoing_desval, pb_variable<FieldType>(0)));
                }

                template<typename FieldType>
                void consistency_enforcer_gadget<FieldType>::generate_r1cs_constraints() {
                    /* pack destination index */
                    pack_desidx->generate_r1cs_constraints(false);

                    /* demux result register */
                    demux_packed_outgoing_desval->generate_r1cs_constraints();

                    /* is_register_instruction */
                    linear_combination<FieldType> reg_a, reg_b, reg_c;
                    reg_a.add_term(pb_variable<FieldType>(0), 1);
                    for (std::size_t i = 0; i < ARRAY_SIZE(tinyram_opcodes_register); ++i) {
                        reg_b.add_term(opcode_indicators[tinyram_opcodes_register[i]], 1);
                    }
                    reg_c.add_term(is_register_instruction, 1);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(reg_a, reg_b, reg_c));

                    /* is_control_flow_instruction */
                    linear_combination<FieldType> cf_a, cf_b, cf_c;
                    cf_a.add_term(pb_variable<FieldType>(0), 1);
                    for (std::size_t i = 0; i < ARRAY_SIZE(tinyram_opcodes_control_flow); ++i) {
                        cf_b.add_term(opcode_indicators[tinyram_opcodes_control_flow[i]], 1);
                    }
                    cf_c.add_term(is_control_flow_instruction, 1);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(cf_a, cf_b, cf_c));

                    /* is_stall_instruction */
                    linear_combination<FieldType> stall_a, stall_b, stall_c;
                    stall_a.add_term(pb_variable<FieldType>(0), 1);
                    for (std::size_t i = 0; i < ARRAY_SIZE(tinyram_opcodes_stall); ++i) {
                        stall_b.add_term(opcode_indicators[tinyram_opcodes_stall[i]], 1);
                    }
                    stall_c.add_term(is_stall_instruction, 1);
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(stall_a, stall_b, stall_c));

                    /* compute actual result/actual flag */
                    compute_computed_result->generate_r1cs_constraints();
                    compute_computed_flag->generate_r1cs_constraints();

                    /*
                      compute new PC address (in double words, not bytes!):

                      PC' = computed_result * is_control_flow_instruction + PC * is_stall_instruction + (PC+1) *
                      (1-is_control_flow_instruction - is_stall_instruction) PC' - pc_from_cf_or_zero -
                      (1-is_control_flow_instruction - is_stall_instruction) = PC * (1 - is_control_flow_instruction)
                    */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(computed_result, is_control_flow_instruction, pc_from_cf_or_zero));

                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>(packed_incoming_pc,
                                                   1 - is_control_flow_instruction,
                                                   packed_outgoing_pc - pc_from_cf_or_zero -
                                                       (1 - is_control_flow_instruction - is_stall_instruction)));

                    /*
                      enforce new flag:

                      flag' = computed_flag * is_register_instruction + flag * (1-is_register_instruction)
                      flag' - flag = (computed_flag - flag) * is_register_instruction
                    */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>({computed_flag, incoming_flag * (-1)},
                                                                            {is_register_instruction},
                                                                            {outgoing_flag, incoming_flag * (-1)}));

                    /*
                      force carryover of unchanged registers

                      (1-indicator) * (new-old) = 0

                      In order to save constraints we "borrow" indicator variables
                      from loose multiplexing gadget.
                    */
                    for (std::size_t i = 0; i < this->pb.ap.k; ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            {pb_variable<FieldType>(0), demux_packed_outgoing_desval->alpha[i] * (-1)},
                            {packed_outgoing_registers[i], packed_incoming_registers[i] * (-1)},
                            {pb_variable<FieldType>(0) * 0}));
                    }

                    /*
                      enforce correct destination register value:

                      next_desval = computed_result * is_register_instruction + packed_incoming_desval *
                      (1-is_register_instruction) next_desval - packed_incoming_desval = (computed_result -
                      packed_incoming_desval) * is_register_instruction
                    */
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({computed_result, packed_incoming_desval * (-1)},
                                                   {is_register_instruction},
                                                   {packed_outgoing_desval, packed_incoming_desval * (-1)}));
                }

                template<typename FieldType>
                void consistency_enforcer_gadget<FieldType>::generate_r1cs_witness() {
                    /* pack destination index */
                    pack_desidx->generate_r1cs_witness_from_bits();

                    /* is_register_instruction */
                    this->pb.val(is_register_instruction) = FieldType::zero();

                    for (std::size_t i = 0; i < ARRAY_SIZE(tinyram_opcodes_register); ++i) {
                        this->pb.val(is_register_instruction) +=
                            this->pb.val(opcode_indicators[tinyram_opcodes_register[i]]);
                    }

                    /* is_control_flow_instruction */
                    this->pb.val(is_control_flow_instruction) = FieldType::zero();

                    for (std::size_t i = 0; i < ARRAY_SIZE(tinyram_opcodes_control_flow); ++i) {
                        this->pb.val(is_control_flow_instruction) +=
                            this->pb.val(opcode_indicators[tinyram_opcodes_control_flow[i]]);
                    }

                    /* is_stall_instruction */
                    this->pb.val(is_stall_instruction) = FieldType::zero();

                    for (std::size_t i = 0; i < ARRAY_SIZE(tinyram_opcodes_stall); ++i) {
                        this->pb.val(is_stall_instruction) += this->pb.val(opcode_indicators[tinyram_opcodes_stall[i]]);
                    }

                    /* compute actual result/actual flag */
                    compute_computed_result->generate_r1cs_witness();
                    compute_computed_flag->generate_r1cs_witness();

                    /*
                      compute new PC address (in double words, not bytes!):

                      PC' = computed_result * is_control_flow_instruction + PC * is_stall_instruction + (PC+1) *
                      (1-is_control_flow_instruction - is_stall_instruction) PC' - pc_from_cf_or_zero -
                      (1-is_control_flow_instruction - is_stall_instruction) = PC * (1 - is_control_flow_instruction)
                    */
                    this->pb.val(pc_from_cf_or_zero) =
                        this->pb.val(computed_result) * this->pb.val(is_control_flow_instruction);
                    this->pb.val(packed_outgoing_pc) =
                        this->pb.val(pc_from_cf_or_zero) +
                        this->pb.val(packed_incoming_pc) * this->pb.val(is_stall_instruction) +
                        (this->pb.val(packed_incoming_pc) + FieldType::one()) *
                            (FieldType::one() - this->pb.val(is_control_flow_instruction) -
                             this->pb.val(is_stall_instruction));

                    /*
                      enforce new flag:

                      flag' = computed_flag * is_register_instruction + flag * (1-is_register_instruction)
                      flag' - flag = (computed_flag - flag) * is_register_instruction
                    */
                    this->pb.val(outgoing_flag) =
                        this->pb.val(computed_flag) * this->pb.val(is_register_instruction) +
                        this->pb.val(incoming_flag) * (FieldType::one() - this->pb.val(is_register_instruction));

                    /*
                      update registers (changed and unchanged)

                      next_desval = computed_result * is_register_instruction + packed_incoming_desval *
                      (1-is_register_instruction)
                    */
                    FieldType changed_register_contents =
                        this->pb.val(computed_result) * this->pb.val(is_register_instruction) +
                        this->pb.val(packed_incoming_desval) *
                            (FieldType::one() - this->pb.val(is_register_instruction));

                    for (std::size_t i = 0; i < this->pb.ap.k; ++i) {
                        this->pb.val(packed_outgoing_registers[i]) = (this->pb.val(packed_desidx).as_ulong() == i) ?
                                                                         changed_register_contents :
                                                                         this->pb.val(packed_incoming_registers[i]);
                    }

                    /* demux result register (it is important to do witness generation
                       here after all registers have been set to the correct
                       values!) */
                    demux_packed_outgoing_desval->generate_r1cs_witness();
                }

#if 0
                template<typename FieldType>
void test_arithmetic_consistency_enforcer_gadget()
{
    algebra::print_time("starting arithmetic_consistency_enforcer test");

    tinyram_architecture_params ap(16, 16);
    tinyram_protoboard<FieldType> pb(ap);

    pb_variable_array<FieldType> opcode_indicators, instruction_results, instruction_flags;
    opcode_indicators.allocate(pb, 1ul<<ap.opcode_width());
    instruction_results.allocate(pb, 1ul<<ap.opcode_width());
    instruction_flags.allocate(pb, 1ul<<ap.opcode_width());

    dual_variable_gadget<FieldType> desidx(pb, ap.reg_arg_width(), "desidx");

    pb_variable<FieldType>  incoming_pc;
    incoming_pc.allocate(pb);

    pb_variable_array<FieldType> packed_incoming_registers;
    packed_incoming_registers.allocate(pb, ap.k);

    pb_variable<FieldType>  incoming_load_flag;
    incoming_load_flag.allocate(pb);

    pb_variable<FieldType>  outgoing_pc, outgoing_flag;
    outgoing_pc.allocate(pb);
    outgoing_flag.allocate(pb);

    pb_variable_array<FieldType> packed_outgoing_registers;
    packed_outgoing_registers.allocate(pb, ap.k);

    arithmetic_consistency_enforcer_gadget g(pb, opcode_indicators, instruction_results, instruction_flags,
                                             desidx.bits, incoming_pc, packed_incoming_registers,
                                             incoming_load_flag, outgoing_pc, packed_outgoing_registers, outgoing_flag, "g");
    g.generate_r1cs_constraints();

    for (std::size_t i = 0; i < 1ul<<ap.opcode_width(); ++i)
    {
        this->pb.val(instruction_results[i]) = typename FieldType::value_type(std::rand());
        this->pb.val(instruction_flags[i]) = typename FieldType::value_type(std::rand() % 2);
    }

    this->pb.val(incoming_pc) = typename FieldType::value_type(12345);
    this->pb.val(incoming_load_flag) = FieldType::zero();

    for (std::size_t i = 0; i < ap.k; ++i)
    {
        this->pb.val(packed_incoming_registers[i]) = typename FieldType::value_type(1000+i);
    }

    for (std::size_t t = 0; t < 1ul<<ap.opcode_width(); ++t)
    {
        this->pb.val(opcode_indicators[t]) = FieldType::zero();
    }

    this->pb.val(opcode_indicators[tinyram_opcode_AND]) = FieldType::one();

    for (std::size_t i = 0; i < ap.k; ++i)
    {
        this->pb.val(desidx.packed) = typename FieldType::value_type(i);
        desidx.generate_r1cs_witness_from_packed();

        g.generate_r1cs_witness();

        assert(this->pb.val(outgoing_pc) == typename FieldType::value_type(12346));

        for (std::size_t j = 0; j < ap.k; ++j)
        {
            assert(this->pb.val(packed_outgoing_registers[j]) ==
                   this->pb.val(i == j ?
                                instruction_results[tinyram_opcode_AND] :
                                packed_incoming_registers[j]));
        }

        assert(this->pb.val(outgoing_flag) == this->pb.val(instruction_flags[tinyram_opcode_AND]));
        assert(pb.is_satisfied());
    }

    printf("arithmetic test successful\n");
    for (std::size_t t = 0; t < 1ul<<ap.opcode_width(); ++t)
    {
        this->pb.val(opcode_indicators[t]) = FieldType::zero();
    }
    this->pb.val(opcode_indicators[tinyram_opcode_LOAD]) = FieldType::one();
    this->pb.val(incoming_load_flag) = FieldType::one();

    g.generate_r1cs_witness();

    this->pb.val(outgoing_pc) == typename FieldType::value_type(12345);
    assert(pb.is_satisfied());

    this->pb.val(incoming_load_flag) = FieldType::zero();
    printf("test that firstload doesn't increment PC successful\n");

    for (std::size_t t = 0; t < 1ul<<ap.opcode_width(); ++t)
    {
        this->pb.val(opcode_indicators[t]) = FieldType::zero();
    }

    this->pb.val(opcode_indicators[tinyram_opcode_JMP]) = FieldType::one();

    for (std::size_t i = 0; i < ap.k; ++i)
    {
        this->pb.val(desidx.packed) = typename FieldType::value_type(i);
        desidx.generate_r1cs_witness_from_packed();

        g.generate_r1cs_witness();

        for (std::size_t j = 0; j < ap.k; ++j)
        {
            assert(this->pb.val(packed_outgoing_registers[j]) == this->pb.val(packed_incoming_registers[j]));
        }

        assert(pb.is_satisfied());
    }

    printf("non-arithmetic test successful\n");

    algebra::print_time("arithmetic_consistency_enforcer tests successful");
}

template<typename FieldType>
void test_control_flow_consistency_enforcer_gadget()
{
    algebra::print_time("starting control_flow_consistency_enforcer test");

    tinyram_architecture_params ap(16, 16);
    tinyram_protoboard<FieldType> pb(ap);

    pb_variable_array<FieldType> opcode_indicators, instruction_results;
    opcode_indicators.allocate(pb, 1ul<<ap.opcode_width());
    instruction_results.allocate(pb, 1ul<<ap.opcode_width());

    pb_variable<FieldType>  incoming_pc, incoming_flag;
    incoming_pc.allocate(pb);
    incoming_flag.allocate(pb);

    pb_variable_array<FieldType> packed_incoming_registers;
    packed_incoming_registers.allocate(pb, ap.k);

    pb_variable<FieldType>  outgoing_pc, outgoing_flag;
    outgoing_pc.allocate(pb);
    outgoing_flag.allocate(pb);

    pb_variable_array<FieldType> packed_outgoing_registers;
    packed_outgoing_registers.allocate(pb, ap.k);

    control_flow_consistency_enforcer_gadget g(pb, opcode_indicators, instruction_results,
                                               incoming_pc, packed_incoming_registers, incoming_flag,
                                               outgoing_pc, packed_outgoing_registers, outgoing_flag, "g");
    g.generate_r1cs_constraints();

    for (std::size_t i = 0; i < 1ul<<ap.opcode_width(); ++i)
    {
        this->pb.val(instruction_results[i]) = typename FieldType::value_type(std::rand());
    }

    this->pb.val(incoming_pc) = typename FieldType::value_type(12345);

    for (std::size_t i = 0; i < ap.k; ++i)
    {
        this->pb.val(packed_incoming_registers[i]) = typename FieldType::value_type(1000+i);
    }

    for (std::size_t t = 0; t < 1ul<<ap.opcode_width(); ++t)
    {
        this->pb.val(opcode_indicators[t]) = FieldType::zero();
    }
    this->pb.val(opcode_indicators[tinyram_opcode_JMP]) = FieldType::one();

    for (int flag = 0; flag <= 1; ++flag)
    {
        this->pb.val(incoming_flag) = typename FieldType::value_type(flag);

        g.generate_r1cs_witness();

        assert(this->pb.val(outgoing_pc) == this->pb.val(instruction_results[tinyram_opcode_JMP]));
        assert(this->pb.val(outgoing_flag) == this->pb.val(incoming_flag));

        for (std::size_t j = 0; j < ap.k; ++j)
        {
            assert(this->pb.val(packed_outgoing_registers[j]) == this->pb.val(packed_incoming_registers[j]));
        }
        assert(pb.is_satisfied());
    }

    algebra::print_time("control_flow_consistency_enforcer tests successful");
}

template<typename FieldType>
void test_special_consistency_enforcer_gadget()
{
    algebra::print_time("starting special_consistency_enforcer_gadget test");

    tinyram_architecture_params ap(16, 16);
    tinyram_protoboard<FieldType> pb(ap);

    pb_variable_array<FieldType> opcode_indicators;
    opcode_indicators.allocate(pb, 1ul<<ap.opcode_width());

    pb_variable<FieldType>  incoming_pc, incoming_flag, incoming_load_flag;
    incoming_pc.allocate(pb);
    incoming_flag.allocate(pb);
    incoming_load_flag.allocate(pb);

    pb_variable_array<FieldType> packed_incoming_registers;
    packed_incoming_registers.allocate(pb, ap.k);

    pb_variable<FieldType>  outgoing_pc, outgoing_flag, outgoing_load_flag;
    outgoing_pc.allocate(pb);
    outgoing_flag.allocate(pb);
    outgoing_load_flag.allocate(pb);

    pb_variable_array<FieldType> packed_outgoing_registers;
    packed_outgoing_registers.allocate(pb, ap.k);

    special_consistency_enforcer_gadget g(pb, opcode_indicators,
                                          incoming_pc, packed_incoming_registers, incoming_flag, incoming_load_flag,
                                          outgoing_pc, packed_outgoing_registers, outgoing_flag, outgoing_load_flag, "g");
    g.generate_r1cs_constraints();

    this->pb.val(incoming_pc) = typename FieldType::value_type(12345);
    for (std::size_t i = 0; i < ap.k; ++i)
    {
        this->pb.val(packed_incoming_registers[i]) = typename FieldType::value_type(1000+i);
    }
    this->pb.val(incoming_flag) = FieldType::zero();
    this->pb.val(incoming_load_flag) = FieldType::zero();

    /* test that accept stalls */
    printf("test that ACCEPT stalls\n");

    for (std::size_t t = 0; t < 1ul<<ap.opcode_width(); ++t)
    {
        this->pb.val(opcode_indicators[t]) = FieldType::zero();
    }
    this->pb.val(opcode_indicators[tinyram_opcode_ACCEPT]) = FieldType::one();

    g.generate_r1cs_witness();

    assert(this->pb.val(outgoing_flag) == this->pb.val(incoming_flag));
    for (std::size_t j = 0; j < ap.k; ++j)
    {
        assert(this->pb.val(packed_outgoing_registers[j]) == this->pb.val(packed_incoming_registers[j]));
    }

    assert(this->pb.val(outgoing_pc) == this->pb.val(incoming_pc));
    assert(pb.is_satisfied());

    printf("test that ACCEPT preserves registers\n");
    this->pb.val(packed_outgoing_registers[0]) = FieldType::zero();
    assert(!pb.is_satisfied());

    /* test that other special instructions (e.g. STORE) don't and also preserve registers */
    printf("test that others (e.g. STORE) don't stall\n");

    for (std::size_t t = 0; t < 1ul<<ap.opcode_width(); ++t)
    {
        this->pb.val(opcode_indicators[t]) = FieldType::zero();
    }
    this->pb.val(opcode_indicators[tinyram_opcode_STORE]) = FieldType::one();

    g.generate_r1cs_witness();

    assert(this->pb.val(outgoing_flag) == this->pb.val(incoming_flag));
    for (std::size_t j = 0; j < ap.k; ++j)
    {
        assert(this->pb.val(packed_outgoing_registers[j]) == this->pb.val(packed_incoming_registers[j]));
    }

    assert(this->pb.val(outgoing_pc) == this->pb.val(incoming_pc) + FieldType::one());
    assert(pb.is_satisfied());

    printf("test that STORE preserves registers\n");
    this->pb.val(packed_outgoing_registers[0]) = FieldType::zero();
    assert(!pb.is_satisfied());

    printf("test that STORE can't have load_flag\n");
    g.generate_r1cs_witness();
    this->pb.val(incoming_load_flag) = FieldType::one();

    assert(!pb.is_satisfied());

    /* test that load can modify outgoing register and sets load_flag */
    printf("test that LOAD sets load_flag\n");

    for (std::size_t t = 0; t < 1ul<<ap.opcode_width(); ++t)
    {
        this->pb.val(opcode_indicators[t]) = FieldType::zero();
    }
    this->pb.val(opcode_indicators[tinyram_opcode_LOAD]) = FieldType::one();
    this->pb.val(incoming_load_flag) = FieldType::zero();

    g.generate_r1cs_witness();

    assert(this->pb.val(outgoing_load_flag) == FieldType::one());
    assert(pb.is_satisfied());

    printf("test that LOAD can modify registers\n");
    this->pb.val(packed_outgoing_registers[0]) = FieldType::zero();
    assert(pb.is_satisfied());

    /* test that postload clears load_flag */
    printf("test that postload clears load_flag\n");

    for (std::size_t t = 0; t < 1ul<<ap.opcode_width(); ++t)
    {
        this->pb.val(opcode_indicators[t]) = FieldType::zero();
    }
    this->pb.val(opcode_indicators[tinyram_opcode_LOAD]) = FieldType::one();
    this->pb.val(incoming_load_flag) = FieldType::one();

    g.generate_r1cs_witness();

    assert(this->pb.val(outgoing_load_flag) == FieldType::zero());
    assert(pb.is_satisfied());

    /* test non-special instructions */
    printf("test non-special instructions\n");

    for (std::size_t t = 0; t < 1ul<<ap.opcode_width(); ++t)
    {
        this->pb.val(opcode_indicators[t]) = FieldType::zero();
    }
    this->pb.val(opcode_indicators[tinyram_opcode_JMP]) = FieldType::one();
    this->pb.val(incoming_load_flag) = FieldType::zero();
    g.generate_r1cs_witness();

    assert(pb.is_satisfied());

    printf("test that non-special can't have load_flag\n");
    g.generate_r1cs_witness();
    this->pb.val(incoming_load_flag) = FieldType::one();

    assert(!pb.is_satisfied());

    algebra::print_time("special_consistency_enforcer_gadget tests successful");
}
#endif

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CONSISTENCY_ENFORCER_GADGET_HPP_
