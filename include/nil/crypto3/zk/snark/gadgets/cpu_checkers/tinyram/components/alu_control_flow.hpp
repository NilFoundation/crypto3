//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the TinyRAM ALU control-flow gadgets.
//
// This gadget check the correct execution of control-flow TinyRAM instructions.
//---------------------------------------------------------------------------//

#ifndef ALU_CONTROL_FLOW_HPP_
#define ALU_CONTROL_FLOW_HPP_

#include <nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/tinyram_protoboard.hpp>
#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/word_variable_gadget.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /* control flow gadgets */
                template<typename FieldType>
                class ALU_control_flow_gadget : public tinyram_standard_gadget<FieldType> {
                public:
                    const word_variable_gadget<FieldType> pc;
                    const word_variable_gadget<FieldType> argval2;
                    const pb_variable<FieldType> flag;
                    const pb_variable<FieldType> result;

                    ALU_control_flow_gadget(tinyram_protoboard<FieldType> &pb,
                                            const word_variable_gadget<FieldType> &pc,
                                            const word_variable_gadget<FieldType> &argval2,
                                            const pb_variable<FieldType> &flag,
                                            const pb_variable<FieldType> &result) :
                        tinyram_standard_gadget<FieldType>(pb),
                        pc(pc), argval2(argval2), flag(flag), result(result) {};
                };

                template<typename FieldType>
                class ALU_jmp_gadget : public ALU_control_flow_gadget<FieldType> {
                public:
                    ALU_jmp_gadget(tinyram_protoboard<FieldType> &pb,
                                   const word_variable_gadget<FieldType> &pc,
                                   const word_variable_gadget<FieldType> &argval2,
                                   const pb_variable<FieldType> &flag,
                                   const pb_variable<FieldType> &result) :
                        ALU_control_flow_gadget<FieldType>(pb, pc, argval2, flag, result) {
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_jmp_gadget();

                template<typename FieldType>
                class ALU_cjmp_gadget : public ALU_control_flow_gadget<FieldType> {
                public:
                    ALU_cjmp_gadget(tinyram_protoboard<FieldType> &pb,
                                    const word_variable_gadget<FieldType> &pc,
                                    const word_variable_gadget<FieldType> &argval2,
                                    const pb_variable<FieldType> &flag,
                                    const pb_variable<FieldType> &result) :
                        ALU_control_flow_gadget<FieldType>(pb, pc, argval2, flag, result) {
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_cjmp_gadget();

                template<typename FieldType>
                class ALU_cnjmp_gadget : public ALU_control_flow_gadget<FieldType> {
                public:
                    ALU_cnjmp_gadget(tinyram_protoboard<FieldType> &pb,
                                     const word_variable_gadget<FieldType> &pc,
                                     const word_variable_gadget<FieldType> &argval2,
                                     const pb_variable<FieldType> &flag,
                                     const pb_variable<FieldType> &result) :
                        ALU_control_flow_gadget<FieldType>(pb, pc, argval2, flag, result) {
                    }

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                void test_ALU_cnjmp_gadget();

                /* jmp */
                template<typename FieldType>
                void ALU_jmp_gadget<FieldType>::generate_r1cs_constraints() {
                    this->pb.add_r1cs_constraint(
                        r1cs_constraint<FieldType>({pb_variable<FieldType>(0)}, {this->argval2.packed}, {this->result}));
                }

                template<typename FieldType>
                void ALU_jmp_gadget<FieldType>::generate_r1cs_witness() {
                    this->pb.val(this->result) = this->pb.val(this->argval2.packed);
                }

                template<typename FieldType>
                void test_ALU_jmp_gadget() {
                    algebra::print_time("starting jmp test");

                    tinyram_architecture_params ap(16, 16);
                    tinyram_program P;
                    P.instructions = generate_tinyram_prelude(ap);
                    tinyram_protoboard<FieldType> pb(ap, P.size(), 0, 10);

                    word_variable_gadget<FieldType> pc(pb, "pc"), argval2(pb, "argval2");
                    pb_variable<FieldType> flag, result;

                    pc.generate_r1cs_constraints(true);
                    argval2.generate_r1cs_constraints(true);
                    flag.allocate(pb);
                    result.allocate(pb);

                    ALU_jmp_gadget<FieldType> jmp(pb, pc, argval2, flag, result, "jmp");
                    jmp.generate_r1cs_constraints();

                    pb.val(argval2.packed) = FieldType(123);
                    argval2.generate_r1cs_witness_from_packed();

                    jmp.generate_r1cs_witness();

                    assert(pb.val(result) == FieldType(123));
                    assert(pb.is_satisfied());
                    algebra::print_time("positive jmp test successful");

                    pb.val(result) = FieldType(1);
                    assert(!pb.is_satisfied());
                    algebra::print_time("negative jmp test successful");
                }

                /* cjmp */
                template<typename FieldType>
                void ALU_cjmp_gadget<FieldType>::generate_r1cs_constraints() {
                    /*
                      flag1 * argval2 + (1-flag1) * (pc1 + 1) = cjmp_result
                      flag1 * (argval2 - pc1 - 1) = cjmp_result - pc1 - 1

                      Note that instruction fetch semantics require program counter to
                      be aligned to the double word by rounding down, and pc_addr in
                      the outer reduction is expressed as a double word address. To
                      achieve this we just discard the first ap.subaddr_len() bits of
                      the byte address of the PC.
                    */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        this->flag,
                        pb_packing_sum<FieldType>(pb_variable_array<FieldType>(
                            this->argval2.bits.begin() + this->pb.ap.subaddr_len(), this->argval2.bits.end())) -
                            this->pc.packed - 1,
                        this->result - this->pc.packed - 1));
                }

                template<typename FieldType>
                void ALU_cjmp_gadget<FieldType>::generate_r1cs_witness() {
                    this->pb.val(this->result) =
                        ((this->pb.val(this->flag) == FieldType::one()) ?
                             FieldType(this->pb.val(this->argval2.packed).as_ulong() >> this->pb.ap.subaddr_len()) :
                             this->pb.val(this->pc.packed) + FieldType::one());
                }

                template<typename FieldType>
                void test_ALU_cjmp_gadget() {
                    // TODO: update
                    algebra::print_time("starting cjmp test");

                    tinyram_architecture_params ap(16, 16);
                    tinyram_program P;
                    P.instructions = generate_tinyram_prelude(ap);
                    tinyram_protoboard<FieldType> pb(ap, P.size(), 0, 10);

                    word_variable_gadget<FieldType> pc(pb, "pc"), argval2(pb, "argval2");
                    pb_variable<FieldType> flag, result;

                    pc.generate_r1cs_constraints(true);
                    argval2.generate_r1cs_constraints(true);
                    flag.allocate(pb);
                    result.allocate(pb);

                    ALU_cjmp_gadget<FieldType> cjmp(pb, pc, argval2, flag, result, "cjmp");
                    cjmp.generate_r1cs_constraints();

                    pb.val(argval2.packed) = FieldType(123);
                    argval2.generate_r1cs_witness_from_packed();
                    pb.val(pc.packed) = FieldType(456);
                    pc.generate_r1cs_witness_from_packed();

                    pb.val(flag) = FieldType(1);
                    cjmp.generate_r1cs_witness();

                    assert(pb.val(result) == FieldType(123));
                    assert(pb.is_satisfied());
                    algebra::print_time("positive cjmp test successful");

                    pb.val(flag) = FieldType(0);
                    assert(!pb.is_satisfied());
                    algebra::print_time("negative cjmp test successful");

                    pb.val(flag) = FieldType(0);
                    cjmp.generate_r1cs_witness();

                    assert(pb.val(result) == FieldType(456 + 2 * ap.w / 8));
                    assert(pb.is_satisfied());
                    algebra::print_time("positive cjmp test successful");

                    pb.val(flag) = FieldType(1);
                    assert(!pb.is_satisfied());
                    algebra::print_time("negative cjmp test successful");
                }

                /* cnjmp */
                template<typename FieldType>
                void ALU_cnjmp_gadget<FieldType>::generate_r1cs_constraints() {
                    /*
                      flag1 * (pc1 + inc) + (1-flag1) * argval2 = cnjmp_result
                      flag1 * (pc1 + inc - argval2) = cnjmp_result - argval2

                      Note that instruction fetch semantics require program counter to
                      be aligned to the double word by rounding down, and pc_addr in
                      the outer reduction is expressed as a double word address. To
                      achieve this we just discard the first ap.subaddr_len() bits of
                      the byte address of the PC.
                    */
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                        this->flag,
                        this->pc.packed + 1 -
                            pb_packing_sum<FieldType>(pb_variable_array<FieldType>(
                                this->argval2.bits.begin() + this->pb.ap.subaddr_len(), this->argval2.bits.end())),
                        this->result -
                            pb_packing_sum<FieldType>(pb_variable_array<FieldType>(
                                this->argval2.bits.begin() + this->pb.ap.subaddr_len(), this->argval2.bits.end()))));
                }

                template<typename FieldType>
                void ALU_cnjmp_gadget<FieldType>::generate_r1cs_witness() {
                    this->pb.val(this->result) =
                        ((this->pb.val(this->flag) == FieldType::one()) ?
                             this->pb.val(this->pc.packed) + FieldType::one() :
                             FieldType(this->pb.val(this->argval2.packed).as_ulong() >> this->pb.ap.subaddr_len()));
                }

                template<typename FieldType>
                void test_ALU_cnjmp_gadget() {
                    // TODO: update
                    algebra::print_time("starting cnjmp test");

                    tinyram_architecture_params ap(16, 16);
                    tinyram_program P;
                    P.instructions = generate_tinyram_prelude(ap);
                    tinyram_protoboard<FieldType> pb(ap, P.size(), 0, 10);

                    word_variable_gadget<FieldType> pc(pb, "pc"), argval2(pb, "argval2");
                    pb_variable<FieldType> flag, result;

                    pc.generate_r1cs_constraints(true);
                    argval2.generate_r1cs_constraints(true);
                    flag.allocate(pb);
                    result.allocate(pb);

                    ALU_cnjmp_gadget<FieldType> cnjmp(pb, pc, argval2, flag, result, "cjmp");
                    cnjmp.generate_r1cs_constraints();

                    pb.val(argval2.packed) = FieldType(123);
                    argval2.generate_r1cs_witness_from_packed();
                    pb.val(pc.packed) = FieldType(456);
                    pc.generate_r1cs_witness_from_packed();

                    pb.val(flag) = FieldType(0);
                    cnjmp.generate_r1cs_witness();

                    assert(pb.val(result) == FieldType(123));
                    assert(pb.is_satisfied());
                    algebra::print_time("positive cnjmp test successful");

                    pb.val(flag) = FieldType(1);
                    assert(!pb.is_satisfied());
                    algebra::print_time("negative cnjmp test successful");

                    pb.val(flag) = FieldType(1);
                    cnjmp.generate_r1cs_witness();

                    assert(pb.val(result) == FieldType(456 + (2 * pb.ap.w / 8)));
                    assert(pb.is_satisfied());
                    algebra::print_time("positive cnjmp test successful");

                    pb.val(flag) = FieldType(0);
                    assert(!pb.is_satisfied());
                    algebra::print_time("negative cnjmp test successful");
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // ALU_CONTROL_FLOW_HPP_
