//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the TinyRAM ALU gadget.
//
// The gadget checks the correct execution of a given TinyRAM instruction.
//---------------------------------------------------------------------------//

#ifndef ALU_GADGET_HPP_
#define ALU_GADGET_HPP_

#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/alu_arithmetic.hpp>
#include <nil/crypto3/zk/snark/gadgets/cpu_checkers/tinyram/components/alu_control_flow.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class ALU_gadget : public tinyram_standard_gadget<FieldType> {
                private:
                    std::vector<std::shared_ptr<tinyram_standard_gadget<FieldType>>> components;

                public:
                    pb_variable_array<FieldType> opcode_indicators;
                    word_variable_gadget<FieldType> pc;
                    word_variable_gadget<FieldType> desval;
                    word_variable_gadget<FieldType> arg1val;
                    word_variable_gadget<FieldType> arg2val;
                    pb_variable<FieldType> flag;
                    pb_variable_array<FieldType> instruction_results;
                    pb_variable_array<FieldType> instruction_flags;

                    ALU_gadget<FieldType>(tinyram_protoboard<FieldType> &pb,
                                          const pb_variable_array<FieldType> &opcode_indicators,
                                          const word_variable_gadget<FieldType> &pc,
                                          const word_variable_gadget<FieldType> &desval,
                                          const word_variable_gadget<FieldType> &arg1val,
                                          const word_variable_gadget<FieldType> &arg2val,
                                          const pb_variable<FieldType> &flag,
                                          const pb_variable_array<FieldType> &instruction_results,
                                          const pb_variable_array<FieldType> &instruction_flags) :
                        tinyram_standard_gadget<FieldType>(pb),
                        opcode_indicators(opcode_indicators), pc(pc), desval(desval), arg1val(arg1val),
                        arg2val(arg2val), flag(flag), instruction_results(instruction_results),
                        instruction_flags(instruction_flags) {
                        components.resize(1ul << pb.ap.opcode_width());

                        /* arithmetic */
                        components[tinyram_opcode_AND].reset(new ALU_and_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_AND], instruction_flags[tinyram_opcode_AND]));

                        components[tinyram_opcode_OR].reset(new ALU_or_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_OR], instruction_flags[tinyram_opcode_OR]));

                        components[tinyram_opcode_XOR].reset(new ALU_xor_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_XOR], instruction_flags[tinyram_opcode_XOR]));

                        components[tinyram_opcode_NOT].reset(new ALU_not_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_NOT], instruction_flags[tinyram_opcode_NOT]));

                        components[tinyram_opcode_ADD].reset(new ALU_add_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_ADD], instruction_flags[tinyram_opcode_ADD]));

                        components[tinyram_opcode_SUB].reset(new ALU_sub_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_SUB], instruction_flags[tinyram_opcode_SUB]));

                        components[tinyram_opcode_MOV].reset(new ALU_mov_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_MOV], instruction_flags[tinyram_opcode_MOV]));

                        components[tinyram_opcode_CMOV].reset(new ALU_cmov_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_CMOV], instruction_flags[tinyram_opcode_CMOV]));

                        components[tinyram_opcode_CMPA].reset(new ALU_cmp_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_CMPE], instruction_flags[tinyram_opcode_CMPE],
                            instruction_results[tinyram_opcode_CMPA], instruction_flags[tinyram_opcode_CMPA],
                            instruction_results[tinyram_opcode_CMPAE], instruction_flags[tinyram_opcode_CMPAE]));

                        components[tinyram_opcode_CMPG].reset(new ALU_cmps_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_CMPG], instruction_flags[tinyram_opcode_CMPG],
                            instruction_results[tinyram_opcode_CMPGE], instruction_flags[tinyram_opcode_CMPGE]));

                        components[tinyram_opcode_UMULH].reset(new ALU_umul_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_MULL], instruction_flags[tinyram_opcode_MULL],
                            instruction_results[tinyram_opcode_UMULH], instruction_flags[tinyram_opcode_UMULH]));

                        components[tinyram_opcode_SMULH].reset(new ALU_smul_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_SMULH], instruction_flags[tinyram_opcode_SMULH]));

                        components[tinyram_opcode_UDIV].reset(new ALU_divmod_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_UDIV], instruction_flags[tinyram_opcode_UDIV],
                            instruction_results[tinyram_opcode_UMOD], instruction_flags[tinyram_opcode_UMOD]));

                        components[tinyram_opcode_SHR].reset(new ALU_shr_shl_gadget<FieldType>(
                            pb, opcode_indicators, desval, arg1val, arg2val, flag,
                            instruction_results[tinyram_opcode_SHR], instruction_flags[tinyram_opcode_SHR],
                            instruction_results[tinyram_opcode_SHL], instruction_flags[tinyram_opcode_SHL]));

                        /* control flow */
                        components[tinyram_opcode_JMP].reset(new ALU_jmp_gadget<FieldType>(
                            pb, pc, arg2val, flag, instruction_results[tinyram_opcode_JMP]));

                        components[tinyram_opcode_CJMP].reset(new ALU_cjmp_gadget<FieldType>(
                            pb, pc, arg2val, flag, instruction_results[tinyram_opcode_CJMP]));

                        components[tinyram_opcode_CNJMP].reset(new ALU_cnjmp_gadget<FieldType>(
                            pb, pc, arg2val, flag, instruction_results[tinyram_opcode_CNJMP]));
                    }

                    void generate_r1cs_constraints() {
                        for (size_t i = 0; i < 1ul << this->pb.ap.opcode_width(); ++i) {
                            if (components[i]) {
                                components[i]->generate_r1cs_constraints();
                            }
                        }
                    }

                    void generate_r1cs_witness() {
                        for (size_t i = 0; i < 1ul << this->pb.ap.opcode_width(); ++i) {
                            if (components[i]) {
                                components[i]->generate_r1cs_witness();
                            }
                        }
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // ALU_GADGET_HPP_
