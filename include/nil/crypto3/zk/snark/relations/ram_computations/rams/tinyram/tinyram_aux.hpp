//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of auxiliary functions for TinyRAM.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TINYRAM_AUX_HPP_
#define CRYPTO3_ZK_TINYRAM_AUX_HPP_

#include <cassert>
#include <iostream>
#include <map>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp>
#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                enum tinyram_opcode {
                    tinyram_opcode_AND = 0b00000,
                    tinyram_opcode_OR = 0b00001,
                    tinyram_opcode_XOR = 0b00010,
                    tinyram_opcode_NOT = 0b00011,
                    tinyram_opcode_ADD = 0b00100,
                    tinyram_opcode_SUB = 0b00101,
                    tinyram_opcode_MULL = 0b00110,
                    tinyram_opcode_UMULH = 0b00111,
                    tinyram_opcode_SMULH = 0b01000,
                    tinyram_opcode_UDIV = 0b01001,
                    tinyram_opcode_UMOD = 0b01010,
                    tinyram_opcode_SHL = 0b01011,
                    tinyram_opcode_SHR = 0b01100,

                    tinyram_opcode_CMPE = 0b01101,
                    tinyram_opcode_CMPA = 0b01110,
                    tinyram_opcode_CMPAE = 0b01111,
                    tinyram_opcode_CMPG = 0b10000,
                    tinyram_opcode_CMPGE = 0b10001,

                    tinyram_opcode_MOV = 0b10010,
                    tinyram_opcode_CMOV = 0b10011,

                    tinyram_opcode_JMP = 0b10100,
                    tinyram_opcode_CJMP = 0b10101,
                    tinyram_opcode_CNJMP = 0b10110,

                    tinyram_opcode_10111 = 0b10111,
                    tinyram_opcode_11000 = 0b11000,
                    tinyram_opcode_11001 = 0b11001,

                    tinyram_opcode_STOREB = 0b11010,
                    tinyram_opcode_LOADB = 0b11011,
                    tinyram_opcode_STOREW = 0b11100,
                    tinyram_opcode_LOADW = 0b11101,
                    tinyram_opcode_READ = 0b11110,
                    tinyram_opcode_ANSWER = 0b11111
                };

                enum tinyram_opcode_args {
                    tinyram_opcode_args_des_arg1_arg2 = 1,
                    tinyram_opcode_args_des_arg2 = 2,
                    tinyram_opcode_args_arg1_arg2 = 3,
                    tinyram_opcode_args_arg2 = 4,
                    tinyram_opcode_args_none = 5,
                    tinyram_opcode_args_arg2_des = 6
                };

                /**
                 * Instructions that may change a register or the flag.
                 * All other instructions leave all registers and the flag intact.
                 */
                const static int tinyram_opcodes_register[] = {
                    tinyram_opcode_AND,   tinyram_opcode_OR,    tinyram_opcode_XOR,   tinyram_opcode_NOT,
                    tinyram_opcode_ADD,   tinyram_opcode_SUB,   tinyram_opcode_MULL,  tinyram_opcode_UMULH,
                    tinyram_opcode_SMULH, tinyram_opcode_UDIV,  tinyram_opcode_UMOD,  tinyram_opcode_SHL,
                    tinyram_opcode_SHR,

                    tinyram_opcode_CMPE,  tinyram_opcode_CMPA,  tinyram_opcode_CMPAE, tinyram_opcode_CMPG,
                    tinyram_opcode_CMPGE,

                    tinyram_opcode_MOV,   tinyram_opcode_CMOV,

                    tinyram_opcode_LOADB, tinyram_opcode_LOADW, tinyram_opcode_READ};

                /**
                 * Instructions that modify the program counter.
                 * All other instructions either advance it (+1) or stall (see below).
                 */
                const static int tinyram_opcodes_control_flow[] = {tinyram_opcode_JMP, tinyram_opcode_CJMP,
                                                                   tinyram_opcode_CNJMP};

                /**
                 * Instructions that make the program counter stall;
                 * these are "answer" plus all the undefined opcodes.
                 */
                const static int tinyram_opcodes_stall[] = {tinyram_opcode_10111, tinyram_opcode_11000,
                                                            tinyram_opcode_11001,

                                                            tinyram_opcode_ANSWER};

                typedef std::size_t reg_count_t;    // type for the number of registers
                typedef std::size_t reg_width_t;    // type for the width of a register

                extern std::map<tinyram_opcode, std::string> tinyram_opcode_names;

                extern std::map<std::string, tinyram_opcode> opcode_values;

                extern std::map<tinyram_opcode, tinyram_opcode_args> opcode_args;

                void ensure_tinyram_opcode_value_map();

                class tinyram_program;
                typedef std::vector<std::size_t> tinyram_input_tape;
                typedef typename tinyram_input_tape::const_iterator tinyram_input_tape_iterator;

                class tinyram_architecture_params {
                public:
                    reg_width_t w; /* width of a register */
                    reg_count_t k; /* number of registers */

                    tinyram_architecture_params() {};
                    tinyram_architecture_params(const reg_width_t w, const reg_count_t k) : w(w), k(k) {
                        assert(w == 1ul << static_cast<std::size_t>(std::ceil(std::log2(w))));
                    };

                    std::size_t address_size() const;
                    std::size_t value_size() const;
                    std::size_t cpu_state_size() const;
                    std::size_t initial_pc_addr() const;

                    std::vector<bool> initial_cpu_state() const;
                    memory_contents initial_memory_contents(const tinyram_program &program,
                                                            const tinyram_input_tape &primary_input) const;

                    std::size_t opcode_width() const;
                    std::size_t reg_arg_width() const;
                    std::size_t instruction_padding_width() const;
                    std::size_t reg_arg_or_imm_width() const;

                    std::size_t dwaddr_len() const;
                    std::size_t subaddr_len() const;

                    std::size_t bytes_in_word() const;

                    std::size_t instr_size() const;

                    bool operator==(const tinyram_architecture_params &other) const;
                };

                /* order everywhere is reversed (i.e. MSB comes first),
                   corresponding to the order in memory */

                class tinyram_instruction {
                public:
                    tinyram_opcode opcode;
                    bool arg2_is_imm;
                    std::size_t desidx;
                    std::size_t arg1idx;
                    std::size_t arg2idx_or_imm;

                    tinyram_instruction(const tinyram_opcode &opcode,
                                        const bool arg2_is_imm,
                                        const std::size_t &desidx,
                                        const std::size_t &arg1idx,
                                        const std::size_t &arg2idx_or_imm);

                    std::size_t as_dword(const tinyram_architecture_params &ap) const;
                };

                tinyram_instruction random_tinyram_instruction(const tinyram_architecture_params &ap);

                std::vector<tinyram_instruction> generate_tinyram_prelude(const tinyram_architecture_params &ap);
                extern tinyram_instruction tinyram_default_instruction;

                class tinyram_program {
                public:
                    std::vector<tinyram_instruction> instructions;
                    std::size_t size() const {
                        return instructions.size();
                    }
                    void add_instruction(const tinyram_instruction &instr);
                };

                tinyram_program load_preprocessed_program(const tinyram_architecture_params &ap,
                                                          std::istream &preprocessed);

                memory_store_trace tinyram_boot_trace_from_program_and_input(const tinyram_architecture_params &ap,
                                                                             const std::size_t boot_trace_size_bound,
                                                                             const tinyram_program &program,
                                                                             const tinyram_input_tape &primary_input);

                tinyram_input_tape load_tape(std::istream &tape);

                tinyram_instruction tinyram_default_instruction =
                    tinyram_instruction(tinyram_opcode_ANSWER, true, 0, 0, 1);

                std::map<tinyram_opcode, std::string> tinyram_opcode_names = {{tinyram_opcode_AND, "and"},
                                                                              {tinyram_opcode_OR, "or"},
                                                                              {tinyram_opcode_XOR, "xor"},
                                                                              {tinyram_opcode_NOT, "not"},
                                                                              {tinyram_opcode_ADD, "add"},
                                                                              {tinyram_opcode_SUB, "sub"},
                                                                              {tinyram_opcode_MULL, "mull"},
                                                                              {tinyram_opcode_UMULH, "umulh"},
                                                                              {tinyram_opcode_SMULH, "smulh"},
                                                                              {tinyram_opcode_UDIV, "udiv"},
                                                                              {tinyram_opcode_UMOD, "umod"},
                                                                              {tinyram_opcode_SHL, "shl"},
                                                                              {tinyram_opcode_SHR, "shr"},

                                                                              {tinyram_opcode_CMPE, "cmpe"},
                                                                              {tinyram_opcode_CMPA, "cmpa"},
                                                                              {tinyram_opcode_CMPAE, "cmpae"},
                                                                              {tinyram_opcode_CMPG, "cmpg"},
                                                                              {tinyram_opcode_CMPGE, "cmpge"},

                                                                              {tinyram_opcode_MOV, "mov"},
                                                                              {tinyram_opcode_CMOV, "cmov"},
                                                                              {tinyram_opcode_JMP, "jmp"},

                                                                              {tinyram_opcode_CJMP, "cjmp"},
                                                                              {tinyram_opcode_CNJMP, "cnjmp"},

                                                                              {tinyram_opcode_10111, "opcode_10111"},
                                                                              {tinyram_opcode_11000, "opcode_11000"},
                                                                              {tinyram_opcode_11001, "opcode_11001"},
                                                                              {tinyram_opcode_STOREB, "store.b"},
                                                                              {tinyram_opcode_LOADB, "load.b"},

                                                                              {tinyram_opcode_STOREW, "store.w"},
                                                                              {tinyram_opcode_LOADW, "load.w"},
                                                                              {tinyram_opcode_READ, "read"},
                                                                              {tinyram_opcode_ANSWER, "answer"}};

                std::map<tinyram_opcode, tinyram_opcode_args> opcode_args = {
                    {tinyram_opcode_AND, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_OR, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_XOR, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_NOT, tinyram_opcode_args_des_arg2},
                    {tinyram_opcode_ADD, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_SUB, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_MULL, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_UMULH, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_SMULH, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_UDIV, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_UMOD, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_SHL, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_SHR, tinyram_opcode_args_des_arg1_arg2},
                    {tinyram_opcode_CMPE, tinyram_opcode_args_arg1_arg2},
                    {tinyram_opcode_CMPA, tinyram_opcode_args_arg1_arg2},
                    {tinyram_opcode_CMPAE, tinyram_opcode_args_arg1_arg2},
                    {tinyram_opcode_CMPG, tinyram_opcode_args_arg1_arg2},
                    {tinyram_opcode_CMPGE, tinyram_opcode_args_arg1_arg2},
                    {tinyram_opcode_MOV, tinyram_opcode_args_des_arg2},
                    {tinyram_opcode_CMOV, tinyram_opcode_args_des_arg2},
                    {tinyram_opcode_JMP, tinyram_opcode_args_arg2},
                    {tinyram_opcode_CJMP, tinyram_opcode_args_arg2},
                    {tinyram_opcode_CNJMP, tinyram_opcode_args_arg2},
                    {tinyram_opcode_10111, tinyram_opcode_args_none},
                    {tinyram_opcode_11000, tinyram_opcode_args_none},
                    {tinyram_opcode_11001, tinyram_opcode_args_none},
                    {tinyram_opcode_STOREB, tinyram_opcode_args_arg2_des},
                    {tinyram_opcode_LOADB, tinyram_opcode_args_des_arg2},
                    {tinyram_opcode_STOREW, tinyram_opcode_args_arg2_des},
                    {tinyram_opcode_LOADW, tinyram_opcode_args_des_arg2},
                    {tinyram_opcode_READ, tinyram_opcode_args_des_arg2},
                    {tinyram_opcode_ANSWER, tinyram_opcode_args_arg2}};

                std::map<std::string, tinyram_opcode> opcode_values;

                void ensure_tinyram_opcode_value_map() {
                    if (opcode_values.empty()) {
                        for (auto it : tinyram_opcode_names) {
                            opcode_values[it.second] = it.first;
                        }
                    }
                }

                std::vector<tinyram_instruction> generate_tinyram_prelude(const tinyram_architecture_params &ap) {
                    std::vector<tinyram_instruction> result;
                    const std::size_t increment = algebra::log2(ap.w) / 8;
                    const std::size_t mem_start = 1ul << (ap.w - 1);
                    result.emplace_back(
                        tinyram_instruction(tinyram_opcode_STOREW, true, 0, 0, 0));    // 0: store.w 0, r0
                    result.emplace_back(
                        tinyram_instruction(tinyram_opcode_MOV, true, 0, 0, mem_start));    // 1: mov r0, 2^{W-1}
                    result.emplace_back(tinyram_instruction(tinyram_opcode_READ, true, 1, 0, 0));    // 2: read r1, 0
                    result.emplace_back(tinyram_instruction(tinyram_opcode_CJMP, true, 0, 0, 7));    // 3: cjmp 7
                    result.emplace_back(
                        tinyram_instruction(tinyram_opcode_ADD, true, 0, 0, increment));    // 4: add r0, r0, INCREMENT
                    result.emplace_back(
                        tinyram_instruction(tinyram_opcode_STOREW, false, 1, 0, 0));                // 5: store.w r0, r1
                    result.emplace_back(tinyram_instruction(tinyram_opcode_JMP, true, 0, 0, 2));    // 6: jmp 2
                    result.emplace_back(
                        tinyram_instruction(tinyram_opcode_STOREW, true, 0, 0, mem_start));    // 7: store.w 2^{W-1}, r0
                    return result;
                }

                std::size_t tinyram_architecture_params::address_size() const {
                    return dwaddr_len();
                }

                std::size_t tinyram_architecture_params::value_size() const {
                    return 2 * w;
                }

                std::size_t tinyram_architecture_params::cpu_state_size() const {
                    return k * w + 2; /* + flag + tape1_exhausted */
                }

                std::size_t tinyram_architecture_params::initial_pc_addr() const {
                    /* the initial PC address is memory units for the RAM reduction */
                    const std::size_t initial_pc_addr = generate_tinyram_prelude(*this).size();
                    return initial_pc_addr;
                }

                std::vector<bool> tinyram_architecture_params::initial_cpu_state() const {
                    std::vector<bool> result(this->cpu_state_size(), false);
                    return result;
                }

                memory_contents tinyram_architecture_params::initial_memory_contents(
                    const tinyram_program &program,
                    const tinyram_input_tape &primary_input) const {
                    // remember that memory consists of 1ul<<dwaddr_len() double words (!)
                    memory_contents m;

                    for (std::size_t i = 0; i < program.instructions.size(); ++i) {
                        m[i] = program.instructions[i].as_dword(*this);
                    }

                    const std::size_t input_addr = 1ul << (dwaddr_len() - 1);
                    std::size_t latest_double_word =
                        (1ull << (w - 1)) +
                        primary_input.size();    // the first word will contain 2^{w-1} + input_size (the
                    // location where the last input word was stored)

                    for (std::size_t i = 0; i < primary_input.size() / 2 + 1; ++i) {
                        if (2 * i < primary_input.size()) {
                            latest_double_word += (primary_input[2 * i] << w);
                        }

                        m[input_addr + i] = latest_double_word;

                        if (2 * i + 1 < primary_input.size()) {
                            latest_double_word = primary_input[2 * i + 1];
                        }
                    }

                    return m;
                }

                std::size_t tinyram_architecture_params::opcode_width() const {
                    return algebra::log2(
                        static_cast<std::size_t>(tinyram_opcode_ANSWER)); /* assumption: answer is the last */
                }

                std::size_t tinyram_architecture_params::reg_arg_width() const {
                    return static_cast<std::size_t>(std::ceil(std::log2(k)));
                }

                std::size_t tinyram_architecture_params::instruction_padding_width() const {
                    return 2 * w - (opcode_width() + 1 + 2 * reg_arg_width() + reg_arg_or_imm_width());
                }

                std::size_t tinyram_architecture_params::reg_arg_or_imm_width() const {
                    return std::max(w, reg_arg_width());
                }

                std::size_t tinyram_architecture_params::dwaddr_len() const {
                    return w - (static_cast<std::size_t>(std::ceil(std::log2(w))) - 2);
                }

                std::size_t tinyram_architecture_params::subaddr_len() const {
                    return static_cast<std::size_t>(std::ceil(std::log2(w))) - 2;
                }

                std::size_t tinyram_architecture_params::bytes_in_word() const {
                    return w / 8;
                }

                std::size_t tinyram_architecture_params::instr_size() const {
                    return 2 * w;
                }

                bool tinyram_architecture_params::operator==(const tinyram_architecture_params &other) const {
                    return (this->w == other.w && this->k == other.k);
                }

                tinyram_instruction::tinyram_instruction(const tinyram_opcode &opcode,
                                                         const bool arg2_is_imm,
                                                         const std::size_t &desidx,
                                                         const std::size_t &arg1idx,
                                                         const std::size_t &arg2idx_or_imm) :
                    opcode(opcode),
                    arg2_is_imm(arg2_is_imm), desidx(desidx), arg1idx(arg1idx), arg2idx_or_imm(arg2idx_or_imm) {
                }

                std::size_t tinyram_instruction::as_dword(const tinyram_architecture_params &ap) const {
                    std::size_t result = static_cast<std::size_t>(opcode);
                    result = (result << 1) | (arg2_is_imm ? 1 : 0);
                    result = (result << algebra::log2(ap.k)) | desidx;
                    result = (result << algebra::log2(ap.k)) | arg1idx;
                    result = (result << (2 * ap.w - ap.opcode_width() - 1 - 2 * algebra::log2(ap.k))) | arg2idx_or_imm;

                    return result;
                }

                tinyram_instruction random_tinyram_instruction(const tinyram_architecture_params &ap) {
                    const tinyram_opcode opcode = (tinyram_opcode)(std::rand() % (1ul << ap.opcode_width()));
                    const bool arg2_is_imm = std::rand() & 1;
                    const std::size_t desidx = std::rand() % (1ul << ap.reg_arg_width());
                    const std::size_t arg1idx = std::rand() % (1ul << ap.reg_arg_width());
                    const std::size_t arg2idx_or_imm = std::rand() % (1ul << ap.reg_arg_or_imm_width());
                    return {opcode, arg2_is_imm, desidx, arg1idx, arg2idx_or_imm};
                }

                void tinyram_program::add_instruction(const tinyram_instruction &instr) {
                    instructions.emplace_back(instr);
                }

                tinyram_program load_preprocessed_program(const tinyram_architecture_params &ap,
                                                          std::istream &preprocessed) {
                    ensure_tinyram_opcode_value_map();

                    tinyram_program program;

                    std::string instr, line;

                    while (preprocessed >> instr) {
                        std::size_t immflag, des, a1;
                        long long int a2;
                        if (preprocessed.good()) {
                            preprocessed >> immflag >> des >> a1 >> a2;
                            a2 = ((1ul << ap.w) + (a2 % (1ul << ap.w))) % (1ul << ap.w);
                            program.add_instruction(tinyram_instruction(opcode_values[instr], immflag, des, a1, a2));
                        }
                    }

                    return program;
                }

                memory_store_trace tinyram_boot_trace_from_program_and_input(const tinyram_architecture_params &ap,
                                                                             const std::size_t boot_trace_size_bound,
                                                                             const tinyram_program &program,
                                                                             const tinyram_input_tape &primary_input) {
                    // TODO: document the reverse order here

                    memory_store_trace result;

                    std::size_t boot_pos = boot_trace_size_bound - 1;
                    for (std::size_t i = 0; i < program.instructions.size(); ++i) {
                        result.set_trace_entry(boot_pos--, std::make_pair(i, program.instructions[i].as_dword(ap)));
                    }

                    const std::size_t primary_input_base_addr = (1ul << (ap.dwaddr_len() - 1));

                    for (std::size_t j = 0; j < primary_input.size(); j += 2) {
                        const std::size_t memory_dword =
                            primary_input[j] + ((j + 1 < primary_input.size() ? primary_input[j + 1] : 0) << ap.w);
                        result.set_trace_entry(boot_pos--, std::make_pair(primary_input_base_addr + j, memory_dword));
                    }

                    return result;
                }

                tinyram_input_tape load_tape(std::istream &tape) {
                    tinyram_input_tape result;

                    std::size_t cell;
                    while (tape >> cell) {
                        result.emplace_back(cell);
                    }

                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // TINYRAM_AUX_HPP_
