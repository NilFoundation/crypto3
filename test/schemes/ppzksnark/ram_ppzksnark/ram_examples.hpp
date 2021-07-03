//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a RAM example, as well as functions to sample
// RAM examples with prescribed parameters (according to some distribution).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_RAM_EXAMPLES_HPP
#define CRYPTO3_ZK_RAM_EXAMPLES_HPP

#include <nil/crypto3/zk/snark/relations/ram_computations/rams/ram_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename RAMType>
                struct ram_example {
                    ram_architecture_params<RAMType> ap;
                    std::size_t boot_trace_size_bound;
                    std::size_t time_bound;
                    ram_boot_trace<RAMType> boot_trace;
                    ram_input_tape<RAMType> auxiliary_input;
                };

                /**
                 * For now: only specialized to TinyRAM
                 */
                template<typename RAMType>
                ram_example<RAMType> gen_ram_example_simple(const ram_architecture_params<RAMType> &ap,
                                                            std::size_t boot_trace_size_bound, std::size_t time_bound,
                                                            bool satisfiable = true) {
                    const std::size_t program_size = boot_trace_size_bound / 2;
                    const std::size_t input_size = boot_trace_size_bound - program_size;

                    ram_example<RAMType> result;

                    result.ap = ap;
                    result.boot_trace_size_bound = boot_trace_size_bound;
                    result.time_bound = time_bound;

                    tinyram_program prelude;
                    prelude.instructions = generate_tinyram_prelude(ap);

                    std::size_t boot_pos = 0;
                    for (std::size_t i = 0; i < prelude.instructions.size(); ++i) {
                        result.boot_trace.set_trace_entry(boot_pos++,
                                                          std::make_pair(i, prelude.instructions[i].as_dword(ap)));
                    }

                    result.boot_trace[boot_pos] = std::make_pair(
                        boot_pos++, tinyram_instruction(tinyram_opcode_ANSWER, true, 0, 0, satisfiable ? 0 : 1)
                                        .as_dword(ap)); /* answer 0/1 depending on satisfiability */

                    while (boot_pos < program_size) {
                        result.boot_trace.set_trace_entry(boot_pos++, random_tinyram_instruction(ap).as_dword(ap));
                    }

                    for (std::size_t i = 0; i < input_size; ++i) {
                        result.boot_trace.set_trace_entry(
                            boot_pos++,
                            std::make_pair((1ul << (ap.dwaddr_len() - 1)) + i, std::rand() % (1ul << (2 * ap.w))));
                    }

                    BOOST_CHECK(boot_pos == boot_trace_size_bound);

                    return result;
                }

                /**
                 * For now: only specialized to TinyRAM
                 */
                template<typename RAMType>
                ram_example<RAMType> gen_ram_example_complex(const ram_architecture_params<RAMType> &ap,
                                                             std::size_t boot_trace_size_bound, std::size_t time_bound,
                                                             bool satisfiable = true) {
                    const std::size_t program_size = boot_trace_size_bound / 2;
                    const std::size_t input_size = boot_trace_size_bound - program_size;

                    BOOST_CHECK(2 * ap.w / 8 * program_size < 1ul << (ap.w - 1));
                    BOOST_CHECK(ap.w / 8 * input_size < 1ul << (ap.w - 1));

                    ram_example<RAMType> result;

                    result.ap = ap;
                    result.boot_trace_size_bound = boot_trace_size_bound;
                    result.time_bound = time_bound;

                    tinyram_program prelude;
                    prelude.instructions = generate_tinyram_prelude(ap);

                    std::size_t boot_pos = 0;
                    for (std::size_t i = 0; i < prelude.instructions.size(); ++i) {
                        result.boot_trace.set_trace_entry(boot_pos++,
                                                          std::make_pair(i, prelude.instructions[i].as_dword(ap)));
                    }

                    const std::size_t prelude_len = prelude.instructions.size();
                    const std::size_t instr_addr = (prelude_len + 4) * (2 * ap.w / 8);
                    const std::size_t input_addr =
                        (1ul << (ap.w - 1)) + (ap.w / 8);    // byte address of the first input word

                    result.boot_trace.set_trace_entry(
                        boot_pos,
                        std::make_pair(boot_pos,
                                       tinyram_instruction(tinyram_opcode_LOADB, true, 1, 0, instr_addr).as_dword(ap)));
                    ++boot_pos;
                    result.boot_trace.set_trace_entry(
                        boot_pos,
                        std::make_pair(boot_pos,
                                       tinyram_instruction(tinyram_opcode_LOADW, true, 2, 0, input_addr).as_dword(ap)));
                    ++boot_pos;
                    result.boot_trace.set_trace_entry(
                        boot_pos,
                        std::make_pair(boot_pos, tinyram_instruction(tinyram_opcode_SUB, false, 1, 1, 2).as_dword(ap)));
                    ++boot_pos;
                    result.boot_trace.set_trace_entry(
                        boot_pos,
                        std::make_pair(
                            boot_pos, tinyram_instruction(tinyram_opcode_STOREB, true, 1, 0, instr_addr).as_dword(ap)));
                    ++boot_pos;
                    result.boot_trace.set_trace_entry(
                        boot_pos,
                        std::make_pair(boot_pos,
                                       tinyram_instruction(tinyram_opcode_ANSWER, true, 0, 0, 1).as_dword(ap)));
                    ++boot_pos;

                    while (boot_pos < program_size) {
                        result.boot_trace.set_trace_entry(
                            boot_pos, std::make_pair(boot_pos, random_tinyram_instruction(ap).as_dword(ap)));
                        ++boot_pos;
                    }

                    result.boot_trace.set_trace_entry(
                        boot_pos++, std::make_pair(1ul << (ap.dwaddr_len() - 1), satisfiable ? 1ul << ap.w : 0));

                    for (std::size_t i = 1; i < input_size; ++i) {
                        result.boot_trace.set_trace_entry(
                            boot_pos++,
                            std::make_pair((1ul << (ap.dwaddr_len() - 1)) + i + 1, std::rand() % (1ul << (2 * ap.w))));
                    }

                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RAM_EXAMPLES_HPP
