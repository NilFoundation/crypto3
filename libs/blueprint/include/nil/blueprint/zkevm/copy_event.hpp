
//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#pragma once

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <nil/blueprint/zkevm/util/ptree.hpp>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            constexpr uint8_t MEMORY_COPY = 0;
            constexpr uint8_t BYTECODE_COPY = 1;
            constexpr uint8_t TX_CALLDATA_COPY = 2;
            constexpr uint8_t TX_LOG_COPY = 3;
            constexpr uint8_t KECCAK_COPY = 4;
            constexpr uint8_t PADDING_COPY = 5;

            struct copy_event{
                // {hash_hi, hash_lo} for keccak,
                // {bytecode_hash_hi, bytecode_hash_lo} for bytecode,
                // {0, transaction_id} for TX_CALLDATA_COPY, TX_LOG_COPY
                // {0, call_id} for MEMORY

                zkevm_word_type source_id;
                uint8_t source_type;
                std::size_t src_addr;

                zkevm_word_type destination_id;
                uint8_t destination_type;
                std::size_t dst_addr;

                std::size_t length;

                std::size_t initial_rw_counter;  // Optional for memory operations
                std::vector<std::uint8_t> bytes;
            };

            copy_event calldatacopy_event(
                std::size_t transaction_id,
                std::size_t call_id,
                std::size_t src_addr,
                std::size_t dst_addr,
                std::size_t length,
                std::size_t initial_rw_counter,
                std::vector<uint8_t> bytes
            ){
                return copy_event({
                    transaction_id,
                    TX_CALLDATA_COPY,
                    src_addr,
                    call_id,
                    MEMORY_COPY,
                    dst_addr,
                    length,
                    initial_rw_counter,
                    bytes
                });
            }

            copy_event calldata_hash_event(
                std::size_t transaction_id,
                zkevm_word_type hash,
                std::size_t src_addr,
                std::size_t dst_addr,
                std::size_t length,
                std::vector<uint8_t> bytes
            ){
                return copy_event({
                    transaction_id,
                    TX_CALLDATA_COPY,
                    src_addr,
                    hash,
                    KECCAK_COPY,
                    dst_addr,
                    length,
                    0,
                    bytes
                });
            }

            copy_event keccak_event(
                std::size_t call_id,
                zkevm_word_type hash,
                std::size_t src_addr,
                std::size_t dst_addr,
                std::size_t length,
                std::size_t initial_rw_counter,
                std::vector<uint8_t> bytes
            ){
                return copy_event({
                    call_id,
                    MEMORY_COPY,
                    src_addr,
                    hash,
                    KECCAK_COPY,
                    dst_addr,
                    length,
                    initial_rw_counter,
                    bytes
                });
            }

            copy_event codecopy_event(
                std::size_t call_id,
                zkevm_word_type bytecode_hash,
                std::size_t src_addr,
                std::size_t dst_addr,
                std::size_t length,
                std::size_t initial_rw_counter,
                std::vector<uint8_t> bytes
            ){
                return copy_event({
                    bytecode_hash,
                    BYTECODE_COPY,
                    src_addr,
                    call_id,
                    MEMORY_COPY,
                    dst_addr,
                    length,
                    initial_rw_counter,
                    bytes
                });
            }

            copy_event logx_event(
                std::size_t call_id,
                std::size_t transaction_id,
                std::size_t src_addr,
                std::size_t dst_addr,
                std::size_t length,
                std::size_t initial_rw_counter,
                std::vector<uint8_t> bytes
            ){
                return copy_event({
                    call_id,
                    MEMORY_COPY,
                    src_addr,
                    transaction_id,
                    TX_LOG_COPY,
                    dst_addr,
                    length,
                    initial_rw_counter,
                    bytes
                });
            }

            copy_event mcopy_event(
                std::size_t call_id,
                std::size_t src_addr,
                std::size_t dst_addr,
                std::size_t length,
                std::size_t initial_rw_counter,
                std::vector<uint8_t> bytes
            ){
                return copy_event({
                    call_id,
                    MEMORY_COPY,
                    src_addr,
                    call_id,
                    MEMORY_COPY,
                    dst_addr,
                    length,
                    initial_rw_counter,
                    bytes
                });
            }

            // TODO: add constructors for
            // CALLOP, RETURN, REVERT, RETURNDATACOPY

            // This function is just for testing. It'll be fully rewritten in evm-assigner.
            std::size_t copy_events_from_trace(
                std::vector<copy_event>           &result,
                boost::property_tree::ptree const &pt,
                std::size_t rows_amount,
                std::size_t call_id = 0,
                std::size_t transaction_id = 0,
                std::size_t initial_rw_counter = 0
            ){
                using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                boost::property_tree::ptree ptrace = pt.get_child("result.structLogs");
                boost::property_tree::ptree pstack;
                boost::property_tree::ptree pmemory;

                std::cout << "PT = " << ptrace.size() << std::endl;

                std::vector<zkevm_word_type> stack = zkevm_word_vector_from_ptree(ptrace.begin()->second.get_child("stack"));
                std::vector<std::uint8_t> memory = byte_vector_from_ptree(ptrace.begin()->second.get_child("memory"));
                std::vector<std::uint8_t> memory_next;
                std::vector<zkevm_word_type> stack_next;
                std::map<zkevm_word_type, zkevm_word_type> storage = key_value_storage_from_ptree(ptrace.begin()->second.get_child("storage"));
                std::map<zkevm_word_type, zkevm_word_type> storage_next;

                std::size_t rw_counter = initial_rw_counter;

                for( auto it = ptrace.begin(); it!=ptrace.end(); it++ ){
                    auto opcode = it->second.get_child("op").data();
                    if(std::distance(it, ptrace.end()) == 1) {
                        stack_next = {};
                        memory_next = {};
                        storage_next = storage;
                    }else{
                        stack_next = zkevm_word_vector_from_ptree(std::next(it)->second.get_child("stack"));
                        memory_next = byte_vector_from_ptree(std::next(it)->second.get_child("memory"));
                        storage_next = key_value_storage_from_ptree(it->second.get_child("storage"));
                    }

                    if(opcode == "STOP") {
                        // 0x00 -- no RW operations
                    } else if(opcode == "ADD") {
                        // 0x01
                        rw_counter += 3;
                    } else if(opcode == "MUL") {
                        // 0x02
                        rw_counter += 3;
                    } else if(opcode == "SUB") {
                        // 0x03
                        rw_counter += 3;
                    } else if(opcode == "DIV") {
                        // 0x04
                        rw_counter += 3;
                    } else if(opcode == "SDIV") {
                        // 0x05
                        rw_counter += 3;
                    }  else if(opcode == "MOD") {
                        // 0x06
                        rw_counter += 3;
                    }   else if(opcode == "SMOD") {
                        // 0x07
                        rw_counter += 3;
                    } else if(opcode == "ADDMOD") {
                        // 0x08
                        rw_counter += 4;
                    } else if(opcode == "MULMOD") {
                        // 0x09
                        rw_counter += 4;
                    }   else if(opcode == "EXP") {
                        // 0x0a
                        rw_counter += 3;
                    }   else if(opcode == "SIGEXTEND") {
                        // 0x0b
                        rw_counter += 2;
                    } else if(opcode == "LT") {
                        // 0x10
                        rw_counter += 3;
                    } else if(opcode == "GT") {
                        // 0x11
                        rw_counter += 3;
                    } else if(opcode == "SLT") {
                        // 0x12
                        rw_counter += 3;
                    } else if(opcode == "SGT") {
                        // 0x13
                        rw_counter += 3;
                    } else if(opcode == "EQ") {
                        // 0x14
                        rw_counter += 3;
                    } else if(opcode == "ISZERO") {
                        // 0x15
                        rw_counter += 2;
                    } else if(opcode == "AND") {
                        // 0x16
                        rw_counter += 3;
                    } else if(opcode == "OR") {
                        // 0x17
                        rw_counter += 3;
                    } else if(opcode == "XOR") {
                        // 0x18
                        rw_counter += 3;
                    } else if(opcode == "NOT") {
                        // 0x19
                        rw_counter += 3;
                    } else if(opcode == "BYTE") {
                        // 0x1a
                        rw_counter += 3;
                    } else if(opcode == "SHL") {
                        // 0x1b
                        rw_counter += 3;
                    } else if(opcode == "SHR") {
                        // 0x1c
                        rw_counter += 3;
                    } else if(opcode == "SAR") {
                        // 0x1d
                        rw_counter += 3;
                    } else if(opcode == "SHA3") {
                        // 0x20
                        std::cout << "KECCAK copy event!!!" << std::endl;
                        exit(2);
                        rw_counter += 3; // TODO: add memory read operations
                    } else if(opcode == "ADDRESS") {
                        // 0x30
                        rw_counter += 1;
                    } else if(opcode == "BALANCE") {
                        // 0x31
                        rw_counter += 2;
                    } else if(opcode == "ORIGIN") {
                        // 0x32
                        rw_counter += 1;
                    } else if(opcode == "CALLER") {
                        // 0x33
                        rw_counter += 1;
                    } else if(opcode == "CALLVALUE") {
                        // 0x34
                        rw_counter += 1;
                    } else if(opcode == "CALLDATALOAD") {
                        // 0x35
                        rw_counter += 2;
                    } else if(opcode == "CALLDATASIZE") {
                        // 0x36
                        rw_counter += 1;
                    } else if(opcode == "CALLDATACOPY") {
                        // 0x37
//                        exit(2);
                        std::size_t dst = std::size_t(integral_type(stack[stack.size()- 1]));
                        std::size_t src = std::size_t(integral_type(stack[stack.size()- 2]));
                        std::size_t length = std::size_t(integral_type(stack[stack.size() - 3]));
                        std::cout << "CALLDATACOPY copy event length = " << length << " rw_counter = " << rw_counter << ": ";
                        std::vector<std::uint8_t> bytes;
                        for( std::size_t i = 0; i < length; i++){
                            bytes.push_back(memory_next[dst+i]);
                            std::cout << std::hex << std::setw(2) << std::setfill('0') << std::size_t(memory_next[std::size_t(integral_type(dst + i))]) << std::dec;
                        }
                        std::cout << std::endl;
                        result.push_back(calldatacopy_event(transaction_id, call_id, src, dst, length, rw_counter, bytes));
                        rw_counter += 3+length;
                        // TODO: add length read operations to calldata
                        // TODO: add length write operations to memory
                    } else if(opcode == "CODESIZE") {
                        // 0x38
                        rw_counter += 1;
                    } else if(opcode == "CODECOPY") {
                        // 0x39
                        std::cout << "CODECOPY event calldata copy!" << std::endl;
                        exit(2);
                        std::size_t length = std::size_t(integral_type(stack[stack.size()-3]));
                        rw_counter += 3 + length;
                        // TODO: add length write operations to memory
                        // Consistency with bytecode table will be checked by bytecode circuit
                    } else if(opcode == "GASPRICE") {
                        // 0x3a
                        rw_counter += 1;
                    } else if(opcode == "EXTCODESIZE") {
                        // 0x3b
                        rw_counter += 1;
                    } else if(opcode == "EXTCODECOPY") {
                        // 0x3c
                        std::cout << "EXDCODECOPY event copy!" << std::endl;
                        exit(2);
                        std::size_t length = std::size_t(integral_type(stack[stack.size()-3]));
                        rw_counter += 4 + length;
                        // TODO: add length write operations to memory
                        // Consistency with bytecode table will be checked by bytecode circuit
                    } else if(opcode == "RETURNDATASIZE") {
                        // 0x3d
                        rw_counter += 1;
                    } else if(opcode == "RETURNDATACOPY") {
                        // 0x3e
                        std::cout << "RETURNDATACOPY event copy!" << std::endl;
                        exit(2);
                        std::size_t length = std::size_t(integral_type(stack[stack.size()-3]));
                        rw_counter += 3 + length;
                        // TODO: add length write operations to memory
                        // Where will consistency check be done?
                    } else if(opcode == "EXTCODEHASH") {
                        // 0x3f
                        rw_counter += 2;
                    } else if(opcode == "BLOCKHASH") {
                        // 0x40
                        rw_counter += 1;
                    } else if(opcode == "COINBASE") {
                        // 0x41
                        rw_counter += 1;
                    } else if(opcode == "TIMESTAMP") {
                        // 0x42
                        rw_counter += 1;
                    } else if(opcode == "NUMBER") {
                        // 0x43
                        rw_counter += 1;
                    } else if(opcode == "DIFFICULTY") {
                        // 0x44
                        rw_counter += 1;
                    } else if(opcode == "GASLIMIT") {
                        // 0x45
                        rw_counter += 1;
                    } else if(opcode == "CHAINID") {
                        // 0x46
                        std::cout << "Test me, please!" << std::endl;
                        rw_counter += 1;
                    } else if(opcode == "SELFBALANCE") {
                        // 0x47
                        rw_counter += 1;
                    } else if(opcode == "BASEFEE") {
                        // 0x48
                        rw_counter += 2;
                    } else if(opcode == "BLOBHASH") {
                        // 0x49
                        rw_counter += 1;
                    } else if(opcode == "BLOBBASEFEE") {
                        // 0x4a
                        rw_counter += 1;
                    } else if(opcode == "POP") {
                        // 0x50
                        rw_counter += 2;
                    } else if(opcode == "MLOAD") {
                        // 0x51
                        rw_counter += 34;
                    } else if(opcode == "MSTORE") {
                        // 0x52
                        rw_counter += 34;
                    } else if(opcode == "MSTORE8") {
                        // 0x53
                        rw_counter += 3;
                    } else if(opcode == "SLOAD") {
                        // 0x54
                        rw_counter += 3;
                    } else if(opcode == "SSTORE") {
                        // 0x55
                        rw_counter += 3;
                    } else if(opcode == "JUMP") {
                        // 0x56
                        rw_counter += 1;
                    } else if(opcode == "JUMPI") {
                        // 0x57
                        rw_counter += 2;
                    } else if(opcode == "PC") {
                        // 0x58
                        rw_counter += 1;
                    } else if(opcode == "MSIZE") {
                        // 0x58
                        rw_counter += 1;
                    } else if(opcode == "GAS") {
                        // 0x59
                        rw_counter += 1;
                    } else if(opcode == "JUMPDEST") {
                        // 0x5a
                    } else if(opcode == "TLOAD") {
                        rw_counter += 2;
                    } else if(opcode == "TSTORE") {
                        rw_counter += 2;
                    } else if(opcode == "MCOPY") {
                        // 0x5d
                        std::cout << "MCOPY copy event" << std::endl;
                        exit(2);
                        rw_counter += 3;
                    }  else  if(opcode == "PUSH0") {
                        // 0x5f
                        rw_counter += 1;
                    }  else  if(opcode == "PUSH1") {
                        // 0x60
                        rw_counter += 1;
                    } else if(opcode == "PUSH2") {
                        // 0x61
                        rw_counter += 1;
                    } else if(opcode == "PUSH3") {
                        // 0x62
                        rw_counter += 1;
                    } else if(opcode == "PUSH4") {
                        // 0x63
                        rw_counter += 1;
                    } else if(opcode == "PUSH5") {
                        // 0x64
                        rw_counter += 1;
                    } else if(opcode == "PUSH6") {
                        // 0x65
                        rw_counter += 1;
                    } else if(opcode == "PUSH7") {
                        // 0x66
                        rw_counter += 1;
                    } else if(opcode == "PUSH8") {
                        // 0x67
                        rw_counter += 1;
                    } else if(opcode == "PUSH9") {
                        // 0x68
                        rw_counter += 1;
                    } else if(opcode == "PUSH10") {
                        // 0x69
                        rw_counter += 1;
                    } else if(opcode == "PUSH11") {
                        // 0x6a
                        rw_counter += 1;
                    } else if(opcode == "PUSH12") {
                        // 0x6b
                        rw_counter += 1;
                    } else if(opcode == "PUSH13") {
                        // 0x6c
                        rw_counter += 1;
                    } else if(opcode == "PUSH14") {
                        // 0x6d
                        rw_counter += 1;
                    } else if(opcode == "PUSH15") {
                        // 0x6e
                        rw_counter += 1;
                    } else if(opcode == "PUSH16") {
                        // 0x6f
                        rw_counter += 1;
                    } else if(opcode == "PUSH17") {
                        // 0x70
                        rw_counter += 1;
                    } else if(opcode == "PUSH18") {
                        // 0x71
                        rw_counter += 1;
                    } else if(opcode == "PUSH19") {
                        // 0x72
                        rw_counter += 1;
                    } else if(opcode == "PUSH20") {
                        // 0x73
                        rw_counter += 1;
                    } else if(opcode == "PUSH21") {
                        // 0x74
                        rw_counter += 1;
                    } else if(opcode == "PUSH22") {
                        // 0x75
                        rw_counter += 1;
                    } else if(opcode == "PUSH23") {
                        // 0x76
                        rw_counter += 1;
                    } else if(opcode == "PUSH24") {
                        // 0x77
                        rw_counter += 1;
                    } else if(opcode == "PUSH25") {
                        // 0x78
                        rw_counter += 1;
                    } else if(opcode == "PUSH26") {
                        // 0x79
                        rw_counter += 1;
                    } else if(opcode == "PUSH27") {
                        // 0x7a
                        rw_counter += 1;
                    } else if(opcode == "PUSH28") {
                        // 0x7b
                        rw_counter += 1;
                    } else if(opcode == "PUSH29") {
                        // 0x7c
                        rw_counter += 1;
                    } else if(opcode == "PUSH30") {
                        // 0x7d
                        rw_counter += 1;
                    } else if(opcode == "PUSH31") {
                        // 0x7e
                        rw_counter += 1;
                    } else if(opcode == "PUSH32") {
                        // 0x7f
                        rw_counter += 1;
                    } else if(opcode == "DUP1") {
                        // 0x80
                        rw_counter += 2;
                    } else if(opcode == "DUP2") {
                        // 0x81
                        rw_counter += 2;
                    } else if(opcode == "DUP3") {
                        // 0x82
                        rw_counter += 2;
                    } else if(opcode == "DUP4") {
                        // 0x83
                        rw_counter += 2;
                    } else if(opcode == "DUP5") {
                        // 0x84
                        rw_counter += 2;
                    } else if(opcode == "DUP6") {
                        // 0x85
                        rw_counter += 2;
                    } else if(opcode == "DUP7") {
                        // 0x86
                        rw_counter += 2;
                    } else if(opcode == "DUP8") {
                        // 0x87
                        rw_counter += 2;
                    } else if(opcode == "DUP9") {
                        // 0x88
                        rw_counter += 2;
                    } else if(opcode == "DUP10") {
                        // 0x89
                        rw_counter += 2;
                    } else if(opcode == "DUP11") {
                        // 0x8a
                        rw_counter += 2;
                    } else if(opcode == "DUP12") {
                        // 0x8b
                        rw_counter += 2;
                    } else if(opcode == "DUP13") {
                        // 0x8c
                        rw_counter += 2;
                    } else if(opcode == "DUP14") {
                        // 0x8d
                        rw_counter += 2;
                    } else if(opcode == "DUP15") {
                        // 0x8e
                        rw_counter += 2;
                    } else if(opcode == "DUP16") {
                        // 0x8f
                        rw_counter += 2;
                    } else if(opcode == "SWAP1") {
                        // 0x90
                        rw_counter += 4;
                    } else if(opcode == "SWAP2") {
                        // 0x91
                        rw_counter += 4;
                    } else if(opcode == "SWAP3") {
                        // 0x92
                        rw_counter += 4;
                    } else if(opcode == "SWAP4") {
                        // 0x93
                        rw_counter += 4;
                    } else if(opcode == "SWAP5") {
                        // 0x94
                        rw_counter += 4;
                    } else if(opcode == "SWAP6") {
                        // 0x95
                        rw_counter += 4;
                    } else if(opcode == "SWAP7") {
                        // 0x96
                        rw_counter += 4;
                    } else if(opcode == "SWAP8") {
                        // 0x97
                        rw_counter += 4;
                    } else if(opcode == "SWAP9") {
                        // 0x98
                        rw_counter += 4;
                    } else if(opcode == "SWAP10") {
                        // 0x99
                        rw_counter += 4;
                    } else if(opcode == "SWAP11") {
                        // 0x9a
                        rw_counter += 4;
                    } else if(opcode == "SWAP12") {
                        // 0x9b
                        rw_counter += 4;
                    } else if(opcode == "SWAP13") {
                        // 0x9c
                        rw_counter += 4;
                    } else if(opcode == "SWAP14") {
                        // 0x9d
                        rw_counter += 4;
                    } else if(opcode == "SWAP15") {
                        // 0x9e
                        rw_counter += 4;
                    } else if(opcode == "SWAP16") {
                        // 0x9f
                        rw_counter += 4;
                    } else if(opcode == "LOG0") {
                        // 0xa0
                        std::cout << "LOG0 copy event" << std::endl;
                        exit(2);
                        rw_counter += 2;
                    } else if(opcode == "LOG1") {
                        // 0xa1
                        std::cout << "LOG1 copy event" << std::endl;
                        exit(2);
                        rw_counter += 3;
                    } else if(opcode == "LOG2") {
                        // 0xa2
                        std::cout << "LOG2 copy event" << std::endl;
                        exit(2);
                        rw_counter += 4;
                    } else if(opcode == "LOG3") {
                        // 0xa3
                        std::cout << "LOG3 copy event" << std::endl;
                        exit(2);
                        rw_counter += 5;
                    } else if(opcode == "LOG4") {
                        // 0xa4
                        std::cout << "LOG4 copy event" << std::endl;
                        exit(2);
                        rw_counter += 6;
                    } else if(opcode == "CREATE") {
                        // 0xf0
                        std::cout << "CREATE copy event" << std::endl;
                        exit(2);
                        rw_counter += 4;
                    } else if(opcode == "CALL") {
                        // 0xf1
                        rw_counter += 8;
                    } else if(opcode == "CALLCODE") {
                        // 0xf2
                        rw_counter += 8;
                    } else if(opcode == "RETURN") {
                        // 0xf3
                        std::cout << "RETURN copy event" << std::endl;
//                        exit(2);
                        rw_counter += 2;
                    } else if(opcode == "DELEGATECALL") {
                        // 0xf4
                        rw_counter += 7;
                    } else if(opcode == "CREATE2") {
                        // 0xf5
                        std::cout << "CREATE2 copy event" << std::endl;
                        exit(2);
                        rw_counter += 5;
                    } else if(opcode == "STATICCALL") {
                        // 0xfa
                        rw_counter += 7;
                    } else if(opcode == "REVERT") {
                        // 0xfd
                        rw_counter += 2;
                    } else if(opcode == "SELFDESTRUCT") {
                        // 0xff
                        rw_counter += 1;
                    } else {
                        std::cout << "Unknown opcode " << std::hex << opcode << std::dec << std::endl;
                        BOOST_ASSERT(false);
                    }

                    storage = storage_next;
                    stack = stack_next;
                    memory = memory_next;
                }
                return rw_counter;
            }
        }
    }
}