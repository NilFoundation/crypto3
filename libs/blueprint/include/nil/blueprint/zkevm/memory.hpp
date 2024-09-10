//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, ffree of charge, to any person obtaining a copy
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

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/zkevm/zkevm_word.hpp>
#include <ostream>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/blueprint/zkevm/util/ptree.hpp>

namespace nil {
    namespace blueprint {
        constexpr std::uint8_t START_OP = 0;
        constexpr std::uint8_t STACK_OP = 1;
        constexpr std::uint8_t MEMORY_OP = 2;
        constexpr std::uint8_t STORAGE_OP = 3;
        constexpr std::uint8_t TRANSIENT_STORAGE_OP = 4;
        constexpr std::uint8_t CALL_CONTEXT_OP = 5;
        constexpr std::uint8_t ACCOUNT_OP = 6;
        constexpr std::uint8_t TX_REFUND_OP = 7;
        constexpr std::uint8_t TX_ACCESS_LIST_ACCOUNT_OP = 8;
        constexpr std::uint8_t TX_ACCESS_LIST_ACCOUNT_STORAGE_OP = 9;
        constexpr std::uint8_t TX_LOG_OP = 10;
        constexpr std::uint8_t TX_RECEIPT_OP = 11;
        constexpr std::uint8_t PADDING_OP = 12;
        constexpr std::uint8_t rw_options_amount = 13;

        struct rw_operation{
            std::uint8_t op;             // described above
            std::size_t id;              // call_id for stack, memory, tx_id for
            zkevm_word_type address;     // 10 bit for stack, 160 bit for
            std::uint8_t field;          // Not used for stack, memory, storage
            zkevm_word_type storage_key; // 256-bit, not used for stack, memory
            std::size_t rw_id;           // 32-bit
            bool is_write;               // 1 if it's write operation
            zkevm_word_type value;       // It's full 256 words for storage and stack, but it's only byte for memory.
            zkevm_word_type value_prev;

            bool operator< (const rw_operation &other) const {
                if( op != other.op ) return op < other.op;
                if( address != other.address ) return address < other.address;
                if( field != other.field ) return field < other.field;
                if( storage_key != other.storage_key ) return storage_key < other.storage_key;
                if( rw_id != other.rw_id) return rw_id < other.rw_id;
                return false;
            }
        };

        // For testing purposes
        std::ostream& operator<<(std::ostream& os, const rw_operation& obj){
            if(obj.op == START_OP )                           os << "START                              : ";
            if(obj.op == STACK_OP )                           os << "STACK                              : ";
            if(obj.op == MEMORY_OP )                          os << "MEMORY                             : ";
            if(obj.op == STORAGE_OP )                         os << "STORAGE                            : ";
            if(obj.op == TRANSIENT_STORAGE_OP )               os << "TRANSIENT_STORAGE                  : ";
            if(obj.op == CALL_CONTEXT_OP )                    os << "CALL_CONTEXT_OP                    : ";
            if(obj.op == ACCOUNT_OP )                         os << "ACCOUNT_OP                         : ";
            if(obj.op == TX_REFUND_OP )                       os << "TX_REFUND_OP                       : ";
            if(obj.op == TX_ACCESS_LIST_ACCOUNT_OP )          os << "TX_ACCESS_LIST_ACCOUNT_OP          : ";
            if(obj.op == TX_ACCESS_LIST_ACCOUNT_STORAGE_OP )  os << "TX_ACCESS_LIST_ACCOUNT_STORAGE_OP  : ";
            if(obj.op == TX_LOG_OP )                          os << "TX_LOG_OP                          : ";
            if(obj.op == TX_RECEIPT_OP )                      os << "TX_RECEIPT_OP                      : ";
            if(obj.op == PADDING_OP )                         os << "PADDING_OP                         : ";
            os << obj.rw_id << ", addr =" << std::hex << obj.address << std::dec;
            if(obj.op == STORAGE_OP || obj.op == TRANSIENT_STORAGE_OP)
                os << " storage_key = " << obj.storage_key;
            if(obj.is_write) os << " W "; else os << " R ";
            os << "[" << std::hex << obj.value_prev << std::dec <<"] => ";
            os << "[" << std::hex << obj.value << std::dec <<"]";
            return os;
        }

        rw_operation start_operation(){
            return rw_operation({START_OP, 0, 0, 0, 0, 0, 0, 0});
        }

        rw_operation stack_operation(std::size_t id, uint16_t address, std::size_t rw_id, bool is_write, zkevm_word_type value){
            BOOST_ASSERT(id < ( 1 << 28)); // Maximum calls amount(?)
            BOOST_ASSERT(address < 1024);
            return rw_operation({STACK_OP, id, address, 0, 0, rw_id, is_write, value, 0});
        }

        rw_operation memory_operation(std::size_t id, zkevm_word_type address, std::size_t rw_id, bool is_write, zkevm_word_type value){
            BOOST_ASSERT(id < ( 1 << 28)); // Maximum calls amount(?)
            return rw_operation({MEMORY_OP, id, address, 0, 0, rw_id, is_write, value, 0});
        }

        rw_operation storage_operation(
            std::size_t id,
            zkevm_word_type address,
            zkevm_word_type storage_key,
            std::size_t rw_id,
            bool is_write,
            zkevm_word_type value,
            zkevm_word_type value_prev
        ){
            return rw_operation({STORAGE_OP, id, address, 0, storage_key, rw_id, is_write, value, value_prev});
        }

        rw_operation padding_operation(){
            return rw_operation({PADDING_OP, 0, 0, 0, 0, 0, 0, 0});
        }

        template<typename BlueprintFieldType>
        class rw_trace{
        public:
            using val = typename BlueprintFieldType::value_type;
        protected:
            std::vector<rw_operation> rw_ops;
            std::size_t call_id;

            void append_opcode(
                std::string opcode,
                const std::vector<zkevm_word_type> &stack,       // Stack state before operation
                const std::vector<zkevm_word_type> &stack_next,  // stack state after operation. We need it for correct PUSH and correct SLOAD
                const std::vector<uint8_t> &memory ,     // Memory state before operation in bytes format
                const std::vector<uint8_t> &memory_next ,     // Memory state before operation in bytes format
                const std::map<zkevm_word_type, zkevm_word_type> &storage,// Storage state before operation
                const std::map<zkevm_word_type, zkevm_word_type> &storage_next// Storage state before operation
            ){
                using integral_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<257>>;

                // Opcode is not presented in RW lookup table. We just take it from json
                std::cout << opcode << std::endl;
                if(opcode == "STOP") {
                    // 0x00 -- no RW operations
                } else if(opcode == "ADD") {
                    // 0x01
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "MUL") {
                    // 0x02
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SUB") {
                    // 0x03
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DIV") {
                    // 0x04
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SDIV") {
                    // 0x05
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                }  else if(opcode == "MOD") {
                    // 0x06
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                }   else if(opcode == "SMOD") {
                    // 0x07
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "ADDMOD") {
                    // 0x08
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "MULMOD") {
                    // 0x09
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                }   else if(opcode == "EXP") {
                    // 0x0a
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                }   else if(opcode == "SIGEXTEND") {
                    // 0x0b
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "LT") {
                    // 0x10
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "GT") {
                    // 0x11
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SLT") {
                    // 0x12
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SGT") {
                    // 0x13
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "EQ") {
                    // 0x14
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "ISZERO") {
                    // 0x15
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "AND") {
                    // 0x16
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "OR") {
                    // 0x17
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "XOR") {
                    // 0x18
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "NOT") {
                    // 0x19
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "BYTE") {
                    // 0x1a
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SHL") {
                    // 0x1b
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SHR") {
                    // 0x1c
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SAR") {
                    // 0x1d
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SHA3") {
                    // 0x20
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    auto length = stack[stack.size()-2];
                    // TODO: add Length memory READ operations
                    auto offset = stack[stack.size()-1];
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "ADDRESS") {
                    // 0x30
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "BALANCE") {
                    // 0x31
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    // TODO:  add read operations from account
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "ORIGIN") {
                    // 0x32
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CALLER") {
                    // 0x33
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CALLVALUE") {
                    // 0x34
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CALLDATALOAD") {
                    // 0x35
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    // TODO: add 32 read operations to calldata
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CALLDATASIZE") {
                    // 0x36
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CALLDATACOPY") {
                    // 0x37
                    std::cout << "Test me, please!" << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    std::size_t length = std::size_t(integral_type(stack[stack.size()-3]));
                    std::size_t dest = std::size_t(integral_type(stack[stack.size()-1]));
                    std::cout << "Length = " << length << std::endl;
                    std::cout << "Memory_size " << memory.size() << "=>" << memory_next.size() << std::endl;
                    for( std::size_t i = 0; i < length; i++){
                        rw_ops.push_back(memory_operation(call_id, dest+i, rw_ops.size(), true, memory_next[dest+i]));
                        std::cout << "\t" << rw_ops[rw_ops.size() - 1] << std::endl;
                    }
                    // TODO: add length read operations to calldata
                    // TODO: add length write operations to memory
                } else if(opcode == "CODESIZE") {
                    // 0x38
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CODECOPY") {
                    // 0x39
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    // TODO: add length write operations to memory
                    // Consistency with bytecode table will be checked by bytecode circuit
                } else if(opcode == "GASPRICE") {
                    // 0x3a
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "EXTCODESIZE") {
                    // 0x3b
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "EXTCODECOPY") {
                    // 0x3c
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    // TODO: add length write operations to memory
                    // Consistency with bytecode table will be checked by bytecode circuit
                } else if(opcode == "RETURNDATASIZE") {
                    // 0x3d
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "RETURNDATACOPY") {
                    // 0x3e
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    // TODO: add length write operations to memory
                    // Where will consistency check be done?
                } else if(opcode == "EXTCODEHASH") {
                    // 0x3f
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "BLOCKHASH") {
                    // 0x40
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "COINBASE") {
                    // 0x41
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "TIMESTAMP") {
                    // 0x42
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "NUMBER") {
                    // 0x43
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DIFFICULTY") {
                    // 0x44
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "GASLIMIT") {
                    // 0x45
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CHAINID") {
                    // 0x46
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SELFBALANCE") {
                    // 0x47
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "BASEFEE") {
                    // 0x48
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "BLOBHASH") {
                    // 0x49
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "BLOBBASEFEE") {
                    // 0x4a
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "POP") {
                    // 0x50
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "MLOAD") {
                    // 0x51
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    zkevm_word_type addr = stack[stack.size() - 1];
                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                    std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                    for( std::size_t i = 0; i < 32; i++){
                        rw_ops.push_back(memory_operation(call_id, addr+i, rw_ops.size(), false, addr+i < memory.size() ? memory[std::size_t(integral_type(addr+i))]: 0));
                        std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    }
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "MSTORE") {
                    // 0x52
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    zkevm_word_type addr = stack[stack.size() - 1];
                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                    std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                    auto bytes = w_to_8(stack[stack.size() - 2]);
                    for( std::size_t i = 0; i < 32; i++){
                        rw_ops.push_back(memory_operation(call_id, addr + i, rw_ops.size(), true, bytes[i]));
                        std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    }
                } else if(opcode == "MSTORE8") {
                    // 0x53
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    zkevm_word_type addr = stack[stack.size() - 1];
                    BOOST_ASSERT_MSG(addr < std::numeric_limits<std::size_t>::max(), "Cannot process so large memory address");
                    std::cout << "\t\t Address = 0x" << std::hex << addr << std::dec << " memory size " << memory.size() << std::endl;
                    auto bytes = w_to_8(stack[stack.size() - 2]);
                    rw_ops.push_back(memory_operation(call_id, addr, rw_ops.size(), true, bytes[31]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SLOAD") {
                    // 0x54
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(storage_operation(
                        call_id,
                        0,
                        stack[stack.size()-1],
                        rw_ops.size(),
                        false,
                        storage_next.at(stack[stack.size()-1]),
                        storage_next.at(stack[stack.size()-1])
                    )); // Second parameter should be transaction_id)
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SSTORE") {
                    // 0x55
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));

                    rw_ops.push_back(storage_operation(
                        call_id,
                        0,
                        stack[stack.size()-1],
                        rw_ops.size(),
                        true,
                        stack[stack.size()-2],
                        // TODO: Remove this zero value in value_before by real previous storage value.
                        // Overwise lookup in MPT table won't be correct
                        (storage.find(stack[stack.size()-1]) == storage.end())? 0: storage.at(stack[stack.size()-1]))
                    ); // Second parameter should be transaction_id
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "JUMP") {
                    // 0x56
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "JUMPI") {
                    // 0x57
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PC") {
                    // 0x58
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "MSIZE") {
                    // 0x58
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "GAS") {
                    // 0x59
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "JUMPDEST") {
                    // 0x5a
                } else if(opcode == "TLOAD") {
                    // 0x5b
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    // TODO: add trasient storage operations
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "TSTORE") {
                    // 0x5c
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    // TODO: add trasient storage write operations
                } else if(opcode == "MCOPY") {
                    // 0x5d
                    std::cout << "Test me, please!" << std::endl;
                    exit(2);
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    // TODO: add length read operations to memory
                    // TODO: add length write operations to memory
                    // Consistensy will be checked by copy circuit
                }  else  if(opcode == "PUSH0") {
                    // 0x5f
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                }  else  if(opcode == "PUSH1") {
                    // 0x60
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH2") {
                    // 0x61
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH3") {
                    // 0x62
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH4") {
                    // 0x63
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH5") {
                    // 0x64
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH6") {
                    // 0x65
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH7") {
                    // 0x66
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH8") {
                    // 0x67
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH9") {
                    // 0x68
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH10") {
                    // 0x69
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH11") {
                    // 0x6a
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH12") {
                    // 0x6b
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH13") {
                    // 0x6c
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH14") {
                    // 0x6d
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH15") {
                    // 0x6e
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH16") {
                    // 0x6f
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH17") {
                    // 0x70
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH18") {
                    // 0x71
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH19") {
                    // 0x72
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH20") {
                    // 0x73
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH21") {
                    // 0x74
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH22") {
                    // 0x75
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH23") {
                    // 0x76
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH24") {
                    // 0x77
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH25") {
                    // 0x78
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH26") {
                    // 0x79
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH27") {
                    // 0x7a
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH28") {
                    // 0x7b
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH29") {
                    // 0x7c
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH30") {
                    // 0x7d
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH31") {
                    // 0x7e
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "PUSH32") {
                    // 0x7f
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP1") {
                    // 0x80
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP2") {
                    // 0x81
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP3") {
                    // 0x82
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP4") {
                    // 0x83
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP5") {
                    // 0x84
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP6") {
                    // 0x85
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-6, rw_ops.size(), false, stack[stack.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP7") {
                    // 0x86
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-7, rw_ops.size(), false, stack[stack.size()-7]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP8") {
                    // 0x87
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-8, rw_ops.size(), false, stack[stack.size()-8]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP9") {
                    // 0x88
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-9, rw_ops.size(), false, stack[stack.size()-9]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP10") {
                    // 0x89
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-10, rw_ops.size(), false, stack[stack.size()-10]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP11") {
                    // 0x8a
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-11, rw_ops.size(), false, stack[stack.size()-11]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP12") {
                    // 0x8b
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-12, rw_ops.size(), false, stack[stack.size()-12]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP13") {
                    // 0x8c
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-13, rw_ops.size(), false, stack[stack.size()-13]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP14") {
                    // 0x8d
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-14, rw_ops.size(), false, stack[stack.size()-14]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP15") {
                    // 0x8e
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-15, rw_ops.size(), false, stack[stack.size()-15]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DUP16") {
                    // 0x8f
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-16, rw_ops.size(), false, stack[stack.size()-16]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP1") {
                    // 0x90
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-2, rw_ops.size(), true, stack_next[stack_next.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP2") {
                    // 0x91
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-3, rw_ops.size(), true, stack_next[stack_next.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP3") {
                    // 0x92
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-4, rw_ops.size(), true, stack_next[stack_next.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP4") {
                    // 0x93
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-5, rw_ops.size(), true, stack_next[stack_next.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP5") {
                    // 0x94
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-6, rw_ops.size(), false, stack[stack.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-6, rw_ops.size(), true, stack_next[stack_next.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP6") {
                    // 0x95
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-7, rw_ops.size(), false, stack[stack.size()-7]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-7, rw_ops.size(), true, stack_next[stack_next.size()-7]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP7") {
                    // 0x96
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-8, rw_ops.size(), false, stack[stack.size()-8]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-8, rw_ops.size(), true, stack_next[stack_next.size()-8]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP8") {
                    // 0x97
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-9, rw_ops.size(), false, stack[stack.size()-9]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-9, rw_ops.size(), true, stack_next[stack_next.size()-9]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP9") {
                    // 0x98
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-10, rw_ops.size(), false, stack[stack.size()-10]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-10, rw_ops.size(), true, stack_next[stack_next.size()-10]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP10") {
                    // 0x99
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-11, rw_ops.size(), false, stack[stack.size()-11]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-11, rw_ops.size(), true, stack_next[stack_next.size()-11]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP11") {
                    // 0x9a
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-12, rw_ops.size(), false, stack[stack.size()-12]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-12, rw_ops.size(), true, stack_next[stack_next.size()-12]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP12") {
                    // 0x9b
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-13, rw_ops.size(), false, stack[stack.size()-13]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-13, rw_ops.size(), true, stack_next[stack_next.size()-13]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP13") {
                    // 0x9c
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-14, rw_ops.size(), false, stack[stack.size()-14]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-14, rw_ops.size(), true, stack_next[stack_next.size()-14]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP14") {
                    // 0x9d
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-15, rw_ops.size(), false, stack[stack.size()-15]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-15, rw_ops.size(), true, stack_next[stack_next.size()-15]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP15") {
                    // 0x9e
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-16, rw_ops.size(), false, stack[stack.size()-16]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-16, rw_ops.size(), true, stack_next[stack_next.size()-16]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SWAP16") {
                    // 0x9f
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-17, rw_ops.size(), false, stack[stack.size()-17]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-17, rw_ops.size(), true, stack_next[stack_next.size()-17]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "LOG0") {
                    // 0xa0
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "LOG1") {
                    // 0xa1
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "LOG2") {
                    // 0xa2
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "LOG3") {
                    // 0xa3
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "LOG4") {
                    // 0xa4
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-6, rw_ops.size(), false, stack[stack.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CREATE") {
                    // 0xf0
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CALL") {
                    // 0xf1
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-7, rw_ops.size(), false, stack[stack.size()-7]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-6, rw_ops.size(), false, stack[stack.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CALLCODE") {
                    // 0xf2
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-7, rw_ops.size(), false, stack[stack.size()-7]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-6, rw_ops.size(), false, stack[stack.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "RETURN") {
                    // 0xf3
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "DELEGATECALL") {
                    // 0xf4
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-6, rw_ops.size(), false, stack[stack.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "CREATE2") {
                    // 0xf5
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "STATICCALL") {
                    // 0xfa
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-6, rw_ops.size(), false, stack[stack.size()-6]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-5, rw_ops.size(), false, stack[stack.size()-5]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-4, rw_ops.size(), false, stack[stack.size()-4]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-3, rw_ops.size(), false, stack[stack.size()-3]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack_next.size()-1, rw_ops.size(), true, stack_next[stack_next.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "REVERT") {
                    // 0xfd
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-2, rw_ops.size(), false, stack[stack.size()-2]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else if(opcode == "SELFDESTRUCT") {
                    // 0xff
                    rw_ops.push_back(stack_operation(call_id,  stack.size()-1, rw_ops.size(), false, stack[stack.size()-1]));
                    std::cout << "\t" << rw_ops[rw_ops.size()-1] << std::endl;
                } else {
                    std::cout << "Unknown opcode " << std::hex << opcode << std::dec << std::endl;
                    BOOST_ASSERT(false);
                }
            }
        public:
            rw_trace(boost::property_tree::ptree const &pt, std::size_t rows_amount, std::size_t _call_id = 0){
                call_id = _call_id;

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

                rw_ops.push_back(start_operation());
                for( auto it = ptrace.begin(); it!=ptrace.end(); it++ ){
                    if(std::distance(it, ptrace.end()) == 1)
                        append_opcode(it->second.get_child("op").data(), stack, {}, memory, {}, storage, storage);
                    else{
                        stack_next = zkevm_word_vector_from_ptree(std::next(it)->second.get_child("stack"));
                        memory_next = byte_vector_from_ptree(std::next(it)->second.get_child("memory"));
                        storage_next = key_value_storage_from_ptree(it->second.get_child("storage"));
                        append_opcode(it->second.get_child("op").data(), stack, stack_next, memory, memory_next, storage, storage_next);
                    }
                    storage = storage_next;
                    stack = stack_next;
                    memory = memory_next;
                }
                std::sort(rw_ops.begin(), rw_ops.end(), [](rw_operation a, rw_operation b){
                    return a < b;
                });

                while( rw_ops.size() < rows_amount ) rw_ops.push_back(padding_operation());
            }
            const std::vector<rw_operation> &get_rw_ops() const{
                return rw_ops;
            }
        };
    } // namespace blueprint
} // namespace nil
