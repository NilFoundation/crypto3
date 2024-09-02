//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include <iostream>

#include <boost/assert.hpp>
#include <boost/bimap.hpp>

namespace nil {
    namespace blueprint {
        #define ZKEVM_OPCODE_ENUM(X) \
            X(STOP) \
            X(ADD) \
            X(MUL) \
            X(SUB) \
            X(DIV) \
            X(SDIV) \
            X(MOD) \
            X(SMOD) \
            X(ADDMOD) \
            X(MULMOD) \
            X(EXP) \
            X(SIGNEXTEND) \
            X(LT) \
            X(GT) \
            X(SLT) \
            X(SGT) \
            X(EQ) \
            X(ISZERO) \
            X(AND) \
            X(OR) \
            X(XOR) \
            X(NOT) \
            X(BYTE) \
            X(SHL) \
            X(SHR) \
            X(SAR) \
            X(KECCAK256) \
            X(ADDRESS) \
            X(BALANCE) \
            X(ORIGIN) \
            X(CALLER) \
            X(CALLVALUE) \
            X(CALLDATALOAD) \
            X(CALLDATASIZE) \
            X(CALLDATACOPY) \
            X(CODESIZE) \
            X(CODECOPY) \
            X(GASPRICE) \
            X(EXTCODESIZE) \
            X(EXTCODECOPY) \
            X(RETURNDATASIZE) \
            X(RETURNDATACOPY) \
            X(EXTCODEHASH) \
            X(BLOCKHASH) \
            X(COINBASE) \
            X(TIMESTAMP) \
            X(NUMBER) \
            X(PREVRANDAO) \
            X(GASLIMIT) \
            X(CHAINID) \
            X(SELFBALANCE) \
            X(BASEFEE) \
            X(BLOBHASH) \
            X(BLOBBASEFEE) \
            X(POP) \
            X(MLOAD) \
            X(MSTORE) \
            X(MSTORE8) \
            X(SLOAD) \
            X(SSTORE) \
            X(JUMP) \
            X(JUMPI) \
            X(PC) \
            X(MSIZE) \
            X(GAS) \
            X(JUMPDEST) \
            X(TLOAD) \
            X(TSTORE) \
            X(MCOPY) \
            X(PUSH0) \
            X(PUSH1) \
            X(PUSH2) \
            X(PUSH3) \
            X(PUSH4) \
            X(PUSH5) \
            X(PUSH6) \
            X(PUSH7) \
            X(PUSH8) \
            X(PUSH9) \
            X(PUSH10) \
            X(PUSH11) \
            X(PUSH12) \
            X(PUSH13) \
            X(PUSH14) \
            X(PUSH15) \
            X(PUSH16) \
            X(PUSH17) \
            X(PUSH18) \
            X(PUSH19) \
            X(PUSH20) \
            X(PUSH21) \
            X(PUSH22) \
            X(PUSH23) \
            X(PUSH24) \
            X(PUSH25) \
            X(PUSH26) \
            X(PUSH27) \
            X(PUSH28) \
            X(PUSH29) \
            X(PUSH30) \
            X(PUSH31) \
            X(PUSH32) \
            X(DUP1) \
            X(DUP2) \
            X(DUP3) \
            X(DUP4) \
            X(DUP5) \
            X(DUP6) \
            X(DUP7) \
            X(DUP8) \
            X(DUP9) \
            X(DUP10) \
            X(DUP11) \
            X(DUP12) \
            X(DUP13) \
            X(DUP14) \
            X(DUP15) \
            X(DUP16) \
            X(SWAP1) \
            X(SWAP2) \
            X(SWAP3) \
            X(SWAP4) \
            X(SWAP5) \
            X(SWAP6) \
            X(SWAP7) \
            X(SWAP8) \
            X(SWAP9) \
            X(SWAP10) \
            X(SWAP11) \
            X(SWAP12) \
            X(SWAP13) \
            X(SWAP14) \
            X(SWAP15) \
            X(SWAP16) \
            X(LOG0) \
            X(LOG1) \
            X(LOG2) \
            X(LOG3) \
            X(LOG4) \
            X(CREATE) \
            X(CALL) \
            X(CALLCODE) \
            X(RETURN) \
            X(DELEGATECALL) \
            X(CREATE2) \
            X(STATICCALL) \
            X(REVERT) \
            X(INVALID) \
            X(SELFDESTRUCT) // ! please update LAST_ZKEVM_OPCODE below if changing this !

        enum zkevm_opcode {
            #define ENUM_DEF(name) name,
            ZKEVM_OPCODE_ENUM(ENUM_DEF)
            #undef ENUM_DEF
        };

        // singleton class to hold opcode to byte mapping
        struct opcodes_info {
        public:
            static const opcodes_info& instance() {
                static opcodes_info instance;
                return instance;
            }

            std::size_t get_opcode_value(const zkevm_opcode& opcode) const {
                auto it = opcode_to_byte_map.left.find(opcode);
                BOOST_ASSERT(it != opcode_to_byte_map.left.end());
                return it->second;
            }

            zkevm_opcode get_opcode_from_value(const std::size_t& value) const {
                auto it = opcode_to_byte_map.right.find(value);
                BOOST_ASSERT(it != opcode_to_byte_map.right.end());
                return it->second;
            }

            std::size_t get_opcodes_amount() const {
                return opcode_to_byte_map.size();
            }

            boost::bimap<boost::bimaps::set_of<zkevm_opcode>, boost::bimaps::set_of<std::size_t>>
                opcode_to_byte_map;
        private:
            opcodes_info() {
                opcode_to_byte_map.insert({zkevm_opcode::STOP, 0x00});
                opcode_to_byte_map.insert({zkevm_opcode::ADD, 0x01});
                opcode_to_byte_map.insert({zkevm_opcode::MUL, 0x02});
                opcode_to_byte_map.insert({zkevm_opcode::SUB, 0x03});
                opcode_to_byte_map.insert({zkevm_opcode::DIV, 0x04});
                opcode_to_byte_map.insert({zkevm_opcode::SDIV, 0x05});
                opcode_to_byte_map.insert({zkevm_opcode::MOD, 0x06});
                opcode_to_byte_map.insert({zkevm_opcode::SMOD, 0x07});
                opcode_to_byte_map.insert({zkevm_opcode::ADDMOD, 0x08});
                opcode_to_byte_map.insert({zkevm_opcode::MULMOD, 0x09});
                opcode_to_byte_map.insert({zkevm_opcode::EXP, 0x0a});
                opcode_to_byte_map.insert({zkevm_opcode::SIGNEXTEND, 0x0b});
                opcode_to_byte_map.insert({zkevm_opcode::LT, 0x10});
                opcode_to_byte_map.insert({zkevm_opcode::GT, 0x11});
                opcode_to_byte_map.insert({zkevm_opcode::SLT, 0x12});
                opcode_to_byte_map.insert({zkevm_opcode::SGT, 0x13});
                opcode_to_byte_map.insert({zkevm_opcode::EQ, 0x14});
                opcode_to_byte_map.insert({zkevm_opcode::ISZERO, 0x15});
                opcode_to_byte_map.insert({zkevm_opcode::AND, 0x16});
                opcode_to_byte_map.insert({zkevm_opcode::OR, 0x17});
                opcode_to_byte_map.insert({zkevm_opcode::XOR, 0x18});
                opcode_to_byte_map.insert({zkevm_opcode::NOT, 0x19});
                opcode_to_byte_map.insert({zkevm_opcode::BYTE, 0x1a});
                opcode_to_byte_map.insert({zkevm_opcode::SHL, 0x1b});
                opcode_to_byte_map.insert({zkevm_opcode::SHR, 0x1c});
                opcode_to_byte_map.insert({zkevm_opcode::SAR, 0x1d});
                opcode_to_byte_map.insert({zkevm_opcode::KECCAK256, 0x20});
                opcode_to_byte_map.insert({zkevm_opcode::ADDRESS, 0x30});
                opcode_to_byte_map.insert({zkevm_opcode::BALANCE, 0x31});
                opcode_to_byte_map.insert({zkevm_opcode::ORIGIN, 0x32});
                opcode_to_byte_map.insert({zkevm_opcode::CALLER, 0x33});
                opcode_to_byte_map.insert({zkevm_opcode::CALLVALUE, 0x34});
                opcode_to_byte_map.insert({zkevm_opcode::CALLDATALOAD, 0x35});
                opcode_to_byte_map.insert({zkevm_opcode::CALLDATASIZE, 0x36});
                opcode_to_byte_map.insert({zkevm_opcode::CALLDATACOPY, 0x37});
                opcode_to_byte_map.insert({zkevm_opcode::CODESIZE, 0x38});
                opcode_to_byte_map.insert({zkevm_opcode::CODECOPY, 0x39});
                opcode_to_byte_map.insert({zkevm_opcode::GASPRICE, 0x3a});
                opcode_to_byte_map.insert({zkevm_opcode::EXTCODESIZE, 0x3b});
                opcode_to_byte_map.insert({zkevm_opcode::EXTCODECOPY, 0x3c});
                opcode_to_byte_map.insert({zkevm_opcode::RETURNDATASIZE, 0x3d});
                opcode_to_byte_map.insert({zkevm_opcode::RETURNDATACOPY, 0x3e});
                opcode_to_byte_map.insert({zkevm_opcode::EXTCODEHASH, 0x3f});
                opcode_to_byte_map.insert({zkevm_opcode::BLOCKHASH, 0x40});
                opcode_to_byte_map.insert({zkevm_opcode::COINBASE, 0x41});
                opcode_to_byte_map.insert({zkevm_opcode::TIMESTAMP, 0x42});
                opcode_to_byte_map.insert({zkevm_opcode::NUMBER, 0x43});
                opcode_to_byte_map.insert({zkevm_opcode::PREVRANDAO, 0x44});
                opcode_to_byte_map.insert({zkevm_opcode::GASLIMIT, 0x45});
                opcode_to_byte_map.insert({zkevm_opcode::CHAINID, 0x46});
                opcode_to_byte_map.insert({zkevm_opcode::SELFBALANCE, 0x47});
                opcode_to_byte_map.insert({zkevm_opcode::BASEFEE, 0x48});
                opcode_to_byte_map.insert({zkevm_opcode::BLOBHASH, 0x49});
                opcode_to_byte_map.insert({zkevm_opcode::BLOBBASEFEE, 0x4a});
                opcode_to_byte_map.insert({zkevm_opcode::POP, 0x50});
                opcode_to_byte_map.insert({zkevm_opcode::MLOAD, 0x51});
                opcode_to_byte_map.insert({zkevm_opcode::MSTORE, 0x52});
                opcode_to_byte_map.insert({zkevm_opcode::MSTORE8, 0x53});
                opcode_to_byte_map.insert({zkevm_opcode::SLOAD, 0x54});
                opcode_to_byte_map.insert({zkevm_opcode::SSTORE, 0x55});
                opcode_to_byte_map.insert({zkevm_opcode::JUMP, 0x56});
                opcode_to_byte_map.insert({zkevm_opcode::JUMPI, 0x57});
                opcode_to_byte_map.insert({zkevm_opcode::PC, 0x58});
                opcode_to_byte_map.insert({zkevm_opcode::MSIZE, 0x59});
                opcode_to_byte_map.insert({zkevm_opcode::GAS, 0x5a});
                opcode_to_byte_map.insert({zkevm_opcode::JUMPDEST, 0x5b});
                opcode_to_byte_map.insert({zkevm_opcode::TLOAD, 0x5c});
                opcode_to_byte_map.insert({zkevm_opcode::TSTORE, 0x5d});
                opcode_to_byte_map.insert({zkevm_opcode::MCOPY, 0x5e});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH0, 0x5f});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH1, 0x60});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH2, 0x61});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH3, 0x62});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH4, 0x63});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH5, 0x64});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH6, 0x65});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH7, 0x66});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH8, 0x67});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH9, 0x68});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH10, 0x69});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH11, 0x6a});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH12, 0x6b});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH13, 0x6c});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH14, 0x6d});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH15, 0x6e});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH16, 0x6f});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH17, 0x70});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH18, 0x71});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH19, 0x72});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH20, 0x73});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH21, 0x74});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH22, 0x75});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH23, 0x76});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH24, 0x77});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH25, 0x78});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH26, 0x79});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH27, 0x7a});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH28, 0x7b});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH29, 0x7c});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH30, 0x7d});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH31, 0x7e});
                opcode_to_byte_map.insert({zkevm_opcode::PUSH32, 0x7f});
                opcode_to_byte_map.insert({zkevm_opcode::DUP1, 0x80});
                opcode_to_byte_map.insert({zkevm_opcode::DUP2, 0x81});
                opcode_to_byte_map.insert({zkevm_opcode::DUP3, 0x82});
                opcode_to_byte_map.insert({zkevm_opcode::DUP4, 0x83});
                opcode_to_byte_map.insert({zkevm_opcode::DUP5, 0x84});
                opcode_to_byte_map.insert({zkevm_opcode::DUP6, 0x85});
                opcode_to_byte_map.insert({zkevm_opcode::DUP7, 0x86});
                opcode_to_byte_map.insert({zkevm_opcode::DUP8, 0x87});
                opcode_to_byte_map.insert({zkevm_opcode::DUP9, 0x88});
                opcode_to_byte_map.insert({zkevm_opcode::DUP10, 0x89});
                opcode_to_byte_map.insert({zkevm_opcode::DUP11, 0x8a});
                opcode_to_byte_map.insert({zkevm_opcode::DUP12, 0x8b});
                opcode_to_byte_map.insert({zkevm_opcode::DUP13, 0x8c});
                opcode_to_byte_map.insert({zkevm_opcode::DUP14, 0x8d});
                opcode_to_byte_map.insert({zkevm_opcode::DUP15, 0x8e});
                opcode_to_byte_map.insert({zkevm_opcode::DUP16, 0x8f});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP1, 0x90});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP2, 0x91});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP3, 0x92});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP4, 0x93});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP5, 0x94});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP6, 0x95});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP7, 0x96});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP8, 0x97});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP9, 0x98});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP10, 0x99});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP11, 0x9a});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP12, 0x9b});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP13, 0x9c});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP14, 0x9d});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP15, 0x9e});
                opcode_to_byte_map.insert({zkevm_opcode::SWAP16, 0x9f});
                opcode_to_byte_map.insert({zkevm_opcode::LOG0, 0xa0});
                opcode_to_byte_map.insert({zkevm_opcode::LOG1, 0xa1});
                opcode_to_byte_map.insert({zkevm_opcode::LOG2, 0xa2});
                opcode_to_byte_map.insert({zkevm_opcode::LOG3, 0xa3});
                opcode_to_byte_map.insert({zkevm_opcode::LOG4, 0xa4});
                opcode_to_byte_map.insert({zkevm_opcode::CREATE, 0xf0});
                opcode_to_byte_map.insert({zkevm_opcode::CALL, 0xf1});
                opcode_to_byte_map.insert({zkevm_opcode::CALLCODE, 0xf2});
                opcode_to_byte_map.insert({zkevm_opcode::RETURN, 0xf3});
                opcode_to_byte_map.insert({zkevm_opcode::DELEGATECALL, 0xf4});
                opcode_to_byte_map.insert({zkevm_opcode::CREATE2, 0xf5});
                opcode_to_byte_map.insert({zkevm_opcode::STATICCALL, 0xfa});
                opcode_to_byte_map.insert({zkevm_opcode::REVERT, 0xfd});
                opcode_to_byte_map.insert({zkevm_opcode::INVALID, 0xfe});
                opcode_to_byte_map.insert({zkevm_opcode::SELFDESTRUCT, 0xff});
            }
        };

        std::string opcode_to_string(const zkevm_opcode& opcode) {
            switch (opcode) {
                #define ENUM_DEF(name) case zkevm_opcode::name: return #name;
                ZKEVM_OPCODE_ENUM(ENUM_DEF)
                #undef ENUM_DEF
            }
            return "unknown";
        }

        std::ostream& operator<<(std::ostream& os, const zkevm_opcode& opcode) {
            #define ENUM_DEF(name) case zkevm_opcode::name: os << #name; break;
            switch (opcode) {
                ZKEVM_OPCODE_ENUM(ENUM_DEF)
            }
            #undef ENUM_DEF
            return os;
        }
    }   // namespace blueprint
}   // namespace nil
