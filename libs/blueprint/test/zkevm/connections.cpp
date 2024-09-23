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

#define BOOST_TEST_MODULE zkevm_connections_test

#include <boost/test/unit_test.hpp>

//#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks64.hpp>
#include "nil/crypto3/algebra/fields/pallas/base_field.hpp"

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/zkevm/zkevm_circuit.hpp>
#include <nil/blueprint/zkevm/zkevm_table.hpp>
#include <nil/blueprint/zkevm/util/ptree.hpp>
#include "./opcode_tester.hpp"

using namespace nil::blueprint;
using namespace nil::crypto3::algebra;

// This is circuit connection test
// How it'll work.

// It will have Ethereum RPC trace, parse it and generate RW and EVM circuit
// We have bytecode -- so can generate bytecode circuit
// And then check connections

std::vector<std::uint8_t> hex_string_to_bytes(std::string const &hex_string) {
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 2; i < hex_string.size(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        bytes.push_back(std::stoi(byte_string, nullptr, 16));
    }
    return bytes;
}

zkevm_opcode  opcode_from_str(const std::string &str){
    if(str == "STOP")  return zkevm_opcode::STOP; else
    if(str == "ADD")  return zkevm_opcode::ADD; else
    if(str == "MUL")  return zkevm_opcode::MUL; else
    if(str == "SUB")  return zkevm_opcode::SUB; else
    if(str == "DIV")  return zkevm_opcode::DIV; else
    if(str == "SDIV")  return zkevm_opcode::SDIV; else
    if(str == "MOD")  return zkevm_opcode::MOD; else
    if(str == "SMOD")  return zkevm_opcode::SMOD; else
    if(str == "ADDMOD")  return zkevm_opcode::ADDMOD; else
    if(str == "MULMOD")  return zkevm_opcode::MULMOD; else
    if(str == "EXP")  return zkevm_opcode::EXP; else
    if(str == "SIGNEXTEND")  return zkevm_opcode::SIGNEXTEND; else
    if(str == "LT")  return zkevm_opcode::LT; else
    if(str == "GT")  return zkevm_opcode::GT; else
    if(str == "SLT")  return zkevm_opcode::SLT; else
    if(str == "SGT")  return zkevm_opcode::SGT; else
    if(str == "EQ")  return zkevm_opcode::EQ; else
    if(str == "ISZERO")  return zkevm_opcode::ISZERO; else
    if(str == "AND")  return zkevm_opcode::AND; else
    if(str == "OR")  return zkevm_opcode::OR; else
    if(str == "XOR")  return zkevm_opcode::XOR; else
    if(str == "NOT")  return zkevm_opcode::NOT; else
    if(str == "BYTE")  return zkevm_opcode::BYTE; else
    if(str == "SHL")  return zkevm_opcode::SHL; else
    if(str == "SHR")  return zkevm_opcode::SHR; else
    if(str == "SAR")  return zkevm_opcode::SAR; else
    if(str == "KECCAK256")  return zkevm_opcode::KECCAK256; else
    if(str == "ADDRESS")  return zkevm_opcode::ADDRESS; else
    if(str == "BALANCE")  return zkevm_opcode::BALANCE; else
    if(str == "ORIGIN")  return zkevm_opcode::ORIGIN; else
    if(str == "CALLER")  return zkevm_opcode::CALLER; else
    if(str == "CALLVALUE")  return zkevm_opcode::CALLVALUE; else
    if(str == "CALLDATALOAD")  return zkevm_opcode::CALLDATALOAD; else
    if(str == "CALLDATASIZE")  return zkevm_opcode::CALLDATASIZE; else
    if(str == "CALLDATACOPY")  return zkevm_opcode::CALLDATACOPY; else
    if(str == "CODESIZE")  return zkevm_opcode::CODESIZE; else
    if(str == "CODECOPY")  return zkevm_opcode::CODECOPY; else
    if(str == "GASPRICE")  return zkevm_opcode::GASPRICE; else
    if(str == "EXTCODESIZE")  return zkevm_opcode::EXTCODESIZE; else
    if(str == "EXTCODECOPY")  return zkevm_opcode::EXTCODECOPY; else
    if(str == "RETURNDATASIZE")  return zkevm_opcode::RETURNDATASIZE; else
    if(str == "RETURNDATACOPY")  return zkevm_opcode::RETURNDATACOPY; else
    if(str == "EXTCODEHASH")  return zkevm_opcode::EXTCODEHASH; else
    if(str == "BLOCKHASH")  return zkevm_opcode::BLOCKHASH; else
    if(str == "COINBASE")  return zkevm_opcode::COINBASE; else
    if(str == "TIMESTAMP")  return zkevm_opcode::TIMESTAMP; else
    if(str == "NUMBER")  return zkevm_opcode::NUMBER; else
    if(str == "PREVRANDAO")  return zkevm_opcode::PREVRANDAO; else
    if(str == "GASLIMIT")  return zkevm_opcode::GASLIMIT; else
    if(str == "CHAINID")  return zkevm_opcode::CHAINID; else
    if(str == "SELFBALANCE")  return zkevm_opcode::SELFBALANCE; else
    if(str == "BASEFEE")  return zkevm_opcode::BASEFEE; else
    if(str == "BLOBHASH")  return zkevm_opcode::BLOBHASH; else
    if(str == "BLOBBASEFEE")  return zkevm_opcode::BLOBBASEFEE; else
    if(str == "POP")  return zkevm_opcode::POP; else
    if(str == "MLOAD")  return zkevm_opcode::MLOAD; else
    if(str == "MSTORE")  return zkevm_opcode::MSTORE; else
    if(str == "MSTORE8")  return zkevm_opcode::MSTORE8; else
    if(str == "SLOAD")  return zkevm_opcode::SLOAD; else
    if(str == "SSTORE")  return zkevm_opcode::SSTORE; else
    if(str == "JUMP")  return zkevm_opcode::JUMP; else
    if(str == "JUMPI")  return zkevm_opcode::JUMPI; else
    if(str == "PC")  return zkevm_opcode::PC; else
    if(str == "MSIZE")  return zkevm_opcode::MSIZE; else
    if(str == "GAS")  return zkevm_opcode::GAS; else
    if(str == "JUMPDEST")  return zkevm_opcode::JUMPDEST; else
    if(str == "TLOAD")  return zkevm_opcode::TLOAD; else
    if(str == "TSTORE")  return zkevm_opcode::TSTORE; else
    if(str == "MCOPY")  return zkevm_opcode::JUMPDEST; else
    if(str == "PUSH0")  return zkevm_opcode::PUSH0; else
    if(str == "PUSH1")  return zkevm_opcode::PUSH1; else
    if(str == "PUSH2")  return zkevm_opcode::PUSH2; else
    if(str == "PUSH3")  return zkevm_opcode::PUSH3; else
    if(str == "PUSH4")  return zkevm_opcode::PUSH4; else
    if(str == "PUSH5")  return zkevm_opcode::PUSH5; else
    if(str == "PUSH6")  return zkevm_opcode::PUSH6; else
    if(str == "PUSH7")  return zkevm_opcode::PUSH7; else
    if(str == "PUSH8")  return zkevm_opcode::PUSH8; else
    if(str == "PUSH9")  return zkevm_opcode::PUSH9; else
    if(str == "PUSH10")  return zkevm_opcode::PUSH10; else
    if(str == "PUSH11")  return zkevm_opcode::PUSH11; else
    if(str == "PUSH12")  return zkevm_opcode::PUSH12; else
    if(str == "PUSH13")  return zkevm_opcode::PUSH13; else
    if(str == "PUSH14")  return zkevm_opcode::PUSH14; else
    if(str == "PUSH15")  return zkevm_opcode::PUSH15; else
    if(str == "PUSH16")  return zkevm_opcode::PUSH16; else
    if(str == "PUSH17")  return zkevm_opcode::PUSH17; else
    if(str == "PUSH18")  return zkevm_opcode::PUSH18; else
    if(str == "PUSH19")  return zkevm_opcode::PUSH19; else
    if(str == "PUSH20")  return zkevm_opcode::PUSH20; else
    if(str == "PUSH21")  return zkevm_opcode::PUSH21; else
    if(str == "PUSH22")  return zkevm_opcode::PUSH22; else
    if(str == "PUSH23")  return zkevm_opcode::PUSH23; else
    if(str == "PUSH24")  return zkevm_opcode::PUSH24; else
    if(str == "PUSH25")  return zkevm_opcode::PUSH25; else
    if(str == "PUSH26")  return zkevm_opcode::PUSH26; else
    if(str == "PUSH27")  return zkevm_opcode::PUSH27; else
    if(str == "PUSH28")  return zkevm_opcode::PUSH28; else
    if(str == "PUSH29")  return zkevm_opcode::PUSH29; else
    if(str == "PUSH30")  return zkevm_opcode::PUSH30; else
    if(str == "PUSH31")  return zkevm_opcode::PUSH31; else
    if(str == "PUSH32")  return zkevm_opcode::PUSH32; else
    if(str == "DUP1")  return zkevm_opcode::DUP1; else
    if(str == "DUP2")  return zkevm_opcode::DUP2; else
    if(str == "DUP3")  return zkevm_opcode::DUP3; else
    if(str == "DUP4")  return zkevm_opcode::DUP4; else
    if(str == "DUP5")  return zkevm_opcode::DUP5; else
    if(str == "DUP6")  return zkevm_opcode::DUP6; else
    if(str == "DUP7")  return zkevm_opcode::DUP7; else
    if(str == "DUP8")  return zkevm_opcode::DUP8; else
    if(str == "DUP9")  return zkevm_opcode::DUP9; else
    if(str == "DUP10")  return zkevm_opcode::DUP10; else
    if(str == "DUP11")  return zkevm_opcode::DUP11; else
    if(str == "DUP12")  return zkevm_opcode::DUP12; else
    if(str == "DUP13")  return zkevm_opcode::DUP13; else
    if(str == "DUP14")  return zkevm_opcode::DUP14; else
    if(str == "DUP15")  return zkevm_opcode::DUP15; else
    if(str == "DUP16")  return zkevm_opcode::DUP16; else
    if(str == "SWAP1")  return zkevm_opcode::SWAP1; else
    if(str == "SWAP2")  return zkevm_opcode::SWAP2; else
    if(str == "SWAP3")  return zkevm_opcode::SWAP3; else
    if(str == "SWAP4")  return zkevm_opcode::SWAP4; else
    if(str == "SWAP5")  return zkevm_opcode::SWAP5; else
    if(str == "SWAP6")  return zkevm_opcode::SWAP6; else
    if(str == "SWAP7")  return zkevm_opcode::SWAP7; else
    if(str == "SWAP8")  return zkevm_opcode::SWAP8; else
    if(str == "SWAP9")  return zkevm_opcode::SWAP9; else
    if(str == "SWAP10")  return zkevm_opcode::SWAP10; else
    if(str == "SWAP11")  return zkevm_opcode::SWAP11; else
    if(str == "SWAP12")  return zkevm_opcode::SWAP12; else
    if(str == "SWAP13")  return zkevm_opcode::SWAP13; else
    if(str == "SWAP14")  return zkevm_opcode::SWAP14; else
    if(str == "SWAP15")  return zkevm_opcode::SWAP15; else
    if(str == "SWAP16")  return zkevm_opcode::SWAP16; else
    if(str == "LOG0")  return zkevm_opcode::LOG0; else
    if(str == "LOG1")  return zkevm_opcode::LOG1; else
    if(str == "LOG2")  return zkevm_opcode::LOG2; else
    if(str == "LOG3")  return zkevm_opcode::LOG3; else
    if(str == "LOG4")  return zkevm_opcode::LOG4; else
    if(str == "CREATE")  return zkevm_opcode::CREATE; else
    if(str == "CALL")  return zkevm_opcode::CALL; else
    if(str == "CALLCODE")  return zkevm_opcode::CALLCODE; else
    if(str == "RETURN")  return zkevm_opcode::RETURN; else
    if(str == "DELEGATECALL")  return zkevm_opcode::DELEGATECALL; else
    if(str == "CREATE2")  return zkevm_opcode::CREATE2; else
    if(str == "STATICCALL")  return zkevm_opcode::STATICCALL; else
    if(str == "REVERT")  return zkevm_opcode::REVERT; else
    if(str == "INVALID")  return zkevm_opcode::INVALID; else
    if(str == "SELFDESTRUCT")  return zkevm_opcode::SELFDESTRUCT;
    // these are not real opcodes, they are for exception processing
    std::cout << "Unknown opcode " << str << std::endl;
    return zkevm_opcode::err0; // not enough static gas or incorrect stack size
}

template <typename BlueprintFieldType>
void test_zkevm(std::string path){
    std::ifstream ss;
    ss.open(path + "/trace0.json");
    boost::property_tree::ptree trace;
    boost::property_tree::read_json(ss, trace);
    ss.close();

    ss.open(path + "/contract0.json");
    boost::property_tree::ptree bytecode_json;
    boost::property_tree::read_json(ss, bytecode_json);
    std::vector<uint8_t> bytecode0 = hex_string_to_bytes(std::string(bytecode_json.get_child("bytecode").data().c_str()));
    ss.close();

    // using field_type = fields::goldilocks64;
    using field_type = BlueprintFieldType;
    using arithmetization_type = nil::crypto3::zk::snark::plonk_constraint_system<field_type>;
    using assignment_type = assignment<arithmetization_type>;
    using circuit_type = circuit<arithmetization_type>;
    using zkevm_machine_type = zkevm_machine_interface;
    assignment_type assignment(0, 0, 0, 0);
    circuit_type circuit;
    zkevm_circuit<field_type> evm_circuit(assignment, circuit, 499, 300);
    zkevm_table<field_type> evm_table(evm_circuit, assignment);

    zkevm_machine_type machine = get_empty_machine(zkevm_keccak_hash(bytecode0));

    // First constant column is for even rows.
    std::vector<size_t> lookup_columns_indices;
    std::cout << "Constants amount = " <<  assignment.constants_amount() << std::endl;
    for(std::size_t i = 1; i < assignment.constants_amount(); i++) {
        lookup_columns_indices.push_back(i);
    }

    nil::crypto3::zk::snark::pack_lookup_tables_horizontal(
        circuit.get_reserved_indices(),
        circuit.get_reserved_tables(),
        circuit.get_reserved_dynamic_tables(),
        circuit, assignment,
        lookup_columns_indices,
        3,
        assignment.rows_amount(),
        65536
    );

    boost::property_tree::ptree ptrace = trace.get_child("result.structLogs");
    std::cout << "PT = " << ptrace.size() << std::endl;

    std::vector<zkevm_word_type> stack = zkevm_word_vector_from_ptree(ptrace.begin()->second.get_child("stack"));
    std::vector<std::uint8_t> memory = byte_vector_from_ptree(ptrace.begin()->second.get_child("memory"));
    std::vector<std::uint8_t> memory_next;
    std::vector<zkevm_word_type> stack_next;
    std::map<zkevm_word_type, zkevm_word_type> storage = key_value_storage_from_ptree(ptrace.begin()->second.get_child("storage"));
    std::map<zkevm_word_type, zkevm_word_type> storage_next;

    for( auto it = ptrace.begin(); it!=ptrace.end(); it++){
        std::string opcode_str = it->second.get_child("op").data();
        if(std::distance(it, ptrace.end()) != 1){
            stack_next = zkevm_word_vector_from_ptree(std::next(it)->second.get_child("stack"));
            memory_next = byte_vector_from_ptree(std::next(it)->second.get_child("memory"));
            storage_next = key_value_storage_from_ptree(it->second.get_child("storage"));
        }
        machine.update_state(
            opcode_from_str(opcode_str),
            stack,
            memory,
            atoi(it->second.get_child("gas").data().c_str()),
            atoi(it->second.get_child("pc").data().c_str()),
            opcode_str.substr(0,4) == "PUSH"? stack_next[stack_next.size() - 1]: 0
        );
        evm_table.assign_opcode(machine);

        storage = storage_next;
        stack = stack_next;
        memory = memory_next;
    }

    typename zkevm_circuit<field_type>::bytecode_table_component::input_type bytecode_input;
    bytecode_input.new_bytecode(bytecode0);

    evm_table.finalize_test(bytecode_input);

//  std::ofstream myfile;
//    myfile.open("test_assignment.txt");
//    assignment.export_table(myfile);
//    myfile.close();

    // assignment.export_table(std::cout);
    // circuit.export_circuit(std::cout);
    nil::crypto3::zk::snark::basic_padding(assignment);
    BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
}

BOOST_AUTO_TEST_SUITE(zkevm_connections_test_suite)

BOOST_AUTO_TEST_CASE(zkevm_minimal_math_test) {
    test_zkevm<fields::pallas_base_field>("./libs/blueprint/test/zkevm/data/minimal_math");
}

BOOST_AUTO_TEST_SUITE_END()
