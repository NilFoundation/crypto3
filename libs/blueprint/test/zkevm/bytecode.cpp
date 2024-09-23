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

#define BOOST_TEST_MODULE blueprint_zkevm_bytecode_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/zkevm/bytecode.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include "../test_plonk_component.hpp"

using namespace nil;
using namespace nil::blueprint;

std::string bytecode_for = "0x60806040523480156100195760008061001661001f565b50505b5061008d565b632a2a7adb598160e01b8152600481016020815285602082015260005b8681101561005a57808601518160408401015260208101905061003c565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6103188061009c6000396000f3fe6080604052348015610019576000806100166100bb565b50505b50600436106100345760003560e01c806347b0b31c14610042575b60008061003f6100bb565b50505b61005c600480360381019061005791906101a3565b610072565b60405161006991906101f7565b60405180910390f35b60006001905060005b828110156100a457838261008f9190610212565b9150808061009c90610276565b91505061007b565b5080600081906100b2610129565b50505092915050565b632a2a7adb598160e01b8152600481016020815285602082015260005b868110156100f65780860151816040840101526020810190506100d8565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6322bd64c0598160e01b8152836004820152846024820152600081604483336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b60005b60408110156101895760008183015260208101905061016f565b505050565b60008135905061019d816102f8565b92915050565b600080604083850312156101bf576000806101bc6100bb565b50505b60006101cd8582860161018e565b92505060206101de8582860161018e565b9150509250929050565b6101f18161026c565b82525050565b600060208201905061020c60008301846101e8565b92915050565b600061021d8261026c565b91506102288361026c565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615610261576102606102bf565b5b828202905092915050565b6000819050919050565b60006102818261026c565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8214156102b4576102b36102bf565b5b600182019050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000006000526011600452602460006102f46100bb565b5050565b6103018161026c565b8114610315576000806103126100bb565b50505b5056";
std::string bytecode_addition = "0x60806040523480156100195760008061001661001f565b50505b5061008d565b632a2a7adb598160e01b8152600481016020815285602082015260005b8681101561005a57808601518160408401015260208101905061003c565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6102b38061009c6000396000f3fe6080604052348015610019576000806100166100a3565b50505b50600436106100345760003560e01c8063f080118c14610042575b60008061003f6100a3565b50505b61005c6004803603810190610057919061018b565b610072565b60405161006991906101df565b60405180910390f35b6000818361008091906101fa565b6000819061008c610111565b505050818361009b91906101fa565b905092915050565b632a2a7adb598160e01b8152600481016020815285602082015260005b868110156100de5780860151816040840101526020810190506100c0565b506020828760640184336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b505050565b6322bd64c0598160e01b8152836004820152846024820152600081604483336000905af158600e01573d6000803e3d6000fd5b3d6001141558600a015760016000f35b60005b604081101561017157600081830152602081019050610157565b505050565b60008135905061018581610293565b92915050565b600080604083850312156101a7576000806101a46100a3565b50505b60006101b585828601610176565b92505060206101c685828601610176565b9150509250929050565b6101d981610250565b82525050565b60006020820190506101f460008301846101d0565b92915050565b600061020582610250565b915061021083610250565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156102455761024461025a565b5b828201905092915050565b6000819050919050565b7f4e487b710000000000000000000000000000000000000000000000000000000060005260116004526024600061028f6100a3565b5050565b61029c81610250565b81146102b0576000806102ad6100a3565b50505b5056";

std::vector<std::uint8_t> hex_string_to_bytes(std::string const &hex_string) {
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 2; i < hex_string.size(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        bytes.push_back(std::stoi(byte_string, nullptr, 16));
    }
    return bytes;
}

template <typename BlueprintFieldType>
void test_zkevm_bytecode(
    const components::bytecode_input_type::data_type& bytecode_input,
    typename components::plonk_keccak_table<BlueprintFieldType>::input_type& keccak_input,
    std::size_t max_rows_amount,
    std::size_t max_keccak_blocks
){
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
    using CircuitType = circuit<ArithmetizationType>;
    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;
    using table_type = nil::blueprint::components::zkevm_bytecode_table<ArithmetizationType, BlueprintFieldType>;
    using component_type = nil::blueprint::components::zkevm_bytecode<ArithmetizationType, BlueprintFieldType>;

    value_type rlc_challenge = 7; //TODO:modify it
    constexpr std::size_t WitnessColumns = 10;

    AssignmentType assignment(WitnessColumns, 1, 7, 5); // witness, public input, constant, selectors
    CircuitType circuit;
    assignment.public_input(0, 0) = rlc_challenge;

    typename component_type::input_type input_obj(var(0, 0, false, var::column_type::public_input));
    keccak_input.rlc_challenge = var(0, 0, false, var::column_type::public_input);

    std::vector<std::uint32_t> witnesses(WitnessColumns);
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(
        witnesses, {}, {}, max_rows_amount, max_keccak_blocks
    );
    generate_circuit(component_instance, circuit, assignment, input_obj, 1);

    std::vector<size_t> lookup_columns_indices;
    for(std::size_t i = 0; i < assignment.constants_amount(); i++) {
        lookup_columns_indices.push_back(i);
    }

    zk::snark::pack_lookup_tables_horizontal(
        circuit.get_reserved_indices(),
        circuit.get_reserved_tables(),
        circuit.get_reserved_dynamic_tables(),
        circuit, assignment,
        lookup_columns_indices,
        3,
        assignment.rows_amount(),
        1000
    );

    input_obj.fill_bytecodes(bytecode_input);
    generate_basic_assignments(component_instance, assignment, input_obj, 1);

    // Keccak table may be filled after bytecode table, zkevm circuit, mpt table e t.c.
    input_obj.fill_dynamic_table_inputs(keccak_input);
    generate_dynamic_tables_assignments(component_instance, assignment, input_obj, 1);

    nil::crypto3::zk::snark::basic_padding(assignment);
    BOOST_ASSERT(is_satisfied(circuit, assignment) == true);
}

BOOST_AUTO_TEST_SUITE(blueprint_bytecode_input_test_suite)
BOOST_AUTO_TEST_CASE(input_test){
    nil::blueprint::components::bytecode_input_type input;
    input.new_bytecode(hex_string_to_bytes(bytecode_for));
    input.new_bytecode({hex_string_to_bytes(bytecode_addition), zkevm_word_type(0x1234ab000_cppui_modular257)});
    auto ind = input.new_bytecode();
    input.push_byte(ind, 0x60);
    input.push_byte(ind, 0x40);
    input.push_byte(ind, 0x60);
    input.push_byte(ind, 0x80);
    input.push_byte(ind, 0xf3);

    const auto &data = input.get_bytecodes();
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(blueprint_bn_test_suite)
    using field_type = nil::crypto3::algebra::curves::alt_bn128_254::base_field_type;
BOOST_AUTO_TEST_CASE(one_small_contract){
    nil::blueprint::components::bytecode_input_type input;
    input.new_bytecode(hex_string_to_bytes(bytecode_for));

    nil::blueprint::components::plonk_keccak_table<field_type>::input_type keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    keccak_input.new_buffer(hex_string_to_bytes("0x00ed"));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    test_zkevm_bytecode<field_type>(input.get_bytecodes(), keccak_input, 1000, 30);
}
BOOST_AUTO_TEST_CASE(two_small_contracts){
    nil::blueprint::components::bytecode_input_type input;
    input.new_bytecode(hex_string_to_bytes(bytecode_for));
    input.new_bytecode(hex_string_to_bytes(bytecode_addition));
    input.new_bytecode(hex_string_to_bytes(bytecode_addition));

    nil::blueprint::components::plonk_keccak_table<field_type>::input_type keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_addition));

    test_zkevm_bytecode<field_type>(input.get_bytecodes(), keccak_input, 2046, 30);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(blueprint_vesta_test_suite)
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
BOOST_AUTO_TEST_CASE(one_small_contract){
    nil::blueprint::components::bytecode_input_type input;
    input.new_bytecode(hex_string_to_bytes(bytecode_for));

    nil::blueprint::components::plonk_keccak_table<field_type>::input_type keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    keccak_input.new_buffer(hex_string_to_bytes("0x00ed"));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    test_zkevm_bytecode<field_type>(input.get_bytecodes(), keccak_input, 1000, 30);
}

BOOST_AUTO_TEST_CASE(two_small_contracts){
    nil::blueprint::components::bytecode_input_type input;
    input.new_bytecode(hex_string_to_bytes(bytecode_for));
    input.new_bytecode(hex_string_to_bytes(bytecode_addition));

    nil::blueprint::components::plonk_keccak_table<field_type>::input_type keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_addition));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa129870189274891702983470189234701829347123948710293874091872310192329140879210"));

    test_zkevm_bytecode<field_type>(input.get_bytecodes(), keccak_input, 2046, 30);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(blueprint_pallas_test_suite)
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
BOOST_AUTO_TEST_CASE(one_small_contract){
    nil::blueprint::components::bytecode_input_type input;
    input.new_bytecode(hex_string_to_bytes(bytecode_for));

    nil::blueprint::components::plonk_keccak_table<field_type>::input_type keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    keccak_input.new_buffer(hex_string_to_bytes("0x00ed"));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa"));
    test_zkevm_bytecode<field_type>(input.get_bytecodes(), keccak_input, 1000, 30);
}

BOOST_AUTO_TEST_CASE(two_small_contracts){
    nil::blueprint::components::bytecode_input_type input;
    input.new_bytecode(hex_string_to_bytes(bytecode_for));
    input.new_bytecode(hex_string_to_bytes(bytecode_addition));

    nil::blueprint::components::plonk_keccak_table<field_type>::input_type keccak_input;
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_for));
    keccak_input.new_buffer(hex_string_to_bytes(bytecode_addition));
    keccak_input.new_buffer(hex_string_to_bytes("0xffaa129870189274891702983470189234701829347123948710293874091872310192329140879210"));

    test_zkevm_bytecode<field_type>(input.get_bytecodes(), keccak_input, 2046, 30);
}
BOOST_AUTO_TEST_SUITE_END()