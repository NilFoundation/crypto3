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

template <typename BlueprintFieldType, std::size_t WitnessColumns>
void test_zkevm_bytecode(
    std::vector<std::vector<std::uint8_t>> bytecodes
){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 6;
    constexpr std::size_t SelectorColumns = 3;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 5;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::zkevm_bytecode<ArithmetizationType, BlueprintFieldType>;

    std::vector<std::vector<var>> bytecode_vars;
    std::size_t cur = 0;
    for (std::size_t i = 0; i < bytecodes.size(); i++) {
        std::vector<var> bytecode;
        bytecode.push_back(var(0, cur, false, var::column_type::public_input)); // length
        cur++;
        for (std::size_t j = 0; j < bytecodes[i].size(); j++, cur++) {
            bytecode.push_back(var(0, cur, false, var::column_type::public_input));
        }
        bytecode_vars.push_back(bytecode);
    }
    std::vector<std::pair<var, var>> bytecode_hash_vars;
    for( std::size_t i = 0; i < bytecodes.size(); i++, cur+=2){
        bytecode_hash_vars.push_back({var(0, cur, false, var::column_type::public_input), var(0, cur+1, false, var::column_type::public_input)});
    }
    var rlc_challenge_var = var(0, cur, false, var::column_type::public_input);
    typename component_type::input_type instance_input(bytecode_vars, bytecode_hash_vars, rlc_challenge_var);

    std::vector<value_type> public_input;
    cur = 0;
    for( std::size_t i = 0; i < bytecodes.size(); i++){
        public_input.push_back(bytecodes[i].size());
        cur++;
        for( std::size_t j = 0; j < bytecodes[i].size(); j++, cur++){
            public_input.push_back(bytecodes[i][j]);
        }
    }
    for( std::size_t i = 0; i < bytecodes.size(); i++){
        std::string hash = nil::crypto3::hash<nil::crypto3::hashes::keccak_1600<256>>(bytecodes[i].begin(), bytecodes[i].end());
        std::string str_hi = hash.substr(0, hash.size()-32);
        std::string str_lo = hash.substr(hash.size()-32, 32);
        value_type hash_hi;
        value_type hash_lo;
        for( std::size_t j = 0; j < str_hi.size(); j++ ){hash_hi *=16; hash_hi += str_hi[j] >= '0' && str_hi[j] <= '9'? str_hi[j] - '0' : str_hi[j] - 'a' + 10;}
        for( std::size_t j = 0; j < str_lo.size(); j++ ){hash_lo *=16; hash_lo += str_lo[j] >= '0' && str_lo[j] <= '9'? str_lo[j] - '0' : str_lo[j] - 'a' + 10;}
        public_input.push_back(hash_hi);
        public_input.push_back(hash_lo);
    }
    nil::crypto3::random::algebraic_engine<BlueprintFieldType> rnd(0);
    value_type rlc_challenge = rnd();
    public_input.push_back(rlc_challenge);

    auto result_check = [](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, 2046);
    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input,
         nil::blueprint::connectedness_check_type::type::NONE, 2046);
}

template <typename BlueprintFieldType, std::size_t WitnessColumns>
void test_zkevm_bytecode_dynamic_table(
    std::vector<std::vector<std::uint8_t>> bytecodes
){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 4;
    constexpr std::size_t SelectorColumns = 6;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 5;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::bytecode_table_tester<ArithmetizationType, BlueprintFieldType>;

    std::vector<std::vector<var>> bytecode_vars;
    std::size_t cur = 0;
    for (std::size_t i = 0; i < bytecodes.size(); i++) {
        std::vector<var> bytecode;
        bytecode.push_back(var(0, cur, false, var::column_type::public_input)); // length
        cur++;
        for (std::size_t j = 0; j < bytecodes[i].size(); j++, cur++) {
            bytecode.push_back(var(0, cur, false, var::column_type::public_input));
        }
        bytecode_vars.push_back(bytecode);
    }
    std::vector<std::pair<var, var>> bytecode_hash_vars;
    for( std::size_t i = 0; i < bytecodes.size(); i++, cur+=2){
        bytecode_hash_vars.push_back({var(0, cur, false, var::column_type::public_input), var(0, cur+1, false, var::column_type::public_input)});
    }
    typename component_type::input_type instance_input(bytecode_vars, bytecode_hash_vars);

    std::vector<value_type> public_input;
    cur = 0;
    for( std::size_t i = 0; i < bytecodes.size(); i++){
        public_input.push_back(bytecodes[i].size());
        cur++;
        for( std::size_t j = 0; j < bytecodes[i].size(); j++, cur++){
            public_input.push_back(bytecodes[i][j]);
        }
    }
    for( std::size_t i = 0; i < bytecodes.size(); i++){
        std::string hash = nil::crypto3::hash<nil::crypto3::hashes::keccak_1600<256>>(bytecodes[i].begin(), bytecodes[i].end());
        std::string str_hi = hash.substr(0, hash.size()-32);
        std::string str_lo = hash.substr(hash.size()-32, 32);
        value_type hash_hi;
        value_type hash_lo;
        for( std::size_t j = 0; j < str_hi.size(); j++ ){hash_hi *=16; hash_hi += str_hi[j] >= '0' && str_hi[j] <= '9'? str_hi[j] - '0' : str_hi[j] - 'a' + 10;}
        for( std::size_t j = 0; j < str_lo.size(); j++ ){hash_lo *=16; hash_lo += str_lo[j] >= '0' && str_lo[j] <= '9'? str_lo[j] - '0' : str_lo[j] - 'a' + 10;}
        public_input.push_back(hash_hi);
        public_input.push_back(hash_lo);
    }
    nil::crypto3::random::algebraic_engine<BlueprintFieldType> rnd(0);
    value_type rlc_challenge = rnd();
    public_input.push_back(rlc_challenge);

    auto result_check = [](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, 2046);
    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input,
         nil::blueprint::connectedness_check_type::type::NONE, 2046);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
BOOST_AUTO_TEST_CASE(one_small_contract){
    test_zkevm_bytecode<field_type, 14>({hex_string_to_bytes(bytecode_addition)});
}
BOOST_AUTO_TEST_CASE(two_small_contracts){
    test_zkevm_bytecode<field_type, 14>({hex_string_to_bytes(bytecode_addition), hex_string_to_bytes(bytecode_for)});
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(blueprint_plonk_pallas_test_suite)
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
BOOST_AUTO_TEST_CASE(one_small_contract){
    test_zkevm_bytecode<field_type, 14>({hex_string_to_bytes(bytecode_addition)});
}
BOOST_AUTO_TEST_CASE(two_small_contracts){
    test_zkevm_bytecode<field_type, 14>({hex_string_to_bytes(bytecode_addition), hex_string_to_bytes(bytecode_for)});
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(blueprint_plonk_bls_test_suite)
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
BOOST_AUTO_TEST_CASE(one_small_contract){
    test_zkevm_bytecode<field_type, 14>({hex_string_to_bytes(bytecode_addition)});
}
BOOST_AUTO_TEST_CASE(two_small_contracts){
    test_zkevm_bytecode<field_type, 14>({hex_string_to_bytes(bytecode_addition),hex_string_to_bytes(bytecode_for)});
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(dynamic_table_test_suite)
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
BOOST_AUTO_TEST_CASE(one_small_contract){
    test_zkevm_bytecode_dynamic_table<field_type, 14>({hex_string_to_bytes(bytecode_addition)});
}
BOOST_AUTO_TEST_CASE(two_small_contracts){
    test_zkevm_bytecode_dynamic_table<field_type, 14>({hex_string_to_bytes(bytecode_addition), hex_string_to_bytes(bytecode_for)});
}
BOOST_AUTO_TEST_SUITE_END()

