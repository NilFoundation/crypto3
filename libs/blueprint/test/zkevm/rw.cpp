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

#define BOOST_TEST_MODULE blueprint_zkevm_rw_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/zkevm/rw.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include "../test_plonk_component.hpp"


using namespace nil;

std::vector<std::uint8_t> hex_string_to_bytes(std::string const &hex_string) {
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 2; i < hex_string.size(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        bytes.push_back(std::stoi(byte_string, nullptr, 16));
    }
    return bytes;
}

template <typename BlueprintFieldType, std::size_t WitnessColumns>
void test_zkevm_rw(
    std::string path,
    std::size_t max_rw_size
){
    std::cout << "Read write circuit test with "<< WitnessColumns << " witnesses" << std::endl;
    std::cout << "path = " << path << std::endl;

    std::ifstream ss;
    ss.open(path);
    boost::property_tree::ptree pt;
    boost::property_tree::read_json(ss, pt);
    ss.close();

    nil::blueprint::rw_trace<BlueprintFieldType> rw_trace(pt, max_rw_size);

    constexpr std::size_t PublicInputColumns = 0;
    constexpr std::size_t ConstantColumns = 4;
    constexpr std::size_t SelectorColumns = 5;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::zkevm_rw<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input(rw_trace);

    auto result_check = [](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, max_rw_size);

    std::vector<value_type> public_input;
    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input,
         nil::blueprint::connectedness_check_type::type::NONE, max_rw_size);
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
BOOST_AUTO_TEST_CASE(small_storage_contract){
    test_zkevm_rw<field_type, 65>("./libs/blueprint/test/zkevm/data/small_stack_storage.json", 10000);
}

BOOST_AUTO_TEST_CASE(mstore8_contract){
    test_zkevm_rw<field_type, 65>("./libs/blueprint/test/zkevm/data/mstore8.json", 10000);
}

BOOST_AUTO_TEST_CASE(meminit_contract){
    test_zkevm_rw<field_type, 65>("./libs/blueprint/test/zkevm/data/mem_init.json", 10000);
}

BOOST_AUTO_TEST_CASE(calldatacopy_contract){
    test_zkevm_rw<field_type, 65>("./libs/blueprint/test/zkevm/data/calldatacopy.json", 10000);
}
BOOST_AUTO_TEST_SUITE_END()

/*
BOOST_AUTO_TEST_SUITE(blueprint_plonk_pallas_test_suite)
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
BOOST_AUTO_TEST_CASE(small_storage_contract){
    test_zkevm_rw<field_type, 65>("../libs/blueprint/test/zkevm/data/small_stack_storage.json");
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(blueprint_plonk_bls_test_suite)
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
BOOST_AUTO_TEST_CASE(small_storage_contract){
    test_zkevm_rw<field_type, 65>("../libs/blueprint/test/zkevm/data/small_stack_storage.json");
}
BOOST_AUTO_TEST_SUITE_END()
*/