//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_poseidon_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk/assignment.hpp>
#include <nil/crypto3/zk/blueprint/plonk/circuit.hpp>
#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_poseidon_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_poseidon_test_case1) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using FieldType = BlueprintFieldType;

    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 11;

    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    using component_type =
        blueprint::components::poseidon<ArithmetizationType, FieldType, 15>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;
    constexpr std::size_t Lambda = 5;

    std::array<typename BlueprintFieldType::value_type, component_type::state_size> public_input = {0, 1, 1};
    std::array<var, component_type::state_size> input_state_var = {var(0, 0, false, var::column_type::public_input),
     var(0, 1, false, var::column_type::public_input), var(0, 2, false, var::column_type::public_input)};
    typename component_type::input_type instance_input = {input_state_var};

    std::array<typename BlueprintFieldType::value_type, component_type::state_size> expected_res = {
        0x294B71F8CF2C775369A3B0B8912E508790B0C64BDBE6A5C26F2C6B53767A47CB_cppui255,
        0x244E5FA0EE801AB3FCCAB47ED7F6EAB38126318F7BD2C414ADDBF62FCC30316A_cppui255,
        0x273C6EE50F9A2970162F5D4503596175C6D3FB4C0BF6C269BCD1DFEFB4F50D47_cppui255};
    std::cout << "Expected result: " << expected_res[0].data << " " << expected_res[1].data << " "
              << expected_res[2].data << std::endl;
    
    auto result_check = [&expected_res](AssignmentType &assignment, 
        component_type::result_type &real_res) {

        for (std::uint32_t i = 0; i < component_type::state_size; i++){
            assert(expected_res[i] == var_value(assignment, real_res.output_state[i]));
        }
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},{},{});

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_SUITE_END()