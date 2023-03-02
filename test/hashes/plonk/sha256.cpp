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

#define BOOST_TEST_MODULE plonk_sha256_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/hashes/sha256/plonk/sha256.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_sha256(std::vector<typename BlueprintFieldType::value_type> public_input){
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 5;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 12;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = blueprint::components::sha256<ArithmetizationType, 9>;

    std::array<var, 4> input_state_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{0},{});

    typename component_type::input_type instance_input = {input_state_var};
    auto result_check = [](AssignmentType &assignment, 
        typename component_type::result_type &real_res) {
            std::cout << std::hex << "real_res: " << var_value(assignment, real_res.output[0]).data << " " << var_value(assignment, real_res.output[1]).data << std::endl;
    };

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_sha256_test0) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    typename BlueprintFieldType::value_type s = typename BlueprintFieldType::value_type(2).pow(126);

    test_sha256<BlueprintFieldType>({s, s + 1, s + 2, s + 3});
    test_sha256<BlueprintFieldType>({0, 0, 0, 0});
    test_sha256<BlueprintFieldType>({0xffffffffffffffff_cppui64, 0xffffffffffffffff_cppui64, 0xffffffffffffffff_cppui64, 0xffffffffffffffff_cppui64});
    test_sha256<BlueprintFieldType>({1, 1, 1, 1});
}

BOOST_AUTO_TEST_SUITE_END()