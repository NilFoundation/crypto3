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
#include <nil/blueprint/components/hashes/sha2/plonk/sha256.hpp>
#include <nil/blueprint/component_stretcher.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, bool Stretched = false>
void test_sha256(std::vector<typename BlueprintFieldType::value_type> public_input, std::array<typename BlueprintFieldType::value_type, 2> expected_res){
    constexpr std::size_t WitnessColumns = 9 * (Stretched ? 2 : 1);
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 33;
    constexpr std::size_t SelectorColumns = 50;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::sha256<ArithmetizationType>;

    std::array<var, 4> input_state_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{0},{});

    typename component_type::input_type instance_input = {input_state_var};
    auto result_check = [expected_res](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
            assert(var_value(assignment, real_res.output[0]) == expected_res[0] && var_value(assignment, real_res.output[1]) == expected_res[1]);
    };

    // check computation
    auto output = component_type::calculate({public_input[0], public_input[1], public_input[2], public_input[3]});
    for (std::size_t i = 0; i < 2; i++) {
        assert(expected_res[i] == output[i]);
    }

    if constexpr (Stretched) {
        using stretched_component_type = blueprint::components::component_stretcher<
            BlueprintFieldType,
            component_type>;

        stretched_component_type stretched_instance(component_instance, WitnessColumns / 2, WitnessColumns);

        crypto3::test_component<stretched_component_type, BlueprintFieldType, hash_type, Lambda>(
            stretched_instance, desc, public_input, result_check, instance_input);
    } else {
        crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
            component_instance, desc, public_input, result_check, instance_input);
        crypto3::test_empty_component<component_type, BlueprintFieldType, hash_type, Lambda>(
            component_instance, desc, public_input, result_check, instance_input);
    }
}

template<typename BlueprintFieldType>
void test_sha256_with_stretching(std::vector<typename BlueprintFieldType::value_type> public_input,
                                 std::array<typename BlueprintFieldType::value_type, 2> expected_res) {
    test_sha256<BlueprintFieldType, false>(public_input, expected_res);
    //test_sha256<BlueprintFieldType, true>(public_input, expected_res);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_sha256_test0) {

    using BlueprintFieldType = typename crypto3::algebra::curves::pallas::base_field_type;

    typename BlueprintFieldType::value_type s = typename BlueprintFieldType::value_type(2).pow(126);

    test_sha256_with_stretching<BlueprintFieldType>(
        {s, s + 1, s + 2, s + 3},
        {0xf5790a69d0a3f69cb85d0b5a233405fb_cppui255, 0xa47050b703fce590fd6585dd02b175f8_cppui255});

    test_sha256_with_stretching<BlueprintFieldType>({
        0xf5a5fd42d16a20302798ef6ed309979b_cppui255, 0x43003d2320d9f0e8ea9831a92759fb4b_cppui255,
        0xdb56114e00fdd4c1f85c892bf35ac9a8_cppui255, 0x9289aaecb1ebd0a96cde606a748b5d71_cppui255},
     {0x42b052541dce45557d83d34634a45a56_cppui255,  0xd216d4375e5a9584f6445ce4e63324af_cppui255});
    test_sha256_with_stretching<BlueprintFieldType>({
        0xc78009fdf07fc56a11f122370658a353_cppui255, 0xaaa542ed63e44c4bc15ff4cd105ab33c_cppui255,
        0x536d98837f2dd165a55d5eeae9148595_cppui255, 0x4472d56f246df256bf3cae19352a123c_cppui255},
     {0x69113382140943e8205d01244f562096_cppui255, 0x4d5b92a1cb78bf9fe35ab0bbd2f1f8c2_cppui255});
    test_sha256_with_stretching<BlueprintFieldType>({
        0x9efde052aa15429fae05bad4d0b1d7c6_cppui255, 0x4da64d03d7a1854a588c2cb8430c0d30_cppui255,
        0xd88ddfeed400a8755596b21942c1497e_cppui255, 0x114c302e6118290f91e6772976041fa1_cppui255},
     {0x60a7f836b0b42a41d74143c1ae465c25_cppui255, 0xed04376190677ef7d589bd69bc4d79c8_cppui255});
    test_sha256_with_stretching<BlueprintFieldType>({
        0x87eb0ddba57e35f6d286673802a4af59_cppui255, 0x75e22506c7cf4c64bb6be5ee11527f2c_cppui255,
        0x26846476fd5fc54a5d43385167c95144_cppui255, 0xf2643f533cc85bb9d16b782f8d7db193_cppui255},
     {0x841510f2de07868d707940400d618c9e_cppui255, 0xeeb91d1bd77177f196a238e272cb9bc3_cppui255});
    test_sha256_with_stretching<BlueprintFieldType>({
        0x506d86582d252405b840018792cad2bf_cppui255, 0x1259f1ef5aa5f887e13cb2f0094f51e1_cppui255,
        0xffff0ad7e659772f9534c195c815efc4_cppui255, 0x14ef1e1daed4404c06385d11192e92b_cppui255},
     {0x88b8aa87277a142cbe3d58e7a85ced04_cppui255, 0x4fec5eb57f1828caf06b5fae9c8c67fd_cppui255});

    test_sha256_with_stretching<BlueprintFieldType>(
        {0xffffffffffffffff_cppui64, 0xffffffffffffffff_cppui64, 0xffffffffffffffff_cppui64, 0xffffffffffffffff_cppui64},
        {0xf58ac0f0665e3f1886f2eae35542987b_cppui255, 0x9d61cc98e5d3ed2a5a9d8e3b9b7d9f2f_cppui255});
    test_sha256_with_stretching<BlueprintFieldType>(
        {1, 1, 1, 1},
         {0x8e1caeb2418a07d7d88f710dccd882d5_cppui255, 0xb5772c88ae5ca4442ccc46c4518a3d3b_cppui255});
}

BOOST_AUTO_TEST_SUITE_END()