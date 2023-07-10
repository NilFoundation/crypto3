//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_auxiliary_sponge_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <../test/verifiers/kimchi/sponge/aux_sponge.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_sponge_0) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 15;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_squeezes = 1;
    using component_type = zk::components::aux<num_squeezes, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input;
    var zero(0, 0, false, var::column_type::public_input);
    typename component_type::params_type params = {input, zero};
    std::vector<typename BlueprintFieldType::value_type> public_input = {0};
    typename BlueprintFieldType::value_type result = 0x2FADBE2852044D028597455BC2ABBD1BC873AF205DFABB8A304600F3E09EEBA8_cppui256;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi sponge: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_sponge_1) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 15;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_squeezes = 1;
    using component_type = zk::components::aux<num_squeezes, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input = {{0, 1, false, var::column_type::public_input}};
    var zero(0, 0, false, var::column_type::public_input);
    typename component_type::params_type params = {input, zero};

    std::vector<typename BlueprintFieldType::value_type> public_input = {0, 0x36FB00AD544E073B92B4E700D9C49DE6FC93536CAE0C612C18FBE5F6D8E8EEF2_cppui256};

    typename BlueprintFieldType::value_type result = 0x3D4F050775295C04619E72176746AD1290D391D73FF4955933F9075CF69259FB_cppui256;
    std::cout<<"Result: "<<result.data<<std::endl;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi sponge: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_sponge_2) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 15;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_squeezes = 1;
    using component_type = zk::components::aux<num_squeezes, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input = {{0, 1, false, var::column_type::public_input}, {0, 2, false, var::column_type::public_input}};
    var zero(0, 0, false, var::column_type::public_input);
    typename component_type::params_type params = {input, zero};

    std::vector<typename BlueprintFieldType::value_type> public_input = {0, 0x3793E30AC691700012BAF26BB813D6D70BD379BEED8050A1DEEE3C188F1C3FBD_cppui256,
                                                                        0x2FC4C98E50E0B1AAE6ECB468E28C0B7D80A7E0EEC7136DB0BA0677B84AF0E465_cppui256};

    typename BlueprintFieldType::value_type result = 0x336C73D08AD408CEB7D1264867096F0817A1D0558B313312A1207602F23624FE_cppui256;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi sponge: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_sponge_3) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 15;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_squeezes = 1;
    using component_type = zk::components::aux<num_squeezes, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input = {{0, 1, false, var::column_type::public_input}, 
        {0, 2, false, var::column_type::public_input}, {0, 3, false, var::column_type::public_input}};
    var zero(0, 0, false, var::column_type::public_input);
    typename component_type::params_type params = {input, zero};

    std::vector<typename BlueprintFieldType::value_type> public_input = {0, 0x0024FB5773CAC987CF3A17DDD6134BA12D3E1CA4F6C43D3695347747CE61EAF5_cppui256,
                                                                        0x18E0ED2B46ED1EC258DF721A1D3145B0AA6ABDD02EE851A14B8B659CF47385F2_cppui256,
                                                                        0x1A842A688E600F012637FE181292F70C4347B5AE0D9EA9CE7CF18592C345CF73_cppui256};

    typename BlueprintFieldType::value_type result = 0x3F4B0EABB64E025F920457AF8D090A9F6472CAE11F3D62A749AF544A44941B9B_cppui256;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi sponge: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_sponge_4) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 15;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_squeezes = 1;
    using component_type = zk::components::aux<num_squeezes, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input = {{0, 1, false, var::column_type::public_input}, 
        {0, 2, false, var::column_type::public_input}, {0, 3, false, var::column_type::public_input}, {0, 4, false, var::column_type::public_input}};
    var zero(0, 0, false, var::column_type::public_input);
    typename component_type::params_type params = {input, zero};

    std::vector<typename BlueprintFieldType::value_type> public_input = {0, 0x2059462D60621F70620EA697FA1382EC5553A3DADB3CF9072201E09871B8284C_cppui256,
                                                                        0x2747337D1C4F9894747074C771E8EC7F570640E5D0CAF30FDDC446C00FA48707_cppui256,
                                                                        0x2DD5047C3EEEF37930E8FA4AD9691B27CF86D3ED39D4DEC4FC6D4E8EE4FF0415_cppui256,
                                                                        0x12C387C69BDD436F65AB607A4ED7C62714872EDBF800518B58E76F5106650B29_cppui256};

    typename BlueprintFieldType::value_type result = 0x165A8CECF6660C6E0054CB9B4DBA9D68047166D7F3CED2F8DC86ED2EBFD3EC47_cppui256;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi sponge: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_sponge_5) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 15;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr size_t num_squeezes = 1;
    using component_type = zk::components::aux<num_squeezes, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input = {{0, 1, false, var::column_type::public_input}, 
        {0, 2, false, var::column_type::public_input}, {0, 3, false, var::column_type::public_input}, {0, 4, false, var::column_type::public_input},
        {0, 5, false, var::column_type::public_input}};
    var zero(0, 0, false, var::column_type::public_input);
    typename component_type::params_type params = {input, zero};

    std::vector<typename BlueprintFieldType::value_type> public_input = {0, 0x3CF70C3A89749A45DB5236B8DE167A37762526C45270138A9FCDF2352B1899DA_cppui256,
                                                                        0x1BDF55BC84C1A0E0F7F6834949FCF90279B9D21C17DBC9928202C49039570598_cppui256,
                                                                        0x09441E95A82199EFC390152C5039C0D0566A90B7F6D1AA5813B2DAB90110FF90_cppui256,
                                                                        0x375B4A9785503C24531723DB1F31B50B79C3D1EC9F95DB7645A3EDA03862B588_cppui256,
                                                                        0x12688FE351ED01F3BB2EB6B0FA2A70FB232654F32B08990DC3A411E527776A89_cppui256};

    typename BlueprintFieldType::value_type result = 0x0CA2C3342C2959D7CD94B5C9D4DC55900F5F60B345F714827C8B907752D5A209_cppui256;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi sponge: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_sponge_double_squeeze) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 15;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;

    constexpr static const size_t num_squeezes = 2;
    using component_type = zk::components::aux<num_squeezes, ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    
    std::vector<var> input;
    var zero(0, 0, false, var::column_type::public_input);
    typename component_type::params_type params = {input, zero};

    std::vector<typename BlueprintFieldType::value_type> public_input;

    typename BlueprintFieldType::value_type result = 0x160A4D666FF9427DC907A5358B16C6966EB386213CE7994F87C8970F7DB8CDC3_cppui256;
    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.squeezed));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "kimchi sponge: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
