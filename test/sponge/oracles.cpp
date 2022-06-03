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

#define BOOST_TEST_MODULE blueprint_plonk_unified_addition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/limbs.hpp>

#include "../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

// BOOST_AUTO_TEST_CASE(blueprint_plonk_from_limbs) {
//     auto start = std::chrono::high_resolution_clock::now();

//     using curve_type = algebra::curves::vesta;
//     using BlueprintFieldType = typename curve_type::scalar_field_type;
//     constexpr std::size_t WitnessColumns = 3;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 0;
//     constexpr std::size_t SelectorColumns = 1;
//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     using component_type = zk::components::from_limbs<ArithmetizationType, curve_type, 0, 1, 2>;
//     std::cout << component_type::rows_amount << '\n';

//     typename BlueprintFieldType::value_type x = 5;
//     typename BlueprintFieldType::value_type y = 12;
//     typename BlueprintFieldType::value_type expected_res = 0xC0000000000000005_cppui256;

//     typename component_type::params_type params = {
//         var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

//     std::vector<typename BlueprintFieldType::value_type> public_input = {x, y, expected_res};

//     auto result_check = [&expected_res](AssignmentType &assignment, 
//         component_type::result_type &real_res) {
//         assert(expected_res == assignment.var_value(real_res.result));
//     };

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

//     auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
//     std::cout << "multiplication: " << duration.count() << "ms" << std::endl;
// }

// BOOST_AUTO_TEST_CASE(blueprint_plonk_to_limbs_1) {
//     auto start = std::chrono::high_resolution_clock::now();

//     using curve_type = algebra::curves::pallas;
//     using BlueprintFieldType = typename curve_type::scalar_field_type;
//     constexpr std::size_t WitnessColumns = 5;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 0;
//     constexpr std::size_t SelectorColumns = 1;
//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     using component_type = zk::components::to_limbs<ArithmetizationType, curve_type, 0, 1, 2, 3, 4>;

//     typename BlueprintFieldType::value_type input = 0x1D42ED837696F2A777E7C1FF0436D46E96878B624ECDE039732E37AFCD409C88_cppui256;
//     typename BlueprintFieldType::value_type x0 = 0x732E37AFCD409C88_cppui256;
//     typename BlueprintFieldType::value_type x1 = 0x96878B624ECDE039_cppui256;
//     typename BlueprintFieldType::value_type x2 = 0x77E7C1FF0436D46E_cppui256;
//     typename BlueprintFieldType::value_type x3 = 0x1D42ED837696F2A7_cppui256;

//     std::vector<typename BlueprintFieldType::value_type> expected_res = {x0, x1, x2, x3};

//     typename component_type::params_type params = {var(0, 0, false, var::column_type::public_input)};

//     std::vector<typename BlueprintFieldType::value_type> public_input = {input, x0, x1, x2, x3};

//     auto result_check = [&expected_res](AssignmentType &assignment, 
//         component_type::result_type &real_res) {
//     	std::cout << "real_res: " << assignment.var_value(real_res.result[0]).data << ' ' << assignment.var_value(real_res.result[1]).data << ' ' << assignment.var_value(real_res.result[2]).data << ' ' << assignment.var_value(real_res.result[3]).data << '\n';
//     	std::cout << "expected_res: " << expected_res[0].data << ' ' << expected_res[1].data << ' ' << expected_res[2].data << ' ' << expected_res[3].data << '\n';
//     	for (int i = 0; i < 4; ++i) {
//     		std::cout << (expected_res[i] == assignment.var_value(real_res.result[i])) << '\n';
// 	   }
// 	   for (int i = 0; i < 4; ++i) {
//     		assert(expected_res[i] == assignment.var_value(real_res.result[i]));
// 	   }
//     };

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

//     auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
//     std::cout << "multiplication: " << duration.count() << "ms" << std::endl;
// }

BOOST_AUTO_TEST_CASE(blueprint_plonk_to_limbs_2) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 5;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = zk::components::to_limbs<ArithmetizationType, curve_type, 0, 1, 2, 3, 4>;

    typename BlueprintFieldType::value_type input = 0xE826DABA538B6DF0000000000000000FB812F513D0FCC04106CB4BD3F32FAD3_cppui256;
    typename BlueprintFieldType::value_type x0 = 0x106CB4BD3F32FAD3_cppui256;
    typename BlueprintFieldType::value_type x1 = 0xFB812F513D0FCC04_cppui256;
    typename BlueprintFieldType::value_type x2 = 0x0_cppui256;
    typename BlueprintFieldType::value_type x3 = 0xE826DABA538B6DF_cppui256;

    std::vector<typename BlueprintFieldType::value_type> expected_res = {x0, x1, x2, x3};

    typename component_type::params_type params = {var(0, 0, false, var::column_type::public_input)};

    std::vector<typename BlueprintFieldType::value_type> public_input = {input, x0, x1, x2, x3};

    auto result_check = [&expected_res](AssignmentType &assignment, 
        component_type::result_type &real_res) {
	   assert(expected_res[0] == assignment.var_value(real_res.result[0]));
	   assert(expected_res[1] == assignment.var_value(real_res.result[1]));
	   assert(expected_res[2] == assignment.var_value(real_res.result[2]));
	   assert(expected_res[3] == assignment.var_value(real_res.result[3]));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "multiplication: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
