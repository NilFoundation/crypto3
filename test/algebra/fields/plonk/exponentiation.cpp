//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_exponentiation_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/exponentiation.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include "../../../test_plonk_component.hpp"

template <typename CurveType, std::size_t ExpSize>
void test_exponentiation(std::vector<typename CurveType::base_field_type::value_type> public_input,
    typename CurveType::base_field_type::value_type expected_res){
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    constexpr std::size_t exp_size = ExpSize;
	using BlueprintFieldType = typename CurveType::base_field_type;
    using BlueprintScalarType = typename CurveType::scalar_field_type;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;
	using component_type = nil::blueprint::components::exponentiation<ArithmetizationType, BlueprintFieldType, exp_size, 15>;

	using var = nil::crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    var base(0, 0, false, var::column_type::public_input);
    var exponent(0, 1, false, var::column_type::public_input);

    typename component_type::input_type instance_input = {base, exponent};

    auto result_check = [&expected_res](AssignmentType &assignment, 
	    typename component_type::result_type &real_res) {
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},{0},{});
	

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (component_instance, public_input, result_check, instance_input);



}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_exponentiation) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;
    
    typename BlueprintFieldType::value_type base_value = nil::crypto3::algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type exponent_value = 654;
    typename BlueprintFieldType::integral_type exponent_value_integral = typename BlueprintFieldType::integral_type(exponent_value.data);
    std::vector<typename BlueprintFieldType::value_type> public_input = {base_value, exponent_value};
    typename BlueprintFieldType::value_type expected_result = power(base_value, exponent_value_integral);

	test_exponentiation<curve_type, 11>(public_input, expected_result);
	
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "exponentiation_test: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_exponentiation_2) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;
    
    typename BlueprintFieldType::value_type base_value = nil::crypto3::algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type exponent_value = (BlueprintFieldType::value_type::modulus - 1) / 2;
    typename BlueprintFieldType::integral_type exponent_value_integral = typename BlueprintFieldType::integral_type(exponent_value.data);
    std::vector<typename BlueprintFieldType::value_type> public_input = {base_value, exponent_value};
    typename BlueprintFieldType::value_type expected_result = power(base_value, exponent_value_integral);

	test_exponentiation<curve_type, 255>(public_input, expected_result);
	
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "exponentiation_test: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()