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

#define BOOST_TEST_MODULE blueprint_plonk_variable_base_endo_scalar_mul_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/variable_base_endo_scalar_mul_15_wires.hpp>
#include "test_plonk_component.hpp"

#include "../../../profiling.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_base_endo_scalar_mul) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    constexpr std::size_t Lambda = 40;
    using component_type = zk::components::curve_element_variable_base_endo_scalar_mul<ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    //curve_type::scalar_field_type::value_type b = algebra::random_element<BlueprintScalarType>();
    curve_type::scalar_field_type::value_type b = 2;
    typename curve_type::scalar_field_type::integral_type integral_b = typename curve_type::scalar_field_type::integral_type(b.data);
	BlueprintFieldType::value_type b_scalar = integral_b;
    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type T = algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();
    var T_X_var = {0, 1, false, var::column_type::public_input};
    var T_Y_var = {0, 2, false, var::column_type::public_input};
    var scalar_var = {0, 3, false, var::column_type::public_input};

    typename component_type::params_type assignment_params = {{T_X_var, T_Y_var},scalar_var};
    std::cout<<"random point: " << T.X.data << " " << T.Y.data <<std::endl;
    std::vector<typename BlueprintFieldType::value_type> public_input = {T.X, T.Y, b_scalar};

    constexpr static const typename BlueprintFieldType::value_type endo  = component_type::endo;
    typename BlueprintFieldType::value_type endo_scalar = 0x244630A7EE5033DA383B3677B4C5CA94A3EBE4156FC4FA4E08B35974929CA2C5_cppui255;

    typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type testResult = endo_scalar * T;
    std::cout<<"Expected result for endo_scalar * T: "<<testResult.X.data<<" "<< testResult.Y.data<<std::endl;
    std::array<bool, curve_type::scalar_field_type::modulus_bits + 1> bits = {false};
    for (std::size_t i = 0; i < 128; i++) {
        bits[128 - i - 1] = multiprecision::bit_test(integral_b, i);
    }
    typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type testQ;
    testQ.X = endo * T.X;
    testQ.Y = T.Y;
    typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type acc = T + (T + testQ) + testQ;
    for (std::size_t i = 0; i < 128; i = i + 2) {
        typename BlueprintFieldType::value_type b1 = bits[i];
        typename BlueprintFieldType::value_type b2 = bits[i + 1];
        if (b1 == 0){
        testQ.X = T.X;
        } else {
            testQ.X = endo * T.X;
        }
        if (b2 == 0) {
            testQ.Y = -T.Y;
        } else {
            testQ.Y = T.Y;
        }
        acc = acc + testQ + acc;
    }
    std::cout<<"Expected result: "<<acc.X.data<<" "<< acc.Y.data<<std::endl;

    auto result_check = [](AssignmentType &assignment,
        component_type::result_type &real_res) {
    };
    test_component<component_type, BlueprintFieldType, hash_type, Lambda> (assignment_params, public_input, result_check);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "base_endo_scalar_mul: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()