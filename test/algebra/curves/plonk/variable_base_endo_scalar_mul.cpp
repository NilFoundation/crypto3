//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/variable_base_endo_scalar_mul_15_wires.hpp>
#include "test_plonk_component.hpp"

#include "../../../profiling.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_base_endo_scalar_mul) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using component_type = zk::components::curve_element_variable_base_endo_scalar_mul<ArithmetizationType, curve_type,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    //curve_type::scalar_field_type::value_type b = algebra::random_element<BlueprintScalarType>();
    curve_type::scalar_field_type::value_type b = 2;
    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type T = algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();
    
    typename component_type::params_type assignment_params = {T,b};
    constexpr static const typename BlueprintFieldType::value_type endo  = component_type::endo;
    typename BlueprintFieldType::value_type endo_scalar = 0x244630A7EE5033DA383B3677B4C5CA94A3EBE4156FC4FA4E08B35974929CA2C5_cppui255;

    typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type testResult = endo_scalar * T;
    std::cout<<"Expected result for endo_scalar * T: "<<testResult.X.data<<" "<< testResult.Y.data<<std::endl;
    std::array<bool, curve_type::scalar_field_type::modulus_bits + 1> bits = {false};
    typename curve_type::scalar_field_type::integral_type integral_b = typename curve_type::scalar_field_type::integral_type(b.data);
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
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (assignment_params);
}

BOOST_AUTO_TEST_SUITE_END()