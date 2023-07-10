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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_range_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/curve25519/base_field.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/range.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <../test/algebra/fields/plonk/non_native/chop_and_glue_non_native.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_field_range(std::vector<typename BlueprintFieldType::value_type> public_input,
                      bool expected_to_pass){
    
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::range<ArithmetizationType,
        typename crypto3::algebra::fields::curve25519_base_field, 9, blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::array<var, 4> input_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};

    typename component_type::input_type instance_input = {input_var};
    
    auto result_check = [public_input](AssignmentType &assignment, 
        typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "________________________________________________________________________\ninput: " << std::hex << std::endl; 
            for (int i = 0; i < 4; i++){
                std::cout << public_input[3-i].data << " ";
            }
            std::cout << std::endl;
            #endif
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});

    if (expected_to_pass) {
        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
    } else {
        crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_non_native_range_test0) {
    using non_native_field_type = typename crypto3::algebra::fields::curve25519_base_field;
    using field_type = crypto3::algebra::curves::pallas::base_field_type;

    test_field_range<typename crypto3::algebra::curves::pallas::base_field_type>(
        {455245345345345, 523553453454343, 68753453534534689, 54355345344544}, true);

    test_field_range<typename crypto3::algebra::curves::pallas::base_field_type>(
        create_public_input_1_value<field_type, non_native_field_type>(
            chop_non_native<field_type, non_native_field_type>(1)
        ), true);
    test_field_range<typename crypto3::algebra::curves::pallas::base_field_type>(
        create_public_input_1_value<field_type, non_native_field_type>(
            chop_non_native<field_type, non_native_field_type>(0)
        ), true);
    test_field_range<typename crypto3::algebra::curves::pallas::base_field_type>(
        create_public_input_1_value<field_type, non_native_field_type>(
            chop_non_native<field_type, non_native_field_type>(-1)
        ), true);

    nil::crypto3::random::algebraic_engine<non_native_field_type> rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    for (std::size_t i = 0; i < 10; i++) {
        test_field_range<field_type>(
            create_public_input_1_value<field_type, non_native_field_type>(
                chop_non_native<field_type, non_native_field_type>(rand())
            ), true);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_range_test_must_fail) {
    using non_native_field_type = typename crypto3::algebra::fields::curve25519_base_field;
    using field_type = crypto3::algebra::curves::pallas::base_field_type;

    test_field_range<typename crypto3::algebra::curves::pallas::base_field_type>( //ed25519 modulus
        {0x3ffffffffffffffed_cppui255, 0x3ffffffffffffffff_cppui255, 0x3ffffffffffffffff_cppui255, 0x1ffffffffffffff_cppui255}, false
    );

    test_field_range<typename crypto3::algebra::curves::pallas::base_field_type>(
        {0x3ffffffffffffffff_cppui255, 0x3ffffffffffffffff_cppui255, 0x3ffffffffffffffff_cppui255, 0x1ffffffffffffff_cppui255}, false
    );

}

BOOST_AUTO_TEST_SUITE_END()