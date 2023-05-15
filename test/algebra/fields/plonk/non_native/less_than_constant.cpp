//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_less_than_constant_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/less_than_constant.hpp>

#include "test_plonk_component.hpp"

template<typename BlueprintFieldType>
std::size_t clz(typename BlueprintFieldType::value_type value) {
    std::size_t count = 0;
    typename BlueprintFieldType::integral_type integral = typename BlueprintFieldType::integral_type(value.data);
    while (integral != 0) {
        integral >>= 1;
        ++count;
    }
    return count;
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R>
auto test_less_than_constant(typename BlueprintFieldType::value_type input,
                             typename BlueprintFieldType::value_type constant) {
    constexpr std::size_t WitnessColumns = WitnessesAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 4;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = nil::crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
    using value_type = typename BlueprintFieldType::value_type;
    using component_type = nil::blueprint::components::less_than_constant<ArithmetizationType, WitnessColumns, R>;

    var x(0, 0, false, var::column_type::public_input);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input};

    typename component_type::input_type instance_input = {x, constant};

    auto result_check = [](AssignmentType &assignment, typename component_type::result_type &real_res) {};

    const bool expected_to_pass = input < constant;

    if (WitnessesAmount == 15 && expected_to_pass) {
        component_type component_instance =
            component_type({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0}, {0});
        nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input);
    } else if (WitnessesAmount == 9 && expected_to_pass) {
        component_type component_instance = component_type({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {0});
        nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input);
    } else if (WitnessesAmount == 15 && !expected_to_pass) {
        component_type component_instance =
            component_type({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0}, {0});
        nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams,
                                             hash_type, Lambda>(
                                                component_instance, public_input, result_check, instance_input);
    } else if (WitnessesAmount == 9 && !expected_to_pass) {
        component_type component_instance = component_type({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {0});
        nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams,
                                             hash_type, Lambda>(
                                                component_instance, public_input, result_check, instance_input);
    } else {
        assert(false);
    }
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R>
void test_less_than_constant_specific_inputs(typename BlueprintFieldType::value_type constant) {
    using value_type = typename BlueprintFieldType::value_type;

    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(0, constant);
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(constant - 1, constant);
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(constant, constant);
    // Note that constant + 1 might not actually fit into R bits, but our component
    // should still fail in that case!
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(constant + 1, constant);
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(-1, constant);
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(-1, constant);
}

// Because R is required to be constexpr, we are unable to check for random constants.
template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R, std::size_t RandomTestsAmount>
void test_less_than_constant_random_inputs(typename BlueprintFieldType::value_type constant) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        value_type input = generate_random();
        if (input > constant) {
            input = -input;
        }
        test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(input, constant);
	}
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R, std::size_t RandomTestsAmount>
void test_less_than_constant_fail_random_inputs(typename BlueprintFieldType::value_type constant) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        value_type input = generate_random();
        if (input < constant) {
            input = -input;
        }
        test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(input, constant);
	}
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_fields_range_check_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_vesta_15) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;

    test_less_than_constant_specific_inputs<field_type, 15, 4>(field_type::value_type(12));

    value_type val_128 = 0xa2cc3863fba4e034145ab09cc77d428d_cppui255;
    assert(clz<field_type>(val_128) == 128);
    test_less_than_constant_specific_inputs<field_type, 15, 128>(val_128);
    test_less_than_constant_random_inputs<field_type, 15, 128, random_tests_amount>(val_128);
    test_less_than_constant_fail_random_inputs<field_type, 15, 128, random_tests_amount>(val_128);

    value_type val_251 = 0x04d4d799d43d91b4d09d9c2bfdc13a64b48d18750503324361f9bf7267ec9b92_cppui255;
    assert(clz<field_type>(val_251) == 251);
    test_less_than_constant_specific_inputs<field_type, 15, 251>(val_251);
    test_less_than_constant_random_inputs<field_type, 15, 251, random_tests_amount>(val_251);
    test_less_than_constant_fail_random_inputs<field_type, 15, 251, random_tests_amount>(val_251);

    value_type val_253 = 0x1a4b4d5cde54a974ea4e57ee4132d2ab2510c300f21930d6bbbf211d1add80f9_cppui255;
    assert(clz<field_type>(val_253) == 253);
    test_less_than_constant_specific_inputs<field_type, 15, 253>(val_253);
    test_less_than_constant_random_inputs<field_type, 15, 253, random_tests_amount>(val_253);
    test_less_than_constant_fail_random_inputs<field_type, 15, 253, random_tests_amount>(val_253);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_vesta_9) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;

    test_less_than_constant_specific_inputs<field_type, 9, 4>(field_type::value_type(12));

    value_type val_33 = 0x1902f2819_cppui253;
    assert(clz<field_type>(val_33) == 33);
    test_less_than_constant_specific_inputs<field_type, 9, 33>(val_33);
    test_less_than_constant_random_inputs<field_type, 9, 33, random_tests_amount>(val_33);
    test_less_than_constant_fail_random_inputs<field_type, 9, 33, random_tests_amount>(val_33);

    value_type val_64 = 0xd45ab09cc77d428d_cppui255;
    assert(clz<field_type>(val_64) == 64);
    test_less_than_constant_specific_inputs<field_type, 9, 64>(val_64);
    test_less_than_constant_random_inputs<field_type, 9, 64, random_tests_amount>(val_64);
    test_less_than_constant_fail_random_inputs<field_type, 9, 64, random_tests_amount>(val_64);

    value_type val_253 = 0x1a4b4d5cde54a974ea4e57ee4132d2ab2510c300f21930d6bbbf211d1add80f9_cppui255;
    assert(clz<field_type>(val_253) == 253);
    test_less_than_constant_specific_inputs<field_type, 9, 253>(val_253);
    test_less_than_constant_random_inputs<field_type, 9, 253, random_tests_amount>(val_253);
    test_less_than_constant_fail_random_inputs<field_type, 9, 253, random_tests_amount>(val_253);
}

BOOST_AUTO_TEST_SUITE_END()
