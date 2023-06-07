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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_bit_shift_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/bit_shift_constant.hpp>

#include "test_plonk_component.hpp"

using namespace nil;

using nil::blueprint::components::detail::bit_shift_mode;

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::size_t BitsAmount,
         std::uint32_t Shift, bit_shift_mode Mode>
void test_bit_shift(typename BlueprintFieldType::value_type input,
                    typename BlueprintFieldType::value_type expected_res){

    constexpr std::size_t WitnessColumns = WitnessesAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
    using value_type = typename BlueprintFieldType::value_type;

    using component_type = blueprint::components::bit_shift_constant<ArithmetizationType, WitnessesAmount>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    std::vector<value_type> public_input = {input};

    bool expected_to_pass = input < value_type(2).pow(BlueprintFieldType::modulus_bits - 1);

    auto result_check = [&expected_res, &public_input, expected_to_pass]
                        (AssignmentType &assignment, typename component_type::result_type &real_res) {
        if (expected_to_pass) {
            assert(var_value(assignment, real_res.output) == expected_res);
        }
    };

    component_type component_instance = WitnessesAmount == 15 ?
                                            component_type({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
                                                           {0}, {0}, BitsAmount, Shift, Mode)
                                          : component_type({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {0},
                                                           BitsAmount, Shift, Mode);

    if (!(WitnessesAmount == 15 || WitnessesAmount == 9)) {
        BOOST_ASSERT_MSG(false, "Please add support for WitnessesAmount that you passed here!") ;
    }

    if (expected_to_pass) {
        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input);
    } else {
        crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
            component_instance, public_input, result_check, instance_input);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

constexpr static const std::size_t random_tests_amount = 10;

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::size_t BitsAmount,
         std::uint32_t Shift, bit_shift_mode Mode>
void calculate_expected_and_test_bit_shift(typename BlueprintFieldType::value_type input) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    integral_type max = integral_type(1) << BitsAmount;
    integral_type input_integral = integral_type(input.data) % max;
    value_type expected_res = 0;

    if (Mode == bit_shift_mode::RIGHT) {
        expected_res = input_integral >> Shift;
    } else if (Mode == bit_shift_mode::LEFT) {
        expected_res = (input_integral << Shift) % max;
    }
    input = value_type(input_integral);
    test_bit_shift<BlueprintFieldType, WitnessesAmount, BitsAmount, Shift, Mode>(input, expected_res);
}

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::size_t BitsAmount,
         std::uint32_t Shift, bit_shift_mode Mode>
void test_shift_specific_inputs() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    value_type max_elem = value_type(integral_type(1) << (BlueprintFieldType::modulus_bits - 1) - 1);

    calculate_expected_and_test_bit_shift<BlueprintFieldType, WitnessesAmount, BitsAmount, Shift, Mode>(1);
    calculate_expected_and_test_bit_shift<BlueprintFieldType, WitnessesAmount, BitsAmount, Shift, Mode>(0);
    calculate_expected_and_test_bit_shift<BlueprintFieldType, WitnessesAmount, BitsAmount, Shift, Mode>(45524);
    calculate_expected_and_test_bit_shift<BlueprintFieldType, WitnessesAmount, BitsAmount, Shift, Mode>(max_elem);
    calculate_expected_and_test_bit_shift<BlueprintFieldType, WitnessesAmount, BitsAmount, Shift, Mode>(max_elem + 1);
}

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::size_t BitsAmount,
         std::uint32_t Shift, bit_shift_mode Mode>
void test_shift_random_input() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using generator_type = nil::crypto3::random::algebraic_engine<BlueprintFieldType>;
    generator_type rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    value_type max_value = value_type(2).pow(BitsAmount);

    for (std::size_t j = 0; j < random_tests_amount; j++) {
        value_type random = rand();
        integral_type input_integral = integral_type(random.data);
        input_integral = input_integral & integral_type((max_value - 1).data);
        value_type input = value_type(input_integral);

        calculate_expected_and_test_bit_shift<BlueprintFieldType, WitnessesAmount, BitsAmount, Shift, Mode>(input);
    }
}


template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::size_t BitsAmount,
         std::uint32_t Shift, bit_shift_mode Mode>
void test_shift() {
    test_shift_specific_inputs<BlueprintFieldType, WitnessesAmount, BitsAmount, Shift, Mode>();
    test_shift_random_input<BlueprintFieldType, WitnessesAmount, BitsAmount, Shift, Mode>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_254_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 1, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_254_8) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 8, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_254_16) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 16, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_254_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 32, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_254_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 64, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_254_128) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 128, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_254_253) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 253, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_9_254_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 1, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_9_254_8) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 8, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_9_254_16) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 16, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_9_254_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 32, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_9_254_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 64, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_9_254_128) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 128, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_9_254_253) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 253, bit_shift_mode::RIGHT>();
}


BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_254_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 1, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_254_8) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 8, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_254_16) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 16, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_254_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 32, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_254_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 64, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_254_128) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 128, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_254_253) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 253, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_9_254_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 1, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_9_254_8) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 8, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_9_254_16) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 16, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_9_254_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 32, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_9_254_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 64, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_9_254_128) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 128, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_9_254_253) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 9, 254, 253, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_128_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 32, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_128_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 64, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_right_test_15_128_17) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 128, bit_shift_mode::RIGHT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_128_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 32, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_128_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 64, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_left_test_15_128_17) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 128, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_shift_constant_test_zero_shift) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_shift<field_type, 15, 254, 0, bit_shift_mode::RIGHT>();
    test_shift<field_type, 15, 254, 0, bit_shift_mode::LEFT>();
}

BOOST_AUTO_TEST_SUITE_END()