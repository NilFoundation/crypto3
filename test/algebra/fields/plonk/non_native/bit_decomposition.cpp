//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_bit_decomposition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

using mode = blueprint::components::bit_composition_mode;

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount, mode Mode,
         bool CustomAssignments = false>
void test_bit_decomposition(typename BlueprintFieldType::value_type input,
                            std::vector<typename BlueprintFieldType::value_type> expected_res,
                            std::map<std::pair<std::size_t, std::size_t>, typename BlueprintFieldType::value_type>
                                patches = {}) {

    constexpr std::size_t WitnessColumns = WitnessesAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using value_type = typename BlueprintFieldType::value_type;

    using component_type = blueprint::components::bit_decomposition<ArithmetizationType>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    std::vector<value_type> public_input = {input};

    bool expected_to_pass = input < value_type(2).pow(BitsAmount);

    auto result_check = [&expected_res, input, expected_to_pass](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "input: " << std::hex << public_input[0].data << "\n";
            for (std::size_t i = 0; i < expected_res.size(); i++){
                std::cout << expected_res[i].data;
            }
            std::cout << std::endl;

            for (std::size_t i = 0; i < real_res.output.size(); i++){
                std::cout << var_value(assignment, real_res.output[i]).data;
            }
            std::cout << std::endl;
            #endif
            if (expected_to_pass) {
                for (std::size_t i = 0; i < real_res.output.size(); i++) {
                    assert(expected_res[i] == var_value(assignment, real_res.output[i]));
                }
            }
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, BitsAmount, Mode);

    assert(BitsAmount + component_instance.padding_bits_amount() + component_instance.sum_bits_amount() ==
           WitnessColumns * component_instance.rows_amount);

    if (!CustomAssignments) {
        if (expected_to_pass) {
            crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                component_instance, public_input, result_check, instance_input,
                crypto3::detail::connectedness_check_type::STRONG, BitsAmount);
        } else {
            crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                component_instance, public_input, result_check, instance_input,
                crypto3::detail::connectedness_check_type::STRONG, BitsAmount);
        }
    } else {
        auto custom_assignments = crypto3::generate_patched_assignments<BlueprintFieldType,
            ArithmetizationParams, component_type>(patches);
        crypto3::test_component_to_fail_custom_assignments<
            component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>
                (component_instance, public_input, result_check, custom_assignments, instance_input,
                 crypto3::detail::connectedness_check_type::STRONG, BitsAmount);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

constexpr static const std::size_t random_tests_amount = 10;

template<typename FieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount, mode Mode>
void calc_expected_and_test_bit_decomposition(typename FieldType::value_type input) {
    using value_type = typename FieldType::value_type;
    using integral_type = typename FieldType::integral_type;

    integral_type input_integral = integral_type(input.data);

    std::vector<value_type> expected_res = std::vector<value_type>(BitsAmount);
    for (std::size_t i = 0; i < BitsAmount; i++) {
        expected_res[Mode == bit_composition_mode::MSB ? BitsAmount - i - 1 : i] =
            ((input_integral >> i) & 0b1) == 1 ? value_type::one() : value_type::zero();
    }
    input = value_type(input_integral);
    test_bit_decomposition<FieldType, WitnessesAmount, BitsAmount, Mode>(input, expected_res);
}

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount>
void test_decomposition_specific_inputs() {
    using value_type = typename BlueprintFieldType::value_type;

    value_type max_elem = (typename BlueprintFieldType::integral_type(1) << BitsAmount) - 1;

    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::MSB>(1);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::MSB>(0);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::MSB>(-1);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::MSB>(45524);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::MSB>(max_elem);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::MSB>(max_elem + 1);

    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::LSB>(1);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::LSB>(0);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::LSB>(-1);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::LSB>(45524);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::LSB>(max_elem);
    calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::LSB>(max_elem + 1);
}

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount,
         std::size_t RandomTestsAmount>
void test_decomposition_random_inputs() {
    using generator_type = nil::crypto3::random::algebraic_engine<BlueprintFieldType>;
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    generator_type rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    value_type max_value = value_type(2).pow(BitsAmount);

    for (std::size_t j = 0; j < random_tests_amount; j++) {
        value_type random = rand();
        integral_type input_integral = integral_type(random.data);
        input_integral = input_integral & integral_type((max_value - 1).data);
        value_type input = value_type(input_integral);
        // Sanity check
        assert(input < max_value);

        calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::MSB>(input);
        calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::LSB>(input);
    }
}

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount,
         std::size_t RandomTestsAmount>
void test_decomposition_fail_random_inputs() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using generator_type = nil::crypto3::random::algebraic_engine<BlueprintFieldType>;
    generator_type rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    value_type max_value = value_type(2).pow(BitsAmount);
    integral_type restriction_modulus = BlueprintFieldType::modulus - integral_type(max_value.data);

    for (std::size_t j = 0; j < random_tests_amount; j++) {
        value_type random = rand();
        value_type input = max_value + (value_type(integral_type(random.data) % restriction_modulus));
        // Sanity check
        assert(input >= max_value);

        calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::MSB>(input);
        calc_expected_and_test_bit_decomposition<BlueprintFieldType, WitnessesAmount, BitsAmount, mode::LSB>(input);
    }
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t BitsAmount>
void test_decomposition() {
    test_decomposition_specific_inputs<BlueprintFieldType, WitnessesAmount, BitsAmount>();
    test_decomposition_random_inputs<BlueprintFieldType, WitnessesAmount, BitsAmount, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_15_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 15, 1>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_15_8) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 15, 8>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_15_16) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 15, 16>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_15_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 15, 32>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_15_44) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 15, 44>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_15_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 15, 64>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_15_128) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 15, 128>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_15_254) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 15, 254>();
}


BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_9_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 9, 1>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_9_8) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 9, 8>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_9_16) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 9, 16>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_9_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 9, 32>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_9_26) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 9, 26>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_9_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 9, 64>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_9_128) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 9, 128>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_pallas_9_254) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_decomposition<field_type, 9, 254>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_decomposition_test_oops_not_bits) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    std::map<std::pair<std::size_t, std::size_t>, value_type> patches;
    for (std::size_t i = 0; i < 43; i++) {
        value_type input = value_type(2).pow(i + 1);
        for (std::size_t j = 0; j < 3; j++) {
            for (std::size_t k = 0; k < 15; k++) {
                if (j == 2 && k == 14) {
                    patches[std::make_pair(j, k)] = input;
                } else {
                    patches[std::make_pair(j, k)] = 0;
                }
            }
        }
        patches[std::make_pair(2 - (i + 1) / 15, (43 - i) % 15)] = 2;
        std::vector<value_type> expected_result(43);
        std::fill(expected_result.begin(), expected_result.end(), 0);
        expected_result[42 - i] = 2;
        test_bit_decomposition<field_type, 15, 43, mode::MSB, true>(input, expected_result, patches);
    }
}

BOOST_AUTO_TEST_SUITE_END()