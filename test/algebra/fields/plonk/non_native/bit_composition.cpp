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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_bit_composition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_composition.hpp>

#include <boost/random/mersenne_twister.hpp>

#include <numeric>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

using mode = blueprint::components::bit_composition_mode;

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount, mode Mode,
         bool CheckInput, bool CustomAssignments = false>
void test_bit_composition(const std::vector<typename BlueprintFieldType::value_type> &bits,
                          typename BlueprintFieldType::value_type expected_res,
                          std::map<std::pair<std::size_t, std::size_t>, typename BlueprintFieldType::value_type>
                                patches = {}){

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

    using component_type = blueprint::components::bit_composition<ArithmetizationType>;

    assert(bits.size() == BitsAmount);

    bool expected_to_pass = true;
    if (CheckInput) {
        expected_to_pass = std::accumulate(bits.begin(), bits.end(), true,
                [](bool acc, typename BlueprintFieldType::value_type b) {
                    return acc && (b == 0 || b == 1);
                }
        );
    }

    typename component_type::input_type instance_input;
    instance_input.bits.resize(BitsAmount);
    for (std::size_t i = 0; i < BitsAmount; i++) {
        instance_input.bits[i] = var(0, i, false, var::column_type::public_input);
    }

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0},
                                                       BitsAmount, CheckInput, Mode);
    // Sanity check.
    assert(BitsAmount + component_instance.padding_bits_amount() + component_instance.sum_bits_amount() ==
           WitnessColumns * component_instance.rows_amount);

    auto result_check = [&expected_res, expected_to_pass](AssignmentType &assignment,
                                                          typename component_type::result_type &real_res) {
        if (expected_to_pass) {
            assert(expected_res == var_value(assignment, real_res.output));
        }
    };

    if (!CustomAssignments) {
        if (expected_to_pass) {
            crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                component_instance, bits, result_check, instance_input,
                crypto3::detail::connectedness_check_type::STRONG, BitsAmount, CheckInput);
            crypto3::test_empty_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                component_instance, bits, result_check, instance_input,
                crypto3::detail::connectedness_check_type::STRONG, BitsAmount, CheckInput);
        } else {
            crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                component_instance, bits, result_check, instance_input,
                crypto3::detail::connectedness_check_type::STRONG, BitsAmount, CheckInput);
        }
    } else {
        auto custom_assignments = crypto3::generate_patched_assignments<BlueprintFieldType,
            ArithmetizationParams, component_type>(patches);
        crypto3::test_component_to_fail_custom_assignments<
            component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>
                (component_instance, bits, result_check,
                 custom_assignments, instance_input,
                 crypto3::detail::connectedness_check_type::STRONG, BitsAmount, CheckInput);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

constexpr static const std::size_t random_tests_amount = 10;

template<typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::uint32_t BitsAmount, mode Mode>
void calculate_expected_and_test_bit_composition(std::vector<typename BlueprintFieldType::value_type> &bits) {
    using value_type = typename BlueprintFieldType::value_type;

    assert(bits.size() == BitsAmount);

    value_type composed = 0;
    auto accumulator = [](value_type acc, value_type b) {
        return value_type(2 * acc + (b == 1 ? 1 : 0));
    };
    if (Mode == mode::LSB) {
        composed = std::accumulate(bits.rbegin(), bits.rend(), composed, accumulator);
    } else {
        composed = std::accumulate(bits.begin(), bits.end(), composed, accumulator);
    }

    test_bit_composition<BlueprintFieldType, WitnessesAmount, BitsAmount, Mode, true>(bits, composed);
    test_bit_composition<BlueprintFieldType, WitnessesAmount, BitsAmount, Mode, false>(bits, composed);
}

template<typename BlueprintFieldType, std::uint32_t BitsAmount>
std::vector<typename BlueprintFieldType::value_type> generate_random_bitstring(boost::random::mt19937 &rng) {
    std::vector<typename BlueprintFieldType::value_type> res(BitsAmount);
    for (std::size_t i = 0; i < BitsAmount; i++) {
        res[i] = rng() % 2 == 1 ? 1 : 0;
    }
    return res;
}

template<typename BlueprintFieldType, std::uint32_t WitnesesAmount, std::uint32_t BitsAmount>
void test_composition() {
    using value_type = typename BlueprintFieldType::value_type;
    boost::random::mt19937 rng;
    rng.seed(1337);

    std::vector<value_type> test_bits(BitsAmount, 0);

    calculate_expected_and_test_bit_composition<BlueprintFieldType, WitnesesAmount, BitsAmount, mode::MSB>(test_bits);
    calculate_expected_and_test_bit_composition<BlueprintFieldType, WitnesesAmount, BitsAmount, mode::LSB>(test_bits);

    for (std::size_t i = 0; i < BitsAmount; i++) {
        test_bits[i] = 1;
    }
    calculate_expected_and_test_bit_composition<BlueprintFieldType, WitnesesAmount, BitsAmount, mode::MSB>(test_bits);
    calculate_expected_and_test_bit_composition<BlueprintFieldType, WitnesesAmount, BitsAmount, mode::LSB>(test_bits);

    for (std::size_t j = 0; j < random_tests_amount; j++) {
        auto bits = generate_random_bitstring<BlueprintFieldType, BitsAmount>(rng);
        calculate_expected_and_test_bit_composition<BlueprintFieldType, WitnesesAmount, BitsAmount, mode::MSB>(bits);
        calculate_expected_and_test_bit_composition<BlueprintFieldType, WitnesesAmount, BitsAmount, mode::LSB>(bits);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_15_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 15, 1>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_15_8) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 15, 8>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_15_16) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 15, 16>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_15_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 15, 32>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_15_44) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 15, 44>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_15_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 15, 64>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_15_128) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 15, 128>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_15_253) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 15, 253>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_9_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 9, 1>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_9_8) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 9, 8>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_9_16) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 9, 16>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_9_26) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 9, 26>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_9_32) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 9, 32>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_9_64) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 9, 64>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_9_128) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 9, 128>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_test_9_253) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    test_composition<field_type, 9, 253>();
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bit_composition_oops_didnt_pass_bits) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    std::map<std::pair<std::size_t, std::size_t>, value_type> patches;
    for (std::size_t i = 0; i < 43; i++) {
        value_type expected_res = value_type(2).pow(i + 1);
        for (std::size_t j = 0; j < 3; j++) {
            for (std::size_t k = 0; k < 15; k++) {
                if (j == 2 && k == 14) {
                    patches[std::make_pair(j, k)] = expected_res;
                } else {
                    patches[std::make_pair(j, k)] = 0;
                }
            }
        }
        patches[std::make_pair(2 - (i + 1) / 15, (43 - i) % 15)] = 2;
        std::vector<value_type> input(43);
        std::fill(input.begin(), input.end(), 0);
        input[42 - i] = 2;
        test_bit_composition<field_type, 15, 43, mode::MSB, true, true>(input, expected_res, patches);
    }
}

BOOST_AUTO_TEST_SUITE_END()