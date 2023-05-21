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
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
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

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R, bool CustomAssignments = false >
auto test_less_than_constant(typename BlueprintFieldType::value_type input,
                             typename BlueprintFieldType::value_type constant,
                             const std::map<std::pair<std::size_t, std::size_t>,
                                            typename BlueprintFieldType::value_type>
                                &patches = {}) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<
        WitnessesAmount, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = nil::crypto3::zk::snark::plonk_variable<BlueprintFieldType>;
    using value_type = typename BlueprintFieldType::value_type;
    using component_type = nil::blueprint::components::less_than_constant<ArithmetizationType, WitnessesAmount, R>;

    var x(0, 0, false, var::column_type::public_input);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input};

    typename component_type::input_type instance_input = {x, constant};

    auto result_check = [](AssignmentType &assignment, typename component_type::result_type &real_res) {};

    const bool expected_to_pass = input < constant;

    component_type component_instance = WitnessesAmount == 15 ?
                                            component_type({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0}, {0})
                                          : component_type({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {0});

    if (!(WitnessesAmount == 15 || WitnessesAmount == 9)) {
        BOOST_ASSERT_MSG(false, "Please add support for WitnessesAmount that you passed here!") ;
    }

    if (!CustomAssignments) {
        if (expected_to_pass) {
            nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                boost::get<component_type>(component_instance), public_input, result_check, instance_input);
        } else {
            nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams,
                                                 hash_type, Lambda>(
                                                    boost::get<component_type>(component_instance), public_input, result_check, instance_input);
        }
    } else {
        auto custom_assignment = nil::crypto3::generate_patched_assignments<
             BlueprintFieldType, ArithmetizationParams, component_type>(patches);

        if (expected_to_pass) {
            nil::crypto3::test_component_custom_assignments<component_type, BlueprintFieldType, ArithmetizationParams,
                    hash_type, Lambda>(
                        boost::get<component_type>(component_instance), public_input,
                        result_check, custom_assignment, instance_input);
        } else {
            nil::crypto3::test_component_to_fail_custom_assignments<component_type, BlueprintFieldType,
                    ArithmetizationParams, hash_type, Lambda>(
                            boost::get<component_type>(component_instance), public_input, result_check,
                            custom_assignment, instance_input);
        }
    }
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R>
void test_less_than_constant_specific_inputs(typename BlueprintFieldType::value_type constant) {
    using value_type = typename BlueprintFieldType::value_type;

    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(0, constant);
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(constant - 1, constant);
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(constant, constant);
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(constant + 1, constant);
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(-1, constant);
    test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(constant - value_type(2).pow(R) + 1, constant);
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
        input = value_type(integral_type(input.data) % integral_type(constant.data));
        // Sanity check.
        assert(input <= constant);
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

    integral_type restriction_modulus = BlueprintFieldType::modulus - integral_type(constant.data);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        value_type input = generate_random();
        input = constant + (value_type(integral_type(input.data) % restriction_modulus));
        // Sanity check
        assert(input >= constant);
        test_less_than_constant<BlueprintFieldType, WitnessesAmount, R>(input, constant);
	}
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_vesta_15_4) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_4 = 12;
    assert(clz<field_type>(val_4) == 4);
    test_less_than_constant_specific_inputs<field_type, 15, 4>(val_4);
    test_less_than_constant_random_inputs<field_type, 15, 4, random_tests_amount>(val_4);
    test_less_than_constant_fail_random_inputs<field_type, 15, 4, random_tests_amount>(val_4);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_vesta_15_128) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_128 = 0xa2cc3863fba4e034145ab09cc77d428d_cppui255;
    assert(clz<field_type>(val_128) == 128);
    test_less_than_constant_specific_inputs<field_type, 15, 128>(val_128);
    test_less_than_constant_random_inputs<field_type, 15, 128, random_tests_amount>(val_128);
    test_less_than_constant_fail_random_inputs<field_type, 15, 128, random_tests_amount>(val_128);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_pallas_15_251) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_251 = 0x04d4d799d43d91b4d09d9c2bfdc13a64b48d18750503324361f9bf7267ec9b92_cppui255;
    assert(clz<field_type>(val_251) == 251);
    test_less_than_constant_specific_inputs<field_type, 15, 251>(val_251);
    test_less_than_constant_random_inputs<field_type, 15, 251, random_tests_amount>(val_251);
    test_less_than_constant_fail_random_inputs<field_type, 15, 251, random_tests_amount>(val_251);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_vesta_15_253) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_253 = 0x1a4b4d5cde54a974ea4e57ee4132d2ab2510c300f21930d6bbbf211d1add80f9_cppui255;
    assert(clz<field_type>(val_253) == 253);
    test_less_than_constant_specific_inputs<field_type, 15, 253>(val_253);
    test_less_than_constant_random_inputs<field_type, 15, 253, random_tests_amount>(val_253);
    test_less_than_constant_fail_random_inputs<field_type, 15, 253, random_tests_amount>(val_253);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_vesta_9_4) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_4 = 12;
    assert(clz<field_type>(val_4) == 4);
    test_less_than_constant_specific_inputs<field_type, 9, 4>(val_4);
    test_less_than_constant_random_inputs<field_type, 9, 4, random_tests_amount>(val_4);
    test_less_than_constant_fail_random_inputs<field_type, 9, 4, random_tests_amount>(val_4);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_pallas_9_32) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_32 = 0x0902f2819_cppui253;
    assert(clz<field_type>(val_32) == 32);
    test_less_than_constant_specific_inputs<field_type, 9, 32>(val_32);
    test_less_than_constant_random_inputs<field_type, 9, 32, random_tests_amount>(val_32);
    test_less_than_constant_fail_random_inputs<field_type, 9, 32, random_tests_amount>(val_32);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_pallas_9_33) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_33 = 0x1902f2819_cppui253;
    assert(clz<field_type>(val_33) == 33);
    test_less_than_constant_specific_inputs<field_type, 9, 33>(val_33);
    test_less_than_constant_random_inputs<field_type, 9, 33, random_tests_amount>(val_33);
    test_less_than_constant_fail_random_inputs<field_type, 9, 33, random_tests_amount>(val_33);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_pallas_9_64) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_64 = 0xd45ab09cc77d428d_cppui255;
    assert(clz<field_type>(val_64) == 64);
    test_less_than_constant_specific_inputs<field_type, 9, 64>(val_64);
    test_less_than_constant_random_inputs<field_type, 9, 64, random_tests_amount>(val_64);
    test_less_than_constant_fail_random_inputs<field_type, 9, 64, random_tests_amount>(val_64);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_vesta_9_127) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_127 = value_type(2).pow(127) - 1;
    assert(clz<field_type>(val_127) == 127);
    test_less_than_constant_specific_inputs<field_type, 9, 127>(val_127);
    test_less_than_constant_random_inputs<field_type, 9, 127, random_tests_amount>(val_127);
    test_less_than_constant_fail_random_inputs<field_type, 9, 127, random_tests_amount>(val_127);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_pallas_15_253) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    using value_type = typename field_type::value_type;

    value_type val_253 = 0x1a4b4d5cde54a974ea4e57ee4132d2ab2510c300f21930d6bbbf211d1add80f9_cppui255;
    assert(clz<field_type>(val_253) == 253);
    test_less_than_constant_specific_inputs<field_type, 9, 253>(val_253);
    test_less_than_constant_random_inputs<field_type, 9, 253, random_tests_amount>(val_253);
    test_less_than_constant_fail_random_inputs<field_type, 9, 253, random_tests_amount>(val_253);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_mnt4_15) {
    using field_type = nil::crypto3::algebra::curves::mnt4<298>::base_field_type;
    using value_type = typename field_type::value_type;

    value_type val_296 = value_type(2).pow(296) - 1;
    assert(clz<field_type>(val_296) == 296);
    test_less_than_constant_specific_inputs<field_type, 15, 296>(val_296);
    test_less_than_constant_random_inputs<field_type, 15, 296, random_tests_amount>(val_296);
    test_less_than_constant_fail_random_inputs<field_type, 15, 296, random_tests_amount>(val_296);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_oops_wrong_chunks) {
    using field_type = nil::crypto3::algebra::curves::mnt4<298>::base_field_type;
    using value_type = typename field_type::value_type;

    value_type val = -1,
               constant = value_type(2).pow(8) - 1;

    std::map<std::pair<std::size_t, std::size_t>, value_type> patches = {};
    for (std::size_t i = 2; i < 15; i++) {
        patches[std::make_pair(0, i)] = 0;
    }
    for (std::size_t i = 0; i < 15; i++) {
        patches[std::make_pair(1, i)] = 0;
    }
    patches[std::make_pair(2, 0)] = val;
    patches[std::make_pair(2, 1)] = constant - val;

    test_less_than_constant<field_type, 15, 8, true>(val, constant, patches);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_less_than_constant_oops_chunk_overflow) {
    // Due to the way the component works, the only time first chunk overflow is actually harmful is
    // when it occurs on maximum possible R. Testing on R less than that would not reveal if the
    // first chunk constraints are correct or not.
    using field_type = nil::crypto3::algebra::curves::vesta::base_field_type;
    using value_type = typename field_type::value_type;

    value_type val_253 = value_type(2).pow(253) - 1,
               val_254 = value_type(2).pow(254) - 1,
               difference = val_253 - val_254;
    std::map<std::pair<std::size_t, std::size_t>, value_type> patches;
    value_type sum, sum_diff;
    // 21 rows, 13 padding.
    std::array<uint32_t, 10> corrections = {
        2, 0, 0, 0, 0, 0x2246, 0x98fc099, 0x4a8dd8c, 0x46eb210, 1
    };
    auto place_gate_chunks = [&patches](std::size_t row, std::size_t idx, uint32_t chunk) {
        std::array<bool, 32> bits;
        for (std::size_t i = 0; i < 32; i++) {
            bits[i] = chunk & (1 << (31 - i));
        }
        if (idx == 1) {
            for (std::size_t i = 0; i < 13; i++) {
                patches[std::make_pair(row, i + 2)] = 2 * bits[4 + i * 2] + bits[4 + i * 2 + 1];
            }
            patches[std::make_pair(row + 1, 0)] = 2 * bits[30] + bits[31];
        } else {
            for (std::size_t i = 0; i < 14; i++) {
                patches[std::make_pair(row + 1, i + 1)] = 2 * bits[4 + i * 2] + bits[4 + i * 2 + 1];
            }
        }
    };
    sum = 3 / value_type(2).pow(28);
    sum_diff = 0;
    for (std::size_t i = 2; i < 21; i += 2) {
        if (i != 2) {
            place_gate_chunks(i - 2, 0, uint32_t((1 << 28) - 1));
        } else {
            place_gate_chunks(i - 2, 0, uint32_t(3));
        }
        patches[std::make_pair(i, 0)] = sum = sum * value_type(2).pow(28) + (i != 2) * (value_type(2).pow(28) - 1);
        place_gate_chunks(i - 2, 1, uint32_t(corrections[i / 2 - 1]));
        patches[std::make_pair(i, 1)] = sum_diff = sum_diff * value_type(2).pow(28) +
                                        value_type(corrections[i / 2 - 1]);
    }
    assert(sum_diff == difference);
    assert(sum == val_254);
    test_less_than_constant<field_type, 15, 253, true>(val_254, val_253, patches);
}

BOOST_AUTO_TEST_SUITE_END()
